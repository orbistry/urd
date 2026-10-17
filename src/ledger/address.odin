package ledger

import "urd:base"
import "urd:cbor"
import "urd:ledger/byron"

// Address decoding, docs/decoding/txbody.md §4
// (cardano-ledger-core Cardano/Ledger/Address.hs).

Address_Kind :: enum u8 {
	Base,
	Pointer,
	Enterprise,
	Byron,
}

Network :: enum u8 {
	Testnet = 0,
	Mainnet = 1,
}

Pointer :: struct {
	slot:    u64,
	tx_ix:   u64,
	cert_ix: u64,
}

Address :: struct {
	raw:            base.Span,
	kind:           Address_Kind,
	network:        Network,
	// Payment credential; for Byron, the address root as a key hash.
	payment:        Credential,
	// Stake credential of a base address.
	stake:          Credential,
	ptr:            Pointer,
	// Length of the address as the ledger stores it. Below v7 trailing bytes
	// after a Shelley address are accepted and dropped, so this can be shorter
	// than `raw`. Pointer addresses are re-serialised from `ptr`, which below v9
	// may have been normalised to (0, 0, 0): see `ptr_normalised`.
	stored_len:     u16,
	ptr_normalised: bool,
}

// Decodes a TxOut address (`fromCborBothAddr`).
read_address :: proc "contextless" (d: ^Decoder) -> (a: Address, err: Error) {
	b := cbor.read_bytes(&d.r) or_return
	a = parse_address(b, d.v) or_return
	a.raw = span(d, b)
	return a, .None
}

parse_address :: proc "contextless" (b: []u8, v: u32) -> (a: Address, err: Error) {
	if len(b) == 0 {
		return {}, .Eof
	}
	header := b[0]
	if header == 0x82 {
		return parse_byron_address(b)
	}
	if header & 0b1000_1110 != 0 {
		return {}, .Invalid_Value
	}
	a.network = Network(header & 1)
	a.payment.is_script = header & 0x10 != 0
	pos := 1
	if len(b) < pos + 28 do return {}, .Eof
	copy(a.payment.hash[:], b[pos:][:28])
	pos += 28

	switch {
	case header & 0x40 == 0:
		a.kind = .Base
		a.stake.is_script = header & 0x20 != 0
		if len(b) < pos + 28 do return {}, .Eof
		copy(a.stake.hash[:], b[pos:][:28])
		pos += 28
	case header & 0x20 == 0:
		a.kind = .Pointer
		if v >= 9 {
			a.ptr = read_pointer_strict(b, &pos) or_return
		} else {
			a.ptr, a.ptr_normalised = read_pointer_lenient(b, &pos) or_return
		}
	case:
		a.kind = .Enterprise
	}

	if pos != len(b) && v >= 7 {
		return {}, .Trailing_Bytes
	}
	a.stored_len = u16(pos)
	return a, .None
}

// Pointer below v9 (decodePtrLenient): three base-128 varints of unbounded
// length, accumulated into Word64 with silent wrap-around, then
// mkPtrNormalized: any component out of range (slot > 2^32 - 1,
// tx index or cert index > 65535) turns the whole pointer into (0, 0, 0).
@(private = "file")
read_pointer_lenient :: proc "contextless" (b: []u8, pos: ^int) -> (p: Pointer, normalised: bool, err: Error) {
	vals: [3]u64
	for k in 0 ..< 3 {
		acc: u64
		for {
			if pos^ >= len(b) do return {}, false, .Eof
			byte := b[pos^]
			pos^ += 1
			acc = acc << 7 | u64(byte & 0x7f)
			if byte & 0x80 == 0 do break
		}
		vals[k] = acc
	}
	if vals[0] > u64(max(u32)) || vals[1] > u64(max(u16)) || vals[2] > u64(max(u16)) {
		return {}, true, .None
	}
	return Pointer{vals[0], vals[1], vals[2]}, false, .None
}

// Pointer from v9 (decodePtr): slot fits 32 bits (at most 5 bytes), tx and
// cert indices fit 16 bits (at most 3 bytes). When the maximum byte count is
// used, the first byte may only carry the bits that still fit.
@(private = "file")
read_pointer_strict :: proc "contextless" (b: []u8, pos: ^int) -> (p: Pointer, err: Error) {
	p.slot = read_varint_bounded(b, pos, 5, 0xf0) or_return
	p.tx_ix = read_varint_bounded(b, pos, 3, 0xfc) or_return
	p.cert_ix = read_varint_bounded(b, pos, 3, 0xfc) or_return
	return p, .None
}

@(private = "file")
read_varint_bounded :: proc "contextless" (
	b: []u8,
	pos: ^int,
	max_bytes: int,
	first_mask: u8,
) -> (
	v: u64,
	err: Error,
) {
	start := pos^
	for n := 1;; n += 1 {
		if pos^ >= len(b) do return 0, .Eof
		byte := b[pos^]
		pos^ += 1
		v = v << 7 | u64(byte & 0x7f)
		if byte & 0x80 == 0 {
			if n == max_bytes && b[start] & first_mask != 0x80 {
				return 0, .Overflow
			}
			return v, .None
		}
		if n == max_bytes {
			return 0, .Overflow
		}
	}
}

// Byron address inside a Shelley-era output (decodeBootstrapAddress, at
// version 1): the Byron address decoder, consuming the whole buffer.
@(private = "file")
parse_byron_address :: proc "contextless" (b: []u8) -> (a: Address, err: Error) {
	ba := byron.parse_address(b) or_return
	a.kind = .Byron
	a.network = .Testnet if ba.has_magic else .Mainnet
	a.payment.hash = ba.root
	a.stored_len = u16(len(b))
	return a, .None
}

// ---------------------------------------------------------------------------
// Reward accounts

Reward_Account :: struct {
	network: Network,
	cred:    Credential,
}

// Haskell `Ord AccountAddress`: network (Testnet < Mainnet), then credential.
reward_account_less :: proc "contextless" (a, b: Reward_Account) -> bool {
	if a.network != b.network {
		return a.network < b.network
	}
	return credential_less(a.cred, b.cred)
}

// `fromCborAccountAddress`: 29 bytes, header 0xE0/0xE1/0xF0/0xF1, at every
// version.
read_reward_account :: proc "contextless" (d: ^Decoder) -> (ra: Reward_Account, err: Error) {
	b := cbor.read_bytes(&d.r) or_return
	return parse_reward_account(b)
}

parse_reward_account :: proc "contextless" (b: []u8) -> (ra: Reward_Account, err: Error) {
	if len(b) == 0 {
		return {}, .Eof
	}
	header := b[0]
	if header & 0b1110_1110 != 0b1110_0000 {
		return {}, .Invalid_Value
	}
	if len(b) < 29 {
		return {}, .Eof
	}
	if len(b) > 29 {
		return {}, .Trailing_Bytes
	}
	ra.network = Network(header & 1)
	ra.cred.is_script = header & 0x10 != 0
	copy(ra.cred.hash[:], b[1:29])
	return ra, .None
}

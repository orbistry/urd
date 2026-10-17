package byron

import "core:hash"

import "urd:base"
import "urd:cbor"

// Byron addresses (byron/Common/Address.hs, AddrAttributes.hs), docs B.3.5.

Addr_Type :: enum u8 {
	Ver_Key = 0,
	Redeem  = 2,
}

// A decoded Byron address. The address bytes themselves stay with the caller
// (outputs keep them as a span): witnesses are checked against the root by
// re-hashing the spending data with the address attributes.
Address :: struct {
	// `addrRoot`: Blake2b-224 of the hashed spending data and attributes.
	root:              base.Hash28,
	// Network magic attribute (key 2); absent on mainnet addresses.
	magic:             u32,
	// `unknownAttributesLength`: total length of the attribute values other
	// than the derivation path (1) and network magic (2). The UTxO rule
	// requires it to be below 128.
	unknown_attrs_len: u32,
	type:              Addr_Type,
	has_magic:         bool,
}

// Parses an address that is exactly the bytes `b`, as `decodeFull` does for
// a bootstrap address inside a Shelley-era output.
parse_address :: proc "contextless" (b: []u8) -> (a: Address, err: Error) {
	r := cbor.reader(b)
	a = read_address(&r) or_return
	cbor.expect_end(&r) or_return
	return a, .None
}

// `decodeCrcProtected`: [#6.24(payload), crc32]. The CRC-32 of the payload
// must match, and the payload must decode in full (at version 1) as a
// definite [root, attributes, type].
read_address :: proc "contextless" (r: ^cbor.Reader) -> (a: Address, err: Error) {
	enforce_size(r, 2) or_return
	payload := read_nested(r) or_return
	crc := cbor.read_u32(r) or_return
	if hash.crc32(payload) != crc {
		return {}, .Invalid_Value
	}

	p := cbor.reader(payload)
	enforce_size(&p, 3) or_return
	root := cbor.read_bytes_n(&p, 28) or_return
	copy(a.root[:], root)

	// `Attributes AddrAttributes`: keys 1 and 2 are parsed (each value must
	// decode in full with a canonical encoding), other keys stay unparsed.
	n := read_map_definite(&p) or_return
	prev := -1
	for _ in 0 ..< n {
		key, value := read_attribute(&p, &prev) or_return
		switch key {
		case 1:
			// HDAddressPayload: decodeBytesCanonical.
			vr := cbor.reader(value)
			_ = cbor.read_bytes_canonical(&vr) or_return
			cbor.expect_end(&vr) or_return
		case 2:
			// NetworkMagic: decodeWord32Canonical.
			vr := cbor.reader(value)
			magic := cbor.read_uint_canonical(&vr, u64(max(u32))) or_return
			cbor.expect_end(&vr) or_return
			a.magic = u32(magic)
			a.has_magic = true
		case:
			a.unknown_attrs_len += u32(len(value))
		}
	}

	// `AddrType`: decodeWord8Canonical, 0 (ATVerKey) or 2 (ATRedeem).
	t := cbor.read_uint_canonical(&p, u64(max(u8))) or_return
	switch t {
	case 0:
		a.type = .Ver_Key
	case 2:
		a.type = .Redeem
	case:
		return {}, .Invalid_Value
	}
	cbor.expect_end(&p) or_return
	return a, .None
}

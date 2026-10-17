package byron

import "urd:base"
import "urd:cbor"

// Decoding rules: docs/decoding/witnesses-auxdata-byron.md Part B.
//
// Every Byron decoder runs at `byronProtVer` = 1. At that version lists are
// indefinite only, records (`enforceSize`), tuples, vectors and maps definite
// only, and maps must have strictly increasing keys. Non-minimal heads are
// accepted except at the few `*Canonical` points (verification keys, address
// attribute payloads and the address type).

Error :: cbor.Error

// Largest valid `Lovelace` (`maxLovelaceVal`, 45 * 10^15).
MAX_LOVELACE :: 45_000_000_000_000_000

// Denominator of a `LovelacePortion` (10^15), also its largest value.
LOVELACE_PORTION_DENOMINATOR :: 1_000_000_000_000_000

Vkey :: [64]u8
Signature :: [64]u8

// Decoding state: the reader, the buffer spans are relative to, and the
// tables rows are appended to (nil when decoding a header alone).
@(private)
Decoder :: struct {
	r:    cbor.Reader,
	base: []u8,
	t:    ^Tables,
}

@(private)
span_from :: #force_inline proc "contextless" (d: ^Decoder, start: int) -> base.Span {
	return base.span_of(d.base, d.r.data[start:d.r.pos])
}

// `enforceSize n`: a definite array of exactly n items.
enforce_size :: #force_inline proc "contextless" (r: ^cbor.Reader, n: int) -> Error {
	return cbor.expect_array_definite(r, n)
}

// `decodeList` at version 1 (`decodeListWith`): an indefinite array. Iterate
// it with `cbor.more`.
read_list :: #force_inline proc "contextless" (r: ^cbor.Reader) -> (c: cbor.Container, err: Error) {
	c = cbor.read_array(r) or_return
	if !c.indefinite {
		return c, .Unexpected_Definite
	}
	return c, .None
}

// `decodeListLen` / `decodeMapLen`: definite only.
read_array_definite :: #force_inline proc "contextless" (r: ^cbor.Reader) -> (n: int, err: Error) {
	c := cbor.read_array(r) or_return
	if c.indefinite {
		return 0, .Unexpected_Indefinite
	}
	return c.n, .None
}

read_map_definite :: #force_inline proc "contextless" (r: ^cbor.Reader) -> (n: int, err: Error) {
	c := cbor.read_map(r) or_return
	if c.indefinite {
		return 0, .Unexpected_Indefinite
	}
	return c.n, .None
}

// `decodeNestedCborBytes`: tag 24 (any head width) then a definite byte
// string. The caller decodes the payload in full (`decodeFull'`).
read_nested :: #force_inline proc "contextless" (r: ^cbor.Reader) -> (payload: []u8, err: Error) {
	t := cbor.read_tag(r) or_return
	if t != 24 {
		return nil, .Unexpected_Tag
	}
	return cbor.read_bytes(r)
}

// `VerificationKey` (`decCBORXPub`): a byte string with a canonical head
// holding exactly 64 bytes (Ed25519 key and chain code).
read_vkey :: proc "contextless" (r: ^cbor.Reader) -> (k: Vkey, err: Error) {
	b := cbor.read_bytes_canonical(r) or_return
	if len(b) != 64 {
		return k, .Length_Mismatch
	}
	copy(k[:], b)
	return k, .None
}

// `Signature a` (`decCBORXSignature`): exactly 64 bytes, any head width.
read_signature :: proc "contextless" (r: ^cbor.Reader) -> (s: Signature, err: Error) {
	b := cbor.read_bytes_n(r, 64) or_return
	copy(s[:], b)
	return s, .None
}

// `Lovelace`: a Word64 no larger than `maxLovelaceVal` (mkLovelace).
read_lovelace :: proc "contextless" (r: ^cbor.Reader) -> (v: u64, err: Error) {
	v = cbor.read_uint(r) or_return
	if v > MAX_LOVELACE {
		return 0, .Invalid_Value
	}
	return v, .None
}

// `LovelacePortion`: a Word64 numerator no larger than 10^15.
read_lovelace_portion :: proc "contextless" (r: ^cbor.Reader) -> (v: u64, err: Error) {
	v = cbor.read_uint(r) or_return
	if v > LOVELACE_PORTION_DENOMINATOR {
		return 0, .Invalid_Value
	}
	return v, .None
}

// `Text` (decodeString): definite, valid UTF-8.
read_text :: proc "contextless" (r: ^cbor.Reader) -> (b: []u8, err: Error) {
	s := cbor.read_text(r) or_return
	b = transmute([]u8)s
	if !cbor.valid_utf8(b) {
		return nil, .Invalid_Value
	}
	return b, .None
}

// ---------------------------------------------------------------------------
// Attributes (byron/Common/Attributes.hs)

// `decCBOR @(Map Word8 LBS.ByteString)` at version 1 (decodeMapSkel): a
// definite map with Word8 keys in strictly increasing order and definite
// byte-string values. Read the header with `read_map_definite`, then each
// entry with this, starting from `prev = -1`.
read_attribute :: proc "contextless" (r: ^cbor.Reader, prev: ^int) -> (key: u8, value: []u8, err: Error) {
	key = cbor.read_u8(r) or_return
	if int(key) <= prev^ {
		return 0, nil, .Not_Sorted
	}
	prev^ = int(key)
	value = cbor.read_bytes(r) or_return
	return key, value, .None
}

// `Attributes ()`: every entry is unparsed. Returns `unknownAttributesLength`,
// the total length of the values.
read_unit_attributes :: proc "contextless" (r: ^cbor.Reader) -> (unknown_len: u32, err: Error) {
	n := read_map_definite(r) or_return
	prev := -1
	for _ in 0 ..< n {
		_, value := read_attribute(r, &prev) or_return
		unknown_len += u32(len(value))
	}
	return unknown_len, .None
}

// `dropEmptyAttributes`: a definite map of length 0.
drop_empty_attributes :: proc "contextless" (r: ^cbor.Reader) -> Error {
	n := read_map_definite(r) or_return
	return .None if n == 0 else .Length_Mismatch
}

// `dropAttributes` (`dropMap dropWord8 dropBytes`): a definite map with no
// order or duplicate check.
drop_attributes :: proc "contextless" (r: ^cbor.Reader) -> Error {
	n := read_map_definite(r) or_return
	for _ in 0 ..< n {
		_ = cbor.read_u8(r) or_return
		_ = cbor.read_bytes(r) or_return
	}
	return .None
}

// ---------------------------------------------------------------------------
// Versions

// `ProtocolVersion`: [Word16 major, Word16 minor, Word8 alt].
Protocol_Version :: struct {
	major: u16,
	minor: u16,
	alt:   u8,
}

read_protocol_version :: proc "contextless" (r: ^cbor.Reader) -> (v: Protocol_Version, err: Error) {
	enforce_size(r, 3) or_return
	v.major = cbor.read_u16(r) or_return
	v.minor = cbor.read_u16(r) or_return
	v.alt = cbor.read_u8(r) or_return
	return v, .None
}

// `SoftwareVersion`: [ApplicationName, Word32]. The name is any text at
// decode time; its length and ASCII limits are checked only when an update
// proposal is registered.
Software_Version :: struct {
	name:   base.Span,
	number: u32,
}

@(private)
read_software_version :: proc "contextless" (d: ^Decoder) -> (v: Software_Version, err: Error) {
	enforce_size(&d.r, 2) or_return
	name := read_text(&d.r) or_return
	v.name = base.span_of(d.base, name)
	v.number = cbor.read_u32(&d.r) or_return
	return v, .None
}

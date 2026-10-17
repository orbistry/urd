package ledger

import "base:runtime"

import "urd:base"
import "urd:cbor"

// Decoder versions (`eraProtVerLow`) of the Shelley-family eras. Blocks of an
// era are always decoded at its low version, whatever the current protocol
// version is.
era_decoder_version :: proc "contextless" (era: base.Era) -> u32 {
	switch era {
	case .Byron:
		return 1
	case .Shelley:
		return 2
	case .Allegra:
		return 3
	case .Mary:
		return 4
	case .Alonzo:
		return 5
	case .Babbage:
		return 7
	case .Conway:
		return 9
	case .Dijkstra:
		return 12
	}
	return 0
}

// Decoding state: the reader, the decoder version, and the tables the block
// is decoded into. `base` is the buffer every `Span` is relative to (the era
// block), which also covers CBOR-in-CBOR payloads decoded with a sub-reader.
Decoder :: struct {
	r:       cbor.Reader,
	v:       u32,
	era:     base.Era,
	base:    []u8,
	t:       ^Block_Tables,
	// Per-block scratch (the tables' arena): temporary arrays for duplicate
	// checks and explicit stacks. Released when the tables are reset.
	scratch: runtime.Allocator,
}

// A decoder over `data` writing into `t`, at the era's decoder version.
make_decoder :: proc(data: []u8, era: base.Era, t: ^Block_Tables) -> Decoder {
	scratch := tables_scratch(t)
	r := cbor.reader(data)
	r.scratch = scratch
	return Decoder{r = r, v = era_decoder_version(era), era = era, base = data, t = t, scratch = scratch}
}

Error :: cbor.Error

@(private)
sub_decoder :: proc "contextless" (d: ^Decoder, payload: []u8) -> Decoder {
	r := cbor.reader(payload)
	r.scratch = d.scratch
	return Decoder{r = r, v = d.v, era = d.era, base = d.base, t = d.t, scratch = d.scratch}
}

span :: #force_inline proc "contextless" (d: ^Decoder, b: []u8) -> base.Span {
	return base.span_of(d.base, b)
}

// Span of the bytes consumed since `start`.
span_from :: #force_inline proc "contextless" (d: ^Decoder, start: int) -> base.Span {
	return base.span_of(d.base, d.r.data[start:d.r.pos])
}

// ---------------------------------------------------------------------------
// Record and sum shapes (see docs/decoding/txbody.md §1.3)

// `decodeRecordNamed`: a definite array of exactly n, or an indefinite array
// closed by a break after the fields. Close with `cbor.end`.
read_rec :: #force_inline proc "contextless" (d: ^Decoder, n: int) -> (c: cbor.Container, err: Error) {
	return cbor.read_array_len(&d.r, n)
}

// Coders' `RecD` below v12. The array header is checked before any field is
// read (decodeCount (RecD cn) n = decodeRecordNamed "RecD" (const n) (pure ..)
// in cardano-ledger-binary Coders.hs). A definite header must say n. An
// indefinite header must be followed *immediately* by the break, and the fields
// come after it: `9f ff f1 .. fn` decodes, `9f f1 .. fn ff` does not.
read_recd :: proc "contextless" (d: ^Decoder, n: int) -> Error {
	c := cbor.read_array(&d.r) or_return
	if !c.indefinite {
		return .None if c.n == n else .Length_Mismatch
	}
	b := cbor.peek_byte(&d.r) or_return
	if b != cbor.BREAK {
		return .Length_Mismatch
	}
	d.r.pos += 1
	return .None
}

// `decodeRecordSum`: `[tag, fields...]`, definite or indefinite. Returns the
// tag; call `end_sum` with the number of fields of that arm.
read_sum :: proc "contextless" (d: ^Decoder) -> (tag: u64, c: cbor.Container, err: Error) {
	c = cbor.read_array(&d.r) or_return
	if !c.indefinite && c.n == 0 {
		return 0, c, .Length_Mismatch
	}
	tag = cbor.read_uint(&d.r) or_return
	return tag, c, .None
}

end_sum :: proc "contextless" (d: ^Decoder, c: cbor.Container, fields: int) -> Error {
	if !c.indefinite {
		return .None if c.n == fields + 1 else .Length_Mismatch
	}
	return cbor.end(&d.r, c)
}

// Tuples below v12 (`decodeListLenOf n`): definite, exactly n.
read_tuple :: #force_inline proc "contextless" (d: ^Decoder, n: int) -> Error {
	return cbor.expect_array_definite(&d.r, n)
}

// ---------------------------------------------------------------------------
// Collections

// `decodeSet` header. Below v9 a tag is not allowed (the length read fails on
// it); from v9 an optional tag 258.
read_set :: proc "contextless" (d: ^Decoder) -> (c: cbor.Container, err: Error) {
	if d.v >= 9 {
		allow_tag(d, 258) or_return
	}
	return cbor.read_array(&d.r)
}

// `allowTag t`: an optional tag that must equal t when present.
allow_tag :: proc "contextless" (d: ^Decoder, t: u64) -> Error {
	m := cbor.peek_major(&d.r) or_return
	if m != .Tag {
		return .None
	}
	tag := cbor.read_tag(&d.r) or_return
	return .None if tag == t else .Unexpected_Tag
}

// ---------------------------------------------------------------------------
// Primitives

read_hash28 :: #force_inline proc "contextless" (d: ^Decoder) -> (h: base.Hash28, err: Error) {
	return cbor.read_hash28(&d.r)
}

read_hash32 :: #force_inline proc "contextless" (d: ^Decoder) -> (h: base.Hash32, err: Error) {
	return cbor.read_hash32(&d.r)
}

// `Coin`: Word64.
read_coin :: #force_inline proc "contextless" (d: ^Decoder) -> (v: u64, err: Error) {
	return cbor.read_uint(&d.r)
}

// `decodePositiveCoin`: Word64, zero rejected.
read_positive_coin :: proc "contextless" (d: ^Decoder) -> (v: u64, err: Error) {
	v = cbor.read_uint(&d.r) or_return
	return v, .None if v != 0 else .Invalid_Value
}

// `decodeNullStrictMaybe`: null means absent.
read_null_or :: #force_inline proc "contextless" (d: ^Decoder) -> (present: bool) {
	if cbor.is_null(&d.r) {
		d.r.pos += 1
		return false
	}
	return true
}

// Definite text whose UTF-8 length is at most `limit` (`textDecCBOR`).
//
// TODO(conformance): cborg's decodeString is assumed to reject invalid UTF-8.
read_bounded_text :: proc "contextless" (d: ^Decoder, limit: int) -> (s: []u8, err: Error) {
	t := cbor.read_text(&d.r) or_return
	if len(t) > limit {
		return nil, .Invalid_Value
	}
	if !cbor.valid_utf8(transmute([]u8)t) {
		return nil, .Invalid_Value
	}
	return transmute([]u8)t, .None
}

// URL and DNS-name length limit: 64 bytes below v9, 128 from v9.
url_limit :: #force_inline proc "contextless" (d: ^Decoder) -> int {
	return 128 if d.v >= 9 else 64
}

// ---------------------------------------------------------------------------
// Credentials

Credential :: struct {
	hash:      base.Hash28,
	is_script: bool,
}

// Haskell `Ord (Credential r)`: ScriptHashObj sorts before KeyHashObj, then
// by hash bytes.
credential_less :: proc "contextless" (a, b: Credential) -> bool {
	if a.is_script != b.is_script {
		return a.is_script
	}
	return hash28_less(a.hash, b.hash)
}

hash28_less :: #force_inline proc "contextless" (a, b: base.Hash28) -> bool {
	for i in 0 ..< 28 {
		if a[i] != b[i] do return a[i] < b[i]
	}
	return false
}

hash32_less :: #force_inline proc "contextless" (a, b: base.Hash32) -> bool {
	for i in 0 ..< 32 {
		if a[i] != b[i] do return a[i] < b[i]
	}
	return false
}

// `[0, keyhash] / [1, scripthash]`
read_credential :: proc "contextless" (d: ^Decoder) -> (cred: Credential, err: Error) {
	tag, c := read_sum(d) or_return
	if tag > 1 {
		return {}, .Invalid_Value
	}
	cred.is_script = tag == 1
	cred.hash = read_hash28(d) or_return
	end_sum(d, c, 1) or_return
	return cred, .None
}

// ---------------------------------------------------------------------------
// Bounded rationals (UnitInterval and friends), docs/decoding/txbody.md §1.5

Ratio :: struct {
	num, den: u64,
}

Interval_Kind :: enum u8 {
	Unit,          // [0, 1]
	Non_Negative,  // [0, 2^64 - 1]
	Positive,      // [10^-19, 2^64 - 1]
	Positive_Unit, // [10^-19, 1]
}

// Tag 30 (mandatory below v12), then an array of exactly two `Integer`s, a
// non-zero denominator, Haskell `%` normalisation (lowest terms, sign on the
// numerator), and the bounds of `kind` with numerator and denominator each
// fitting Word64.
read_interval :: proc "contextless" (d: ^Decoder, kind: Interval_Kind) -> (q: Ratio, err: Error) {
	tag := cbor.read_tag(&d.r) or_return
	if tag != 30 {
		return {}, .Unexpected_Tag
	}
	c := cbor.read_array(&d.r) or_return
	if !c.indefinite && c.n != 2 {
		return {}, .Length_Mismatch
	}
	if c.indefinite {
		// The elements are counted after decoding: exactly two, then break.
		n := 0
		vals: [2]cbor.Integer
		for cbor.more(&d.r, &c) {
			v := cbor.read_integer(&d.r) or_return
			if n < 2 do vals[n] = v
			n += 1
		}
		if n != 2 do return {}, .Length_Mismatch
		return normalise_interval(vals[0], vals[1], kind)
	}
	a := cbor.read_integer(&d.r) or_return
	b := cbor.read_integer(&d.r) or_return
	return normalise_interval(a, b, kind)
}

@(private)
normalise_interval :: proc "contextless" (n, dd: cbor.Integer, kind: Interval_Kind) -> (q: Ratio, err: Error) {
	// After reduction both parts must fit Word64 and the value is
	// non-negative for every bounded kind, so numerator and denominator must
	// have the same sign. Bignums can only reduce into range when they share
	// a large factor; that never happens for well-formed data, and a value
	// that does not fit u128 is rejected here.
	// TODO(conformance): reduce arbitrary-size bignum fractions exactly.
	if n.big != nil || dd.big != nil {
		return {}, .Invalid_Value
	}
	if dd.small == 0 && !dd.negative {
		return {}, .Invalid_Value
	}
	// Magnitudes as u128: a negative CBOR integer is -1 - arg.
	nm := u128(n.small) + (1 if n.negative else 0)
	dm := u128(dd.small) + (1 if dd.negative else 0)
	if nm != 0 && n.negative != dd.negative {
		return {}, .Invalid_Value
	}
	g := gcd_u128(nm, dm)
	nm /= g
	dm /= g
	if nm > u128(max(u64)) || dm > u128(max(u64)) {
		return {}, .Invalid_Value
	}
	q = Ratio {
		num = u64(nm),
		den = u64(dm),
	}
	switch kind {
	case .Unit:
		if q.num > q.den do return {}, .Invalid_Value
	case .Non_Negative:
	case .Positive:
		if !ratio_at_least_min_positive(q) do return {}, .Invalid_Value
	case .Positive_Unit:
		if q.num > q.den || !ratio_at_least_min_positive(q) do return {}, .Invalid_Value
	}
	return q, .None
}

// q >= 10^-19
@(private)
ratio_at_least_min_positive :: proc "contextless" (q: Ratio) -> bool {
	return u128(q.num) * 10_000_000_000_000_000_000 >= u128(q.den)
}

gcd_u128 :: proc "contextless" (a, b: u128) -> u128 {
	a, b := a, b
	for b != 0 {
		a, b = b, a % b
	}
	return a if a != 0 else 1
}

// ---------------------------------------------------------------------------
// Anchors

Anchor :: struct {
	url:     base.Span,
	hash:    base.Hash32,
	present: bool,
}

// `Anchor`: RecD [url (<= 128 bytes at v9), hash32].
read_anchor :: proc "contextless" (d: ^Decoder) -> (a: Anchor, err: Error) {
	read_recd(d, 2) or_return
	url := read_bounded_text(d, url_limit(d)) or_return
	a.url = span(d, url)
	a.hash = read_hash32(d) or_return
	a.present = true
	return a, .None
}

read_nullable_anchor :: proc "contextless" (d: ^Decoder) -> (a: Anchor, err: Error) {
	if !read_null_or(d) {
		return {}, .None
	}
	return read_anchor(d)
}

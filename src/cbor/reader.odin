// Package cbor is a zero-copy CBOR (RFC 8949) reader and a minimal writer.
//
// The reader never allocates on the common path: byte and text strings are
// returned as subslices of the input, and `span`/`skip` let callers capture
// the original bytes of an item for hashing.
//
// Acceptance rules follow Haskell's `cborg`, which is what cardano-node
// decodes with: non-minimal integer and length encodings are accepted,
// byte/text strings must be definite unless read with the `_chunked`
// variants, and reserved additional-info values (28..30) are rejected.
// Schema-level strictness (exact record lengths, set tags, duplicate keys)
// belongs to the callers.
package cbor

import "base:runtime"
import "core:encoding/endian"

Error :: enum u8 {
	None,
	// Input ended in the middle of an item.
	Eof,
	// The item has a different major type than the caller asked for.
	Unexpected_Major,
	// Additional info 28..30, or an indefinite length where none is allowed.
	Invalid_Info,
	// An indefinite-length item where a definite one is required.
	Unexpected_Indefinite,
	// A break byte (0xff) outside an indefinite-length container.
	Unexpected_Break,
	// A value does not fit the requested type.
	Overflow,
	// A container length differs from what the schema requires.
	Length_Mismatch,
	// A value is outside the set of values the schema allows.
	Invalid_Value,
	// Bytes remain after the top-level item.
	Trailing_Bytes,

	// Schema-level errors, raised by the ledger and network decoders.

	// A map or set holds the same key twice where that is not allowed.
	Duplicate_Key,
	// A sparse record (map with integer keys) holds a key it does not define.
	Unknown_Key,
	// A sparse record lacks a required key.
	Missing_Key,
	// A tag differs from the one the schema requires.
	Unexpected_Tag,
	// A collection that must be non-empty is empty.
	Empty,
	// Keys or elements are not in the order the schema requires.
	Not_Sorted,
	// Indices or references inside an item are inconsistent (e.g. an
	// auxiliary-data index past the last transaction).
	Inconsistent,
}

Major :: enum u8 {
	Unsigned = 0,
	Negative = 1,
	Bytes    = 2,
	Text     = 3,
	Array    = 4,
	Map      = 5,
	Tag      = 6,
	Simple   = 7,
}

INFO_INDEFINITE :: 31
BREAK :: 0xff

// Initial byte plus argument of a data item.
Head :: struct {
	arg:   u64,
	major: Major,
	info:  u8,
}

Reader :: struct {
	data:    []u8,
	pos:     int,
	// Where `skip` spills its stack for indefinite containers nested deeper
	// than SKIP_INLINE_DEPTH. Decoders on the validation path set it to their
	// per-block scratch arena; when unset, `context.temp_allocator` is used.
	scratch: runtime.Allocator,
}

// Container length as read from an array or map head. An indefinite container
// has `indefinite = true` and `n` is meaningless; iterate it with `more`.
Container :: struct {
	n:          int,
	indefinite: bool,
}

reader :: #force_inline proc "contextless" (data: []u8) -> Reader {
	return Reader{data = data}
}

remaining :: #force_inline proc "contextless" (r: ^Reader) -> int {
	return len(r.data) - r.pos
}

at_end :: #force_inline proc "contextless" (r: ^Reader) -> bool {
	return r.pos >= len(r.data)
}

// Fails unless the whole input has been consumed.
@(require_results)
expect_end :: #force_inline proc "contextless" (r: ^Reader) -> Error {
	return .None if r.pos == len(r.data) else .Trailing_Bytes
}

// Reads the initial byte and argument of the next item.
// For info 31 the argument is 0; callers inspect `info`.
@(require_results)
read_head :: #force_inline proc "contextless" (r: ^Reader) -> (h: Head, err: Error) #no_bounds_check {
	pos := r.pos
	data := r.data
	if pos >= len(data) {
		return {}, .Eof
	}
	b := data[pos]
	h.major = Major(b >> 5)
	h.info = b & 0x1f
	switch h.info {
	case 0 ..< 24:
		h.arg = u64(h.info)
		r.pos = pos + 1
	case 24:
		if pos + 2 > len(data) do return {}, .Eof
		h.arg = u64(data[pos + 1])
		r.pos = pos + 2
	case 25:
		if pos + 3 > len(data) do return {}, .Eof
		h.arg = u64(endian.unchecked_get_u16be(data[pos + 1:]))
		r.pos = pos + 3
	case 26:
		if pos + 5 > len(data) do return {}, .Eof
		h.arg = u64(endian.unchecked_get_u32be(data[pos + 1:]))
		r.pos = pos + 5
	case 27:
		if pos + 9 > len(data) do return {}, .Eof
		h.arg = endian.unchecked_get_u64be(data[pos + 1:])
		r.pos = pos + 9
	case INFO_INDEFINITE:
		switch h.major {
		case .Unsigned, .Negative, .Tag:
			return {}, .Invalid_Info
		case .Simple:
			return {}, .Unexpected_Break
		case .Bytes, .Text, .Array, .Map:
		}
		r.pos = pos + 1
	case:
		return {}, .Invalid_Info
	}
	return h, .None
}

// Major type of the next item without consuming it.
@(require_results)
peek_major :: #force_inline proc "contextless" (r: ^Reader) -> (m: Major, err: Error) #no_bounds_check {
	if r.pos >= len(r.data) {
		return {}, .Eof
	}
	return Major(r.data[r.pos] >> 5), .None
}

// Raw initial byte of the next item without consuming it.
@(require_results)
peek_byte :: #force_inline proc "contextless" (r: ^Reader) -> (v: u8, err: Error) #no_bounds_check {
	if r.pos >= len(r.data) {
		return 0, .Eof
	}
	return r.data[r.pos], .None
}

// ---------------------------------------------------------------------------
// Integers

@(require_results)
read_uint :: #force_inline proc "contextless" (r: ^Reader) -> (v: u64, err: Error) {
	h := read_head(r) or_return
	if h.major != .Unsigned {
		return 0, .Unexpected_Major
	}
	return h.arg, .None
}

@(require_results)
read_u32 :: #force_inline proc "contextless" (r: ^Reader) -> (v: u32, err: Error) {
	u := read_uint(r) or_return
	if u > u64(max(u32)) {
		return 0, .Overflow
	}
	return u32(u), .None
}

@(require_results)
read_u16 :: #force_inline proc "contextless" (r: ^Reader) -> (v: u16, err: Error) {
	u := read_uint(r) or_return
	if u > u64(max(u16)) {
		return 0, .Overflow
	}
	return u16(u), .None
}

@(require_results)
read_u8 :: #force_inline proc "contextless" (r: ^Reader) -> (v: u8, err: Error) {
	u := read_uint(r) or_return
	if u > u64(max(u8)) {
		return 0, .Overflow
	}
	return u8(u), .None
}

// Signed integer in [min(i64), max(i64)] (major 0 or 1).
@(require_results)
read_int :: #force_inline proc "contextless" (r: ^Reader) -> (v: i64, err: Error) {
	h := read_head(r) or_return
	#partial switch h.major {
	case .Unsigned:
		if h.arg > u64(max(i64)) do return 0, .Overflow
		return i64(h.arg), .None
	case .Negative:
		if h.arg > u64(max(i64)) do return 0, .Overflow
		return -1 - i64(h.arg), .None
	}
	return 0, .Unexpected_Major
}

// Integer in the full CBOR major 0/1 range [-2^64, 2^64 - 1], as sign and
// raw argument. The value is `arg` when !negative, else `-1 - arg`.
Int :: struct {
	arg:      u64,
	negative: bool,
}

@(require_results)
read_int_full :: #force_inline proc "contextless" (r: ^Reader) -> (v: Int, err: Error) {
	h := read_head(r) or_return
	#partial switch h.major {
	case .Unsigned:
		return Int{arg = h.arg}, .None
	case .Negative:
		return Int{arg = h.arg, negative = true}, .None
	}
	return {}, .Unexpected_Major
}

// ---------------------------------------------------------------------------
// Strings

// Definite-length byte string, as a subslice of the input.
@(require_results)
read_bytes :: #force_inline proc "contextless" (r: ^Reader) -> (b: []u8, err: Error) {
	return read_string(r, .Bytes)
}

// Definite-length text string, as a subslice of the input. UTF-8 validity is
// not checked here.
@(require_results)
read_text :: #force_inline proc "contextless" (r: ^Reader) -> (s: string, err: Error) {
	b := read_string(r, .Text) or_return
	return string(b), .None
}

@(require_results)
read_string :: #force_inline proc "contextless" (r: ^Reader, major: Major) -> (b: []u8, err: Error) {
	h := read_head(r) or_return
	if h.major != major {
		return nil, .Unexpected_Major
	}
	if h.info == INFO_INDEFINITE {
		return nil, .Unexpected_Indefinite
	}
	if h.arg > u64(len(r.data) - r.pos) {
		return nil, .Eof
	}
	n := int(h.arg)
	s := r.data[r.pos:][:n]
	r.pos += n
	return s, .None
}

// Definite-length byte string of exactly `n` bytes.
@(require_results)
read_bytes_n :: #force_inline proc "contextless" (r: ^Reader, n: int) -> (b: []u8, err: Error) {
	b = read_bytes(r) or_return
	if len(b) != n {
		return nil, .Length_Mismatch
	}
	return b, .None
}

@(require_results)
read_hash28 :: #force_inline proc "contextless" (r: ^Reader) -> (h: [28]u8, err: Error) {
	b := read_bytes_n(r, 28) or_return
	copy(h[:], b)
	return
}

@(require_results)
read_hash32 :: #force_inline proc "contextless" (r: ^Reader) -> (h: [32]u8, err: Error) {
	b := read_bytes_n(r, 32) or_return
	copy(h[:], b)
	return
}

// Byte string that may be indefinite (chunked). For a definite string the
// result aliases the input and `chunked` is false. For an indefinite string
// the chunks are validated and the result is the raw span of the whole item
// (head, chunks and break); use `chunks_join` to materialise the content.
@(require_results)
read_bytes_chunked :: proc "contextless" (r: ^Reader) -> (b: []u8, chunked: bool, err: Error) {
	start := r.pos
	h := read_head(r) or_return
	if h.major != .Bytes {
		return nil, false, .Unexpected_Major
	}
	if h.info != INFO_INDEFINITE {
		if h.arg > u64(len(r.data) - r.pos) do return nil, false, .Eof
		n := int(h.arg)
		b = r.data[r.pos:][:n]
		r.pos += n
		return b, false, .None
	}
	skip_chunks(r, .Bytes) or_return
	return r.data[start:r.pos], true, .None
}

// Total content length of a chunked string span produced by
// `read_bytes_chunked` (or a definite one).
chunks_len :: proc "contextless" (item: []u8) -> int {
	r := reader(item)
	h, _ := read_head(&r)
	if h.info != INFO_INDEFINITE do return int(h.arg)
	n := 0
	for r.pos < len(r.data) && r.data[r.pos] != BREAK {
		c, _ := read_head(&r)
		n += int(c.arg)
		r.pos += int(c.arg)
	}
	return n
}

// Copies the content of a (possibly chunked) string item into `dst`, which
// must hold at least `chunks_len(item)` bytes. Returns the bytes written.
chunks_join :: proc "contextless" (item: []u8, dst: []u8) -> int {
	r := reader(item)
	h, _ := read_head(&r)
	if h.info != INFO_INDEFINITE {
		return copy(dst, r.data[r.pos:][:h.arg])
	}
	n := 0
	for r.pos < len(r.data) && r.data[r.pos] != BREAK {
		c, _ := read_head(&r)
		n += copy(dst[n:], r.data[r.pos:][:c.arg])
		r.pos += int(c.arg)
	}
	return n
}

// Skips the chunks of an indefinite string whose head was already read,
// including the final break.
@(private)
skip_chunks :: proc "contextless" (r: ^Reader, major: Major) -> Error {
	for {
		b := peek_byte(r) or_return
		if b == BREAK {
			r.pos += 1
			return .None
		}
		c := read_head(r) or_return
		if c.major != major {
			return .Unexpected_Major
		}
		if c.info == INFO_INDEFINITE {
			return .Unexpected_Indefinite
		}
		if c.arg > u64(len(r.data) - r.pos) {
			return .Eof
		}
		r.pos += int(c.arg)
	}
}

// ---------------------------------------------------------------------------
// Containers

@(require_results)
read_array :: #force_inline proc "contextless" (r: ^Reader) -> (c: Container, err: Error) {
	return read_container(r, .Array, 1)
}

@(require_results)
read_map :: #force_inline proc "contextless" (r: ^Reader) -> (c: Container, err: Error) {
	return read_container(r, .Map, 2)
}

@(private)
@(require_results)
read_container :: #force_inline proc "contextless" (
	r: ^Reader,
	major: Major,
	per_item: u64,
) -> (
	c: Container,
	err: Error,
) {
	h := read_head(r) or_return
	if h.major != major {
		return {}, .Unexpected_Major
	}
	if h.info == INFO_INDEFINITE {
		return Container{indefinite = true}, .None
	}
	// Every element takes at least one byte, so a length beyond what is left
	// can never decode. Rejecting it here keeps `n` small and makes it safe
	// to size allocations from.
	if h.arg > u64(len(r.data) - r.pos) / per_item {
		return {}, .Eof
	}
	return Container{n = int(h.arg)}, .None
}

// Definite or indefinite array that must hold exactly `n` items. Pair with
// `end` once the items have been read.
@(require_results)
read_array_len :: #force_inline proc "contextless" (r: ^Reader, n: int) -> (c: Container, err: Error) {
	c = read_array(r) or_return
	if !c.indefinite && c.n != n {
		return c, .Length_Mismatch
	}
	return c, .None
}

// Definite-length array of exactly `n` items (cborg's `decodeListLenOf`,
// cardano-ledger's `enforceSize`). Indefinite arrays are rejected.
@(require_results)
expect_array_definite :: #force_inline proc "contextless" (r: ^Reader, n: int) -> Error {
	c := read_array(r) or_return
	if c.indefinite {
		return .Unexpected_Indefinite
	}
	return .None if c.n == n else .Length_Mismatch
}

// Closes a fixed-length container: for an indefinite one the next byte must
// be the break.
@(require_results)
end :: #force_inline proc "contextless" (r: ^Reader, c: Container) -> Error #no_bounds_check {
	if !c.indefinite {
		return .None
	}
	if r.pos >= len(r.data) {
		return .Eof
	}
	if r.data[r.pos] != BREAK {
		return .Length_Mismatch
	}
	r.pos += 1
	return .None
}

// Iterates the items of a container:
//
//	c := cbor.read_array(&r) or_return
//	for cbor.more(&r, &c) { item := cbor.read_uint(&r) or_return }
//
// For indefinite containers it consumes the break and returns false. If the
// input ends before the break it returns true so that the item read in the
// loop body reports `.Eof`.
more :: #force_inline proc "contextless" (r: ^Reader, c: ^Container) -> bool #no_bounds_check {
	if !c.indefinite {
		if c.n == 0 {
			return false
		}
		c.n -= 1
		return true
	}
	if r.pos < len(r.data) && r.data[r.pos] == BREAK {
		r.pos += 1
		return false
	}
	return true
}

@(require_results)
read_tag :: #force_inline proc "contextless" (r: ^Reader) -> (v: u64, err: Error) {
	h := read_head(r) or_return
	if h.major != .Tag {
		return 0, .Unexpected_Major
	}
	return h.arg, .None
}

// Reads tag `tag` if it is the next item. Returns whether it was present.
@(require_results)
read_optional_tag :: #force_inline proc "contextless" (r: ^Reader, tag: u64) -> (v: bool, err: Error) {
	save := r.pos
	m := peek_major(r) or_return
	if m != .Tag {
		return false, .None
	}
	t := read_tag(r) or_return
	if t != tag {
		r.pos = save
		return false, .None
	}
	return true, .None
}

@(require_results)
expect_tag :: #force_inline proc "contextless" (r: ^Reader, tag: u64) -> Error {
	t := read_tag(r) or_return
	return .None if t == tag else .Invalid_Value
}

// ---------------------------------------------------------------------------
// Simple values

SIMPLE_FALSE :: 20
SIMPLE_TRUE :: 21
SIMPLE_NULL :: 22
SIMPLE_UNDEFINED :: 23

@(require_results)
read_bool :: #force_inline proc "contextless" (r: ^Reader) -> (v: bool, err: Error) {
	h := read_head(r) or_return
	if h.major != .Simple {
		return false, .Unexpected_Major
	}
	switch h.info {
	case SIMPLE_FALSE:
		return false, .None
	case SIMPLE_TRUE:
		return true, .None
	}
	return false, .Invalid_Value
}

@(require_results)
read_null :: #force_inline proc "contextless" (r: ^Reader) -> Error {
	h := read_head(r) or_return
	if h.major != .Simple || h.info != SIMPLE_NULL {
		return .Unexpected_Major
	}
	return .None
}

// True if the next item is `null`.
@(require_results)
is_null :: #force_inline proc "contextless" (r: ^Reader) -> bool #no_bounds_check {
	return r.pos < len(r.data) && r.data[r.pos] == 0xf6
}

// ---------------------------------------------------------------------------
// Skipping and spans

// Inline capacity of the indefinite-container stack used by `skip`. Deeper
// nesting spills to `Reader.scratch`; honest chain data never does.
SKIP_INLINE_DEPTH :: 64

// Skips one complete data item, checking that it is well formed.
//
// Definite arrays, maps and tags only add to a running count of pending
// items, so they need no stack. Only indefinite containers push a frame,
// because their end is marked by a break rather than a count.
@(require_results)
skip :: proc(r: ^Reader) -> Error {
	inline_stack: [SKIP_INLINE_DEPTH]u64
	spill: [dynamic]u64
	spill.allocator = r.scratch if r.scratch.procedure != nil else context.temp_allocator
	depth := 0

	pending: u64 = 1
	for {
		if pending == 0 {
			if depth == 0 {
				return .None
			}
			// Inside an indefinite container: either another item or the break.
			b := peek_byte(r) or_return
			if b == BREAK {
				r.pos += 1
				depth -= 1
				pending = inline_stack[depth] if depth < SKIP_INLINE_DEPTH else pop(&spill)
				continue
			}
			pending = 1
		}

		h := read_head(r) or_return
		pending -= 1
		left := u64(len(r.data) - r.pos)

		switch h.major {
		case .Unsigned, .Negative, .Simple:
		// read_head has consumed the argument and rejected stray breaks.
		case .Tag:
			pending += 1
		case .Bytes, .Text:
			if h.info == INFO_INDEFINITE {
				skip_chunks(r, h.major) or_return
			} else {
				if h.arg > left do return .Eof
				r.pos += int(h.arg)
			}
		case .Array, .Map:
			per: u64 = 1 if h.major == .Array else 2
			if h.info == INFO_INDEFINITE {
				if depth < SKIP_INLINE_DEPTH {
					inline_stack[depth] = pending
				} else {
					append(&spill, pending)
				}
				depth += 1
				pending = 0
			} else {
				if h.arg > left / per do return .Eof
				pending += h.arg * per
			}
		}
	}
}

// Skips the next item and returns its raw bytes.
@(require_results)
span :: #force_inline proc(r: ^Reader) -> (b: []u8, err: Error) {
	start := r.pos
	skip(r) or_return
	return r.data[start:r.pos], .None
}

// Reads a tag-24 wrapped byte string (CBOR-in-CBOR) and returns the inner
// bytes.
@(require_results)
read_embedded :: #force_inline proc "contextless" (r: ^Reader) -> (b: []u8, err: Error) {
	expect_tag(r, 24) or_return
	return read_bytes(r)
}

// ---------------------------------------------------------------------------
// Arbitrary-precision integers

// An integer as decoded by cborg's `decodeInteger`: major 0/1, or a tag 2/3
// bignum. Values whose magnitude fits 64 bits are normalised into `small`;
// larger ones keep their big-endian magnitude (leading zeros stripped) in
// `big`, aliasing the input.
//
// The value is `small` (or `big`) when !negative, else `-1 - magnitude`, which
// is how both major type 1 and tag 3 encode negatives.
Integer :: struct {
	small:    u64,
	big:      []u8,
	negative: bool,
}

TAG_POSITIVE_BIGNUM :: 2
TAG_NEGATIVE_BIGNUM :: 3

// TODO(conformance): cborg is assumed to require a definite-length byte
// string after tags 2/3; confirm against cborg's Codec.CBOR.Read.
@(require_results)
read_integer :: proc "contextless" (r: ^Reader) -> (v: Integer, err: Error) {
	h := read_head(r) or_return
	#partial switch h.major {
	case .Unsigned:
		return Integer{small = h.arg}, .None
	case .Negative:
		return Integer{small = h.arg, negative = true}, .None
	case .Tag:
		if h.arg != TAG_POSITIVE_BIGNUM && h.arg != TAG_NEGATIVE_BIGNUM {
			return {}, .Unexpected_Tag
		}
		mag := read_bytes(r) or_return
		for len(mag) > 0 && mag[0] == 0 {
			mag = mag[1:]
		}
		v.negative = h.arg == TAG_NEGATIVE_BIGNUM
		if len(mag) <= 8 {
			for b in mag {
				v.small = v.small << 8 | u64(b)
			}
		} else {
			v.big = mag
		}
		return v, .None
	}
	return {}, .Unexpected_Major
}

// Non-negative integer (`decodeNatural`): `decodeInteger` that fails on
// negatives. Returns the value, and whether it fits in 64 bits; callers
// decide whether a larger value is an error.
@(require_results)
read_natural :: proc "contextless" (r: ^Reader) -> (v: u64, fits: bool, err: Error) {
	i := read_integer(r) or_return
	if i.negative {
		return 0, false, .Invalid_Value
	}
	if i.big != nil {
		return max(u64), false, .None
	}
	return i.small, true, .None
}

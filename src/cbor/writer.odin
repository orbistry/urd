package cbor

import "base:runtime"
import "core:encoding/endian"

// Appends CBOR to a growable buffer. Heads always use the minimal encoding.
Writer :: struct {
	buf: [dynamic]u8,
}

writer :: proc(allocator := context.allocator, cap := 256) -> Writer {
	return Writer{buf = make([dynamic]u8, 0, cap, allocator)}
}

writer_destroy :: proc(w: ^Writer) {
	delete(w.buf)
}

writer_reset :: #force_inline proc(w: ^Writer) {
	clear(&w.buf)
}

writer_bytes :: #force_inline proc(w: ^Writer) -> []u8 {
	return w.buf[:]
}

// Encoded size of a head with argument `arg`.
head_size :: #force_inline proc "contextless" (arg: u64) -> int {
	switch {
	case arg < 24:
		return 1
	case arg <= u64(max(u8)):
		return 2
	case arg <= u64(max(u16)):
		return 3
	case arg <= u64(max(u32)):
		return 5
	}
	return 9
}

// Encodes a minimal head into `dst`, which must hold `head_size(arg)` bytes.
put_head :: #force_inline proc "contextless" (dst: []u8, major: Major, arg: u64) -> int #no_bounds_check {
	m := u8(major) << 5
	switch {
	case arg < 24:
		dst[0] = m | u8(arg)
		return 1
	case arg <= u64(max(u8)):
		dst[0] = m | 24
		dst[1] = u8(arg)
		return 2
	case arg <= u64(max(u16)):
		dst[0] = m | 25
		endian.unchecked_put_u16be(dst[1:], u16(arg))
		return 3
	case arg <= u64(max(u32)):
		dst[0] = m | 26
		endian.unchecked_put_u32be(dst[1:], u32(arg))
		return 5
	}
	dst[0] = m | 27
	endian.unchecked_put_u64be(dst[1:], arg)
	return 9
}

write_head :: #force_inline proc(w: ^Writer, major: Major, arg: u64) {
	tmp: [9]u8
	n := put_head(tmp[:], major, arg)
	append(&w.buf, ..tmp[:n])
}

write_uint :: #force_inline proc(w: ^Writer, v: u64) {
	write_head(w, .Unsigned, v)
}

write_int :: #force_inline proc(w: ^Writer, v: i64) {
	if v >= 0 {
		write_head(w, .Unsigned, u64(v))
	} else {
		write_head(w, .Negative, u64(-1 - v))
	}
}

write_int_full :: #force_inline proc(w: ^Writer, v: Int) {
	write_head(w, .Negative if v.negative else .Unsigned, v.arg)
}

write_bytes :: #force_inline proc(w: ^Writer, b: []u8) {
	write_head(w, .Bytes, u64(len(b)))
	append(&w.buf, ..b)
}

write_text :: #force_inline proc(w: ^Writer, s: string) {
	write_head(w, .Text, u64(len(s)))
	append(&w.buf, s)
}

write_array :: #force_inline proc(w: ^Writer, n: int) {
	write_head(w, .Array, u64(n))
}

write_map :: #force_inline proc(w: ^Writer, n: int) {
	write_head(w, .Map, u64(n))
}

write_array_indefinite :: #force_inline proc(w: ^Writer) {
	append(&w.buf, u8(Major.Array) << 5 | INFO_INDEFINITE)
}

write_map_indefinite :: #force_inline proc(w: ^Writer) {
	append(&w.buf, u8(Major.Map) << 5 | INFO_INDEFINITE)
}

write_bytes_indefinite :: #force_inline proc(w: ^Writer) {
	append(&w.buf, u8(Major.Bytes) << 5 | INFO_INDEFINITE)
}

write_break :: #force_inline proc(w: ^Writer) {
	append(&w.buf, BREAK)
}

write_tag :: #force_inline proc(w: ^Writer, tag: u64) {
	write_head(w, .Tag, tag)
}

write_bool :: #force_inline proc(w: ^Writer, v: bool) {
	append(&w.buf, 0xf5 if v else 0xf4)
}

write_null :: #force_inline proc(w: ^Writer) {
	append(&w.buf, 0xf6)
}

// Appends already-encoded CBOR.
write_raw :: #force_inline proc(w: ^Writer, b: []u8) {
	append(&w.buf, ..b)
}

// Starts a tag-24 (CBOR-in-CBOR) byte string whose length is not yet known.
// Write the payload, then call `embedded_end` with the returned mark.
embedded_begin :: proc(w: ^Writer) -> int {
	write_tag(w, 24)
	mark := len(w.buf)
	// Reserve the largest head; `embedded_end` shifts the payload if the
	// minimal head is shorter.
	append(&w.buf, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	return mark
}

embedded_end :: proc(w: ^Writer, mark: int) {
	payload := len(w.buf) - mark - 9
	n := head_size(u64(payload))
	put_head(w.buf[mark:], .Bytes, u64(payload))
	if n < 9 {
		if payload > 0 {
			runtime.mem_copy(&w.buf[mark + n], &w.buf[mark + 9], payload)
		}
		resize(&w.buf, mark + n + payload)
	}
}

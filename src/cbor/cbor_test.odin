package cbor

import "core:encoding/hex"
import "core:testing"

@(private = "file")
unhex :: proc(s: string) -> []u8 {
	b, ok := hex.decode(transmute([]u8)s, context.temp_allocator)
	assert(ok, s)
	return b
}

@(test)
test_uint_widths :: proc(t: ^testing.T) {
	cases := []struct {
		hex: string,
		v:   u64,
	} {
		{"00", 0},
		{"17", 23},
		{"1818", 24},
		{"1903e8", 1000},
		{"1a000f4240", 1000000},
		{"1b000000e8d4a51000", 1000000000000},
		{"1bffffffffffffffff", max(u64)},
		// cborg accepts non-minimal encodings; so do we.
		{"1b0000000000000001", 1},
	}
	for c in cases {
		r := reader(unhex(c.hex))
		v, err := read_uint(&r)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, v, c.v)
		testing.expect_value(t, expect_end(&r), Error.None)
	}
}

@(test)
test_ints :: proc(t: ^testing.T) {
	r := reader(unhex("20"))
	v, err := read_int(&r)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, v, -1)

	r = reader(unhex("3903e7"))
	v, err = read_int(&r)
	testing.expect_value(t, v, -1000)

	r = reader(unhex("3b7fffffffffffffff"))
	v, err = read_int(&r)
	testing.expect_value(t, v, min(i64))

	r = reader(unhex("3b8000000000000000"))
	_, err = read_int(&r)
	testing.expect_value(t, err, Error.Overflow)

	r = reader(unhex("3bffffffffffffffff"))
	full, ferr := read_int_full(&r)
	testing.expect_value(t, ferr, Error.None)
	testing.expect(t, full.negative && full.arg == max(u64))
}

@(test)
test_strings :: proc(t: ^testing.T) {
	r := reader(unhex("4401020304"))
	b, err := read_bytes(&r)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(b), 4)
	testing.expect_value(t, b[3], 4)

	r = reader(unhex("6449455446"))
	s, serr := read_text(&r)
	testing.expect_value(t, serr, Error.None)
	testing.expect_value(t, s, "IETF")

	// Truncated.
	r = reader(unhex("440102"))
	_, err = read_bytes(&r)
	testing.expect_value(t, err, Error.Eof)

	// Indefinite strings are rejected by the plain reader...
	r = reader(unhex("5f42010243030405ff"))
	_, err = read_bytes(&r)
	testing.expect_value(t, err, Error.Unexpected_Indefinite)

	// ...but accepted by the chunked one.
	r = reader(unhex("5f42010243030405ff"))
	item, chunked, cerr := read_bytes_chunked(&r)
	testing.expect_value(t, cerr, Error.None)
	testing.expect(t, chunked)
	testing.expect_value(t, chunks_len(item), 5)
	buf: [5]u8
	testing.expect_value(t, chunks_join(item, buf[:]), 5)
	testing.expect_value(t, buf, [5]u8{1, 2, 3, 4, 5})

	// Chunks must have the same major type.
	r = reader(unhex("5f4201026103ff"))
	_, _, cerr = read_bytes_chunked(&r)
	testing.expect_value(t, cerr, Error.Unexpected_Major)
}

@(test)
test_containers :: proc(t: ^testing.T) {
	// [1, [2, 3], [4, 5]] with mixed definite/indefinite encodings.
	for h in ([]string{"8301820203820405", "9f018202039f0405ffff", "83018202039f0405ff"}) {
		r := reader(unhex(h))
		c, err := read_array(&r)
		testing.expect_value(t, err, Error.None)
		sum: u64
		for more(&r, &c) {
			m, _ := peek_major(&r)
			if m == .Unsigned {
				v, _ := read_uint(&r)
				sum += v
				continue
			}
			inner, _ := read_array(&r)
			for more(&r, &inner) {
				v, e := read_uint(&r)
				testing.expect_value(t, e, Error.None)
				sum += v
			}
		}
		testing.expect_value(t, sum, 15)
		testing.expect_value(t, expect_end(&r), Error.None)
	}

	// Fixed-length records accept indefinite encodings closed by a break.
	r := reader(unhex("9f0102ff"))
	c, err := read_array_len(&r, 2)
	testing.expect_value(t, err, Error.None)
	_, _ = read_uint(&r)
	_, _ = read_uint(&r)
	testing.expect_value(t, end(&r, c), Error.None)

	r = reader(unhex("9f010203ff"))
	c, _ = read_array_len(&r, 2)
	_, _ = read_uint(&r)
	_, _ = read_uint(&r)
	testing.expect_value(t, end(&r, c), Error.Length_Mismatch)

	r = reader(unhex("83010203"))
	_, err = read_array_len(&r, 2)
	testing.expect_value(t, err, Error.Length_Mismatch)

	// An indefinite array whose break is missing reports Eof from the body.
	r = reader(unhex("9f0102"))
	c, _ = read_array(&r)
	n := 0
	last := Error.None
	for more(&r, &c) {
		_, last = read_uint(&r)
		if last != .None do break
		n += 1
	}
	testing.expect_value(t, n, 2)
	testing.expect_value(t, last, Error.Eof)

	// Absurd lengths are rejected before anyone sizes an allocation by them.
	r = reader(unhex("9bffffffffffffffff"))
	_, err = read_array(&r)
	testing.expect_value(t, err, Error.Eof)
	r = reader(unhex("a2010203"))
	_, err = read_map(&r)
	testing.expect_value(t, err, Error.Eof)
}

@(test)
test_skip :: proc(t: ^testing.T) {
	items := []string {
		"00",
		"3bffffffffffffffff",
		"4401020304",
		"5f42010243030405ff",
		"7f657374726561646d696e67ff",
		"8301820203820405",
		"9f018202039f0405ffff",
		"a26161016162820203",
		"bf61610161629f0203ffff",
		"c11a514b67b0",
		"d818488201820203820405",
		"f4",
		"f6",
		"f93c00",
		"fa47c35000",
		"fb3ff199999999999a",
		"f820",
		// [_ [_ [_ ]]]
		"9f9f9fffffff",
	}
	for h in items {
		data := unhex(h)
		// Followed by a sentinel, which skip must not touch.
		buf := make([]u8, len(data) + 1, context.temp_allocator)
		copy(buf, data)
		buf[len(data)] = 0x07
		r := reader(buf)
		s, err := span(&r)
		testing.expectf(t, err == .None, "%s: %v", h, err)
		testing.expectf(t, len(s) == len(data), "%s: span %d != %d", h, len(s), len(data))
	}

	bad := []string {
		// Truncated containers.
		"83010203"[:6],
		"9f0102",
		"bf6161",
		// Stray break.
		"ff",
		"820102ff"[:4] + "ff",
		// Reserved additional info.
		"1c",
		"5c",
		// Indefinite integer / tag.
		"1f",
		"df",
		// Nested indefinite string chunk.
		"5f5f4101ffff",
	}
	for h in bad {
		r := reader(unhex(h))
		err := skip(&r)
		testing.expectf(t, err != .None, "%s: expected an error", h)
	}
}

@(test)
test_skip_deep :: proc(t: ^testing.T) {
	// 10k nested indefinite arrays spill past the inline stack.
	DEPTH :: 10_000
	buf := make([]u8, 2 * DEPTH + 1, context.temp_allocator)
	for i in 0 ..< DEPTH {
		buf[i] = 0x9f
		buf[DEPTH + i] = 0xff
	}
	buf[2 * DEPTH] = 0x00
	r := reader(buf)
	testing.expect_value(t, skip(&r), Error.None)
	testing.expect_value(t, r.pos, 2 * DEPTH)

	// 10k nested definite arrays need no stack at all.
	for i in 0 ..< DEPTH {
		buf[i] = 0x81
	}
	buf[DEPTH] = 0x00
	r = reader(buf[:DEPTH + 1])
	testing.expect_value(t, skip(&r), Error.None)
	testing.expect_value(t, expect_end(&r), Error.None)
}

@(test)
test_writer_roundtrip :: proc(t: ^testing.T) {
	w := writer(context.temp_allocator)
	write_array(&w, 6)
	write_uint(&w, 0)
	write_uint(&w, 500)
	write_int(&w, -1000)
	write_bytes(&w, {1, 2, 3})
	write_text(&w, "urd")
	mark := embedded_begin(&w)
	write_array(&w, 2)
	write_bool(&w, true)
	write_null(&w)
	embedded_end(&w, mark)

	testing.expect_value(t, hex_of(writer_bytes(&w)), "86001901f43903e74301020363757264d8184382f5f6")

	r := reader(writer_bytes(&w))
	c, _ := read_array_len(&r, 6)
	a, _ := read_uint(&r)
	b, _ := read_uint(&r)
	i, _ := read_int(&r)
	bs, _ := read_bytes(&r)
	s, _ := read_text(&r)
	inner, err := read_embedded(&r)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, end(&r, c), Error.None)
	testing.expect_value(t, expect_end(&r), Error.None)
	testing.expect(t, a == 0 && b == 500 && i == -1000 && len(bs) == 3 && s == "urd")
	ir := reader(inner)
	ic, _ := read_array_len(&ir, 2)
	v, _ := read_bool(&ir)
	testing.expect(t, v)
	testing.expect_value(t, read_null(&ir), Error.None)
	testing.expect_value(t, end(&ir, ic), Error.None)

	// Embedded payloads long enough to need a wider head.
	w2 := writer(context.temp_allocator)
	mark = embedded_begin(&w2)
	for _ in 0 ..< 300 do write_uint(&w2, 1)
	embedded_end(&w2, mark)
	r = reader(writer_bytes(&w2))
	inner, err = read_embedded(&r)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(inner), 300)
}

@(private = "file")
hex_of :: proc(b: []u8) -> string {
	return string(hex.encode(b, context.temp_allocator))
}

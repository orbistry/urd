package cbor

import "core:fmt"
import "core:strings"

// Renders one data item in RFC 8949 diagnostic notation, for debugging and
// tools. Indefinite containers are shown with `_`. Stops at the first
// malformed byte and appends the error.
diagnose :: proc(data: []u8, allocator := context.allocator) -> string {
	b := strings.builder_make(allocator)
	r := reader(data)
	err := diag_item(&r, &b, 0)
	if err != .None {
		fmt.sbprintf(&b, " <error %v at byte %d>", err, r.pos)
	} else if r.pos < len(data) {
		fmt.sbprintf(&b, " <%d trailing bytes>", len(data) - r.pos)
	}
	return strings.to_string(b)
}

@(private = "file")
diag_item :: proc(r: ^Reader, b: ^strings.Builder, depth: int) -> Error {
	if depth > 512 {
		strings.write_string(b, "...")
		return skip(r)
	}
	h := read_head(r) or_return
	switch h.major {
	case .Unsigned:
		fmt.sbprintf(b, "%d", h.arg)
	case .Negative:
		fmt.sbprintf(b, "-%d", u128(h.arg) + 1)
	case .Bytes, .Text:
		if h.info == INFO_INDEFINITE {
			strings.write_string(b, "(_ ")
			first := true
			for {
				c := peek_byte(r) or_return
				if c == BREAK {
					r.pos += 1
					break
				}
				if !first do strings.write_string(b, ", ")
				first = false
				diag_item(r, b, depth + 1) or_return
			}
			strings.write_string(b, ")")
			return .None
		}
		if h.arg > u64(remaining(r)) do return .Eof
		s := r.data[r.pos:][:h.arg]
		r.pos += int(h.arg)
		if h.major == .Text {
			fmt.sbprintf(b, "%q", string(s))
		} else {
			strings.write_string(b, "h'")
			for c in s do fmt.sbprintf(b, "%02x", c)
			strings.write_string(b, "'")
		}
	case .Array, .Map:
		open, close := "[", "]"
		if h.major == .Map do open, close = "{", "}"
		strings.write_string(b, open)
		indef := h.info == INFO_INDEFINITE
		if indef do strings.write_string(b, "_ ")
		n := h.arg
		for i: u64 = 0; indef || i < n; i += 1 {
			if indef {
				c := peek_byte(r) or_return
				if c == BREAK {
					r.pos += 1
					break
				}
			}
			if i > 0 do strings.write_string(b, ", ")
			diag_item(r, b, depth + 1) or_return
			if h.major == .Map {
				strings.write_string(b, ": ")
				diag_item(r, b, depth + 1) or_return
			}
		}
		strings.write_string(b, close)
	case .Tag:
		fmt.sbprintf(b, "%d(", h.arg)
		diag_item(r, b, depth + 1) or_return
		strings.write_string(b, ")")
	case .Simple:
		switch h.info {
		case SIMPLE_FALSE:
			strings.write_string(b, "false")
		case SIMPLE_TRUE:
			strings.write_string(b, "true")
		case SIMPLE_NULL:
			strings.write_string(b, "null")
		case SIMPLE_UNDEFINED:
			strings.write_string(b, "undefined")
		case 25, 26, 27:
			fmt.sbprintf(b, "float(0x%x)", h.arg)
		case:
			fmt.sbprintf(b, "simple(%d)", h.arg)
		}
	}
	return .None
}

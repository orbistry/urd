package ledger

import "base:runtime"

import "urd:base"
import "urd:cbor"
import "urd:ccrypto"

// Scripts, Plutus Data and metadata, docs/decoding/witnesses-auxdata-byron.md
// §A.3 to §A.6. None of these structures has a nesting limit in Haskell, so
// they are walked with explicit stacks rather than recursion.

Script_Kind :: enum u8 {
	Native    = 0,
	Plutus_V1 = 1,
	Plutus_V2 = 2,
	Plutus_V3 = 3,
}

Script :: struct {
	hash:  base.Script_Hash,
	kind:  Script_Kind,
	// Native: the script's own bytes. Plutus: the content of the byte string.
	bytes: base.Span,
}

// Script hash: Blake2b-224 over the language tag followed by the script bytes
// (0x00 for native scripts, 0x01.. for Plutus V1..).
script_hash :: proc "contextless" (kind: Script_Kind, bytes: []u8) -> base.Script_Hash {
	s: ccrypto.Blake2b_224
	ccrypto.blake2b_224_init(&s)
	tag := [1]u8{u8(kind)}
	ccrypto.blake2b_224_update(&s, tag[:])
	ccrypto.blake2b_224_update(&s, bytes)
	return base.Script_Hash(ccrypto.blake2b_224_final(&s))
}

// Plutus languages an era's scripts may use (mkPlutusScript).
era_supports :: proc "contextless" (era: base.Era, kind: Script_Kind) -> bool {
	switch kind {
	case .Native:
		return era >= .Allegra || era == .Shelley
	case .Plutus_V1:
		return era >= .Alonzo
	case .Plutus_V2:
		return era >= .Babbage
	case .Plutus_V3:
		return era >= .Conway
	}
	return false
}

// ---------------------------------------------------------------------------
// A small explicit stack: inline frames, spilling to the block scratch only
// for pathological nesting.

@(private)
STACK_INLINE :: 32

@(private)
Stack :: struct($T: typeid) {
	inline: [STACK_INLINE]T,
	spill:  [dynamic]T,
	n:      int,
	// Where frames beyond STACK_INLINE go (the decoder's scratch); when unset,
	// context.temp_allocator.
	alloc:  runtime.Allocator,
}

@(private)
stack_push :: proc(s: ^Stack($T), v: T) {
	if s.n < STACK_INLINE {
		s.inline[s.n] = v
	} else {
		if s.spill == nil {
			s.spill = make([dynamic]T, s.alloc if s.alloc.procedure != nil else context.temp_allocator)
		}
		append(&s.spill, v)
	}
	s.n += 1
}

@(private)
stack_top :: proc(s: ^Stack($T)) -> ^T {
	i := s.n - 1
	return &s.inline[i] if i < STACK_INLINE else &s.spill[i - STACK_INLINE]
}

@(private)
stack_pop :: proc(s: ^Stack($T)) {
	s.n -= 1
	if s.n >= STACK_INLINE do pop(&s.spill)
}

// ---------------------------------------------------------------------------
// Native scripts

// Decodes one native script and returns its bytes. Shelley decodes MultiSig
// (tags 0..3); Allegra onwards Timelock (tags 0..5). Every node is a
// `decodeRecordSum`; n-of-k counts are signed Ints (negative allowed); child
// lists are StrictSeqs, definite or indefinite.
read_native_script :: proc(d: ^Decoder) -> (bytes: []u8, err: Error) {
	Frame :: struct {
		node:   cbor.Container,
		list:   cbor.Container,
		fields: int,
	}
	start := d.r.pos
	timelock := d.era >= .Allegra
	stack := Stack(Frame) {
		alloc = d.scratch,
	}

	// Reads one node; a node with children pushes a frame.
	node :: proc(d: ^Decoder, stack: ^Stack(Frame), timelock: bool) -> Error {
		tag, c := read_sum(d) or_return
		switch tag {
		case 0:
			_ = read_hash28(d) or_return
			return end_sum(d, c, 1)
		case 1, 2:
			l := cbor.read_array(&d.r) or_return
			stack_push(stack, Frame{node = c, list = l, fields = 1})
			return .None
		case 3:
			_ = cbor.read_int(&d.r) or_return
			l := cbor.read_array(&d.r) or_return
			stack_push(stack, Frame{node = c, list = l, fields = 2})
			return .None
		case 4, 5:
			if !timelock do return .Invalid_Value
			_ = cbor.read_uint(&d.r) or_return
			return end_sum(d, c, 1)
		}
		return .Invalid_Value
	}

	node(d, &stack, timelock) or_return
	for stack.n > 0 {
		top := stack_top(&stack)
		if cbor.more(&d.r, &top.list) {
			node(d, &stack, timelock) or_return
			continue
		}
		end_sum(d, top.node, top.fields) or_return
		stack_pop(&stack)
	}
	return d.r.data[start:d.r.pos], .None
}

// Appends a native script (as found in witness sets, auxiliary data and
// reference scripts) to `out`.
read_native_script_into :: proc(d: ^Decoder, out: ^[dynamic]Script) -> Error {
	b := read_native_script(d) or_return
	append(out, Script{hash = script_hash(.Native, b), kind = .Native, bytes = span(d, b)})
	return .None
}

// A Plutus script in a witness set: definite bytes of any length (never
// checked for well-formedness at decode time), in a language the era supports.
read_plutus_script_into :: proc(d: ^Decoder, kind: Script_Kind, out: ^[dynamic]Script) -> Error {
	b := cbor.read_bytes(&d.r) or_return
	if !era_supports(d.era, kind) {
		return .Invalid_Value
	}
	append(out, Script{hash = script_hash(kind, b), kind = kind, bytes = span(d, b)})
	return .None
}

// Babbage+ reference script: #6.24(bytes .cbor [language, script]), decoded
// completely at the era's version. Returns the inner bytes.
read_script_ref :: proc(d: ^Decoder) -> (inner: []u8, err: Error) {
	inner = cbor.read_embedded(&d.r) or_return
	sd := sub_decoder(d, inner)
	tag, c := read_sum(&sd) or_return
	switch tag {
	case 0:
		_ = read_native_script(&sd) or_return
	case 1, 2, 3:
		_ = cbor.read_bytes(&sd.r) or_return
		if !era_supports(d.era, Script_Kind(tag)) do return nil, .Invalid_Value
	case:
		return nil, .Invalid_Value
	}
	end_sum(&sd, c, 1) or_return
	cbor.expect_end(&sd.r) or_return
	return inner, .None
}

// Hash and kind of a reference script's inner `[language, script]` bytes.
script_ref_info :: proc(inner: []u8) -> (s: Script, ok: bool) {
	r := cbor.reader(inner)
	c, err := cbor.read_array(&r)
	if err != .None || (!c.indefinite && c.n != 2) do return {}, false
	tag, terr := cbor.read_uint(&r)
	if terr != .None || tag > 3 do return {}, false
	s.kind = Script_Kind(tag)
	start := r.pos
	if tag == 0 {
		if cbor.skip(&r) != .None do return {}, false
		s.hash = script_hash(.Native, r.data[start:r.pos])
	} else {
		b, berr := cbor.read_bytes(&r)
		if berr != .None do return {}, false
		s.hash = script_hash(s.kind, b)
	}
	return s, true
}

// ---------------------------------------------------------------------------
// Plutus Data (plutus-core PlutusCore/Data.hs decodeData)

PLUTUS_BYTES_CHUNK_MAX :: 64

// Checks that `r` is positioned at one well-formed Plutus Data item and
// consumes it. Deep nesting spills to `r.scratch`. Byte strings (and bignum payloads) are limited to 64 bytes per
// definite string or per chunk of an indefinite one; maps keep duplicates.
validate_plutus_data :: proc(r: ^cbor.Reader) -> Error {
	Frame :: struct {
		c:           cbor.Container,
		// Items still owed by a definite container (maps count two per entry).
		left:        u64,
		// Closing this list also closes a `102` constructor wrapper.
		wrapper:     cbor.Container,
		has_wrapper: bool,
	}
	stack := Stack(Frame) {
		alloc = r.scratch,
	}

	item :: proc(r: ^cbor.Reader, stack: ^Stack(Frame)) -> Error {
		b := cbor.peek_byte(r) or_return
		h := cbor.read_head(r) or_return
		switch h.major {
		case .Unsigned, .Negative:
			return .None
		case .Bytes:
			return bounded_bytes_after_head(r, h)
		case .Array, .Map:
			per: u64 = 1 if h.major == .Array else 2
			f := Frame {
				c = cbor.Container{indefinite = h.info == cbor.INFO_INDEFINITE},
			}
			if !f.c.indefinite {
				if h.arg > u64(cbor.remaining(r)) / per do return .Eof
				f.left = h.arg * per
			}
			stack_push(stack, f)
			return .None
		case .Tag:
			switch {
			case h.arg == 2 || h.arg == 3:
				// cborg only treats the one-byte headers 0xc2/0xc3 as bignums;
				// a wider tag 2/3 reaches the constructor decoder and fails.
				// TODO(conformance): confirm against cborg's token classifier.
				if b != 0xc2 && b != 0xc3 do return .Unexpected_Tag
				bh := cbor.read_head(r) or_return
				if bh.major != .Bytes do return .Unexpected_Major
				return bounded_bytes_after_head(r, bh)
			case (h.arg >= 121 && h.arg <= 127) || (h.arg >= 1280 && h.arg <= 1400):
				return list_frame(r, stack, {}, false)
			case h.arg == 102:
				w := cbor.read_array(r) or_return
				if !w.indefinite && w.n != 2 do return .Length_Mismatch
				_ = cbor.read_uint(r) or_return
				return list_frame(r, stack, w, true)
			}
			return .Unexpected_Tag
		case .Simple, .Text:
		}
		return .Unexpected_Major
	}

	list_frame :: proc(r: ^cbor.Reader, stack: ^Stack(Frame), wrapper: cbor.Container, has_wrapper: bool) -> Error {
		c := cbor.read_array(r) or_return
		f := Frame {
			c           = c,
			wrapper     = wrapper,
			has_wrapper = has_wrapper,
		}
		if !c.indefinite do f.left = u64(c.n)
		stack_push(stack, f)
		return .None
	}

	item(r, &stack) or_return
	for stack.n > 0 {
		top := stack_top(&stack)
		done: bool
		if top.c.indefinite {
			b := cbor.peek_byte(r) or_return
			if b == cbor.BREAK {
				r.pos += 1
				done = true
			}
		} else {
			done = top.left == 0
			if !done do top.left -= 1
		}
		if !done {
			item(r, &stack) or_return
			continue
		}
		if top.has_wrapper {
			cbor.end(r, top.wrapper) or_return
		}
		stack_pop(&stack)
	}
	return .None
}

// The body of a Plutus Data byte string whose head was just read: definite
// and at most 64 bytes, or indefinite with definite chunks of at most 64.
@(private = "file")
bounded_bytes_after_head :: proc "contextless" (r: ^cbor.Reader, h: cbor.Head) -> Error {
	if h.info != cbor.INFO_INDEFINITE {
		if h.arg > PLUTUS_BYTES_CHUNK_MAX do return .Invalid_Value
		if h.arg > u64(cbor.remaining(r)) do return .Eof
		r.pos += int(h.arg)
		return .None
	}
	for {
		b := cbor.peek_byte(r) or_return
		if b == cbor.BREAK {
			r.pos += 1
			return .None
		}
		chunk := cbor.read_bytes(r) or_return
		if len(chunk) > PLUTUS_BYTES_CHUNK_MAX do return .Invalid_Value
	}
}

// Inline datum: #6.24(bytes .cbor plutus_data), the payload decoding to
// exactly one Data item. Returns the payload.
read_inline_datum :: proc(d: ^Decoder) -> (payload: []u8, err: Error) {
	payload = cbor.read_embedded(&d.r) or_return
	r := cbor.reader(payload)
	r.scratch = d.scratch
	validate_plutus_data(&r) or_return
	cbor.expect_end(&r) or_return
	return payload, .None
}

// ---------------------------------------------------------------------------
// Transaction metadata (cardano-ledger-core Metadata.hs)

METADATA_STRING_MAX :: 64

// One metadatum: integers (major 0/1, no bignums), byte and text strings
// (from Allegra at most 64 bytes, indefinite ones measured after joining),
// arrays and maps of metadata. Tags, floats and simple values fail.
validate_metadatum :: proc(d: ^Decoder) -> Error {
	Frame :: struct {
		c:    cbor.Container,
		left: u64,
	}
	check_sizes := d.v > 2
	r := &d.r
	stack := Stack(Frame) {
		alloc = d.scratch,
	}

	item :: proc(r: ^cbor.Reader, stack: ^Stack(Frame), check_sizes: bool) -> Error {
		h := cbor.read_head(r) or_return
		switch h.major {
		case .Unsigned, .Negative:
			return .None
		case .Bytes, .Text:
			total: u64
			if h.info != cbor.INFO_INDEFINITE {
				if h.arg > u64(cbor.remaining(r)) do return .Eof
				if h.major == .Text && !cbor.valid_utf8(r.data[r.pos:][:h.arg]) do return .Invalid_Value
				r.pos += int(h.arg)
				total = h.arg
			} else {
				// TODO(conformance): cborg decodes each text chunk as UTF-8
				// on its own; a code point split across chunks is assumed to
				// fail.
				for {
					b := cbor.peek_byte(r) or_return
					if b == cbor.BREAK {
						r.pos += 1
						break
					}
					chunk := cbor.read_string(r, h.major) or_return
					if h.major == .Text && !cbor.valid_utf8(chunk) do return .Invalid_Value
					total += u64(len(chunk))
				}
			}
			if check_sizes && total > METADATA_STRING_MAX do return .Invalid_Value
			return .None
		case .Array, .Map:
			per: u64 = 1 if h.major == .Array else 2
			f := Frame {
				c = cbor.Container{indefinite = h.info == cbor.INFO_INDEFINITE},
			}
			if !f.c.indefinite {
				if h.arg > u64(cbor.remaining(r)) / per do return .Eof
				f.left = h.arg * per
			}
			stack_push(stack, f)
			return .None
		case .Tag, .Simple:
		}
		return .Unexpected_Major
	}

	item(r, &stack, check_sizes) or_return
	for stack.n > 0 {
		top := stack_top(&stack)
		done: bool
		if top.c.indefinite {
			b := cbor.peek_byte(r) or_return
			if b == cbor.BREAK {
				r.pos += 1
				done = true
			}
		} else {
			done = top.left == 0
			if !done do top.left -= 1
		}
		if !done {
			item(r, &stack, check_sizes) or_return
			continue
		}
		stack_pop(&stack)
	}
	return .None
}

// Metadata: { Word64 label => metadatum }. Repeated labels are last-wins
// below v9 and fail from v9.
read_metadata :: proc(d: ^Decoder) -> Error {
	labels := make([dynamic]u64, d.scratch)
	m := cbor.read_map(&d.r) or_return
	for cbor.more(&d.r, &m) {
		append(&labels, cbor.read_uint(&d.r) or_return)
		validate_metadatum(d) or_return
	}
	if d.v >= 9 {
		_ = unique_sorted_u64(d, labels[:]) or_return
	}
	return .None
}

@(private = "file")
unique_sorted_u64 :: proc(d: ^Decoder, xs: []u64) -> (n: int, err: Error) {
	sort_u64(xs)
	return unique_sorted(d, xs)
}

// Package ledger decodes and validates Shelley-family blocks (Shelley through
// Conway). Byron lives in `ledger/byron`.
package ledger

import "core:slice"

import "urd:base"
import "urd:cbor"
import "urd:ccrypto"

// Block tags of the hard-fork combinator's block encoding (on disk and
// inside block-fetch's CBOR-in-CBOR). Byron keeps its own `[0, ebb]` /
// `[1, main]` encoding; later eras are tagged with era index + 1.
Block_Tag :: enum u8 {
	Byron_Ebb  = 0,
	Byron_Main = 1,
	Shelley    = 2,
	Allegra    = 3,
	Mary       = 4,
	Alonzo     = 5,
	Babbage    = 6,
	Conway     = 7,
	Dijkstra   = 8,
}

block_tag_era :: proc "contextless" (t: Block_Tag) -> base.Era {
	switch t {
	case .Byron_Ebb, .Byron_Main:
		return .Byron
	case .Shelley ..= .Dijkstra:
	}
	return base.Era(u8(t) - 1)
}

// A hard-fork wrapped block split into its era and the era block's bytes.
Envelope :: struct {
	tag:   Block_Tag,
	era:   base.Era,
	// The era-specific block: for Byron the EBB or main block array (without
	// the `[0/1, ...]` wrapper), otherwise the Shelley-family block array.
	block: []u8,
}

// Decodes the `[tag, block]` wrapper. The ouroboros-consensus decoder uses
// `enforceSize 2`, so the wrapper must be a definite array.
decode_envelope :: proc(data: []u8) -> (env: Envelope, err: cbor.Error) {
	r := cbor.reader(data)
	cbor.expect_array_definite(&r, 2) or_return
	tag := cbor.read_uint(&r) or_return
	if tag > u64(Block_Tag.Dijkstra) {
		return {}, .Invalid_Value
	}
	env.tag = Block_Tag(tag)
	env.era = block_tag_era(env.tag)
	env.block = cbor.span(&r) or_return
	cbor.expect_end(&r) or_return
	return env, .None
}

// Raw parts of a Shelley-family block, before the transactions are decoded.
Block_Parts :: struct {
	header:    Header,
	// Each part's original bytes; the body hash is computed over them.
	bodies:    []u8,
	witnesses: []u8,
	aux_data:  []u8,
	// Alonzo onwards: the list of phase-2 invalid transaction indices.
	invalid:   []u8,
	// Size of the block body (everything after the header) as the header's
	// `body_size` counts it.
	body_size: int,
	body_hash: base.Hash32,
}

// Splits a Shelley-family block into its header and body parts, decoding the
// header. Shelley to Mary blocks have four parts, Alonzo onwards five.
decode_block_parts :: proc(block: []u8, era: base.Era, p: ^Block_Parts) -> cbor.Error {
	assert(era >= .Shelley)
	r := cbor.reader(block)
	n_parts := 4 if era < .Alonzo else 5
	c := cbor.read_array_len(&r, n_parts) or_return
	decode_header(&r, era, &p.header) or_return

	body_start := r.pos
	p.bodies = cbor.span(&r) or_return
	p.witnesses = cbor.span(&r) or_return
	p.aux_data = cbor.span(&r) or_return
	p.invalid = nil
	if era >= .Alonzo {
		p.invalid = cbor.span(&r) or_return
	}
	p.body_size = r.pos - body_start
	cbor.end(&r, c) or_return
	cbor.expect_end(&r) or_return

	p.body_hash = body_hash(p)
	return .None
}

// The block body hash: Blake2b-256 over the concatenated Blake2b-256 hashes of
// each body part (hashShelleySegWits / hashAlonzoSegWits).
body_hash :: proc "contextless" (p: ^Block_Parts) -> base.Hash32 {
	parts: [4 * 32]u8
	n := 0
	for part in ([4][]u8{p.bodies, p.witnesses, p.aux_data, p.invalid}) {
		if part == nil {
			break
		}
		h := ccrypto.blake2b_256(part)
		copy(parts[n:], h[:])
		n += 32
	}
	return ccrypto.blake2b_256(parts[:n])
}

// A fully decoded Shelley-family block: the header plus its transactions in
// `Block_Tables` (whose txs rows are this block's).
Block :: struct {
	header:    Header,
	era:       base.Era,
	// Computed from the body parts as decoded (not trusted from the header).
	body_hash: base.Hash32,
	body_size: int,
}

// Decodes a Shelley-family block completely into `t` (reset first).
//
// Body part boundaries come from the real decoders, not a generic CBOR skip:
// Haskell's withSlice records what its decoders consumed, and a few of them
// accept shapes that a structural skip would delimit differently (see
// `read_recd`).
decode_block :: proc(block: []u8, era: base.Era, t: ^Block_Tables, b: ^Block) -> (err: Error) {
	assert(era >= .Shelley)
	tables_reset(t)
	d := make_decoder(block, era, t)
	defer if err != .None do last_error_pos = d.r.pos
	b.era = era

	n_parts := 4 if era < .Alonzo else 5
	outer := read_rec(&d, n_parts) or_return
	decode_header(&d.r, era, &b.header) or_return

	// Transaction bodies.
	body_start := d.r.pos
	bodies := cbor.read_array(&d.r) or_return
	for cbor.more(&d.r, &bodies) {
		tx: Tx
		tx.flags += {.Valid}
		start := d.r.pos
		read_tx_body(&d, &tx) or_return
		tx.body = span_from(&d, start)
		tx.id = base.Tx_Id(ccrypto.blake2b_256(d.r.data[start:d.r.pos]))
		append(&t.txs, tx)
	}
	bodies_bytes := d.r.data[body_start:d.r.pos]
	n_txs := len(t.txs)

	// Witness sets, one per body.
	wits_start := d.r.pos
	wits := cbor.read_array(&d.r) or_return
	i := 0
	for cbor.more(&d.r, &wits) {
		if i >= n_txs do return .Inconsistent
		start := d.r.pos
		read_witness_set(&d, &t.txs[i]) or_return
		t.txs[i].witnesses = span_from(&d, start)
		i += 1
	}
	if i != n_txs do return .Inconsistent
	wits_bytes := d.r.data[wits_start:d.r.pos]

	// Auxiliary data: { tx index => aux data } (IntMap). Repeated indices are
	// last-wins below v9 and fail from v9; every index must name a body.
	aux_start := d.r.pos
	aux := cbor.read_map(&d.r) or_return
	seen_aux := make([dynamic]int, d.scratch)
	for cbor.more(&d.r, &aux) {
		idx := cbor.read_int(&d.r) or_return
		start := d.r.pos
		tx_tmp: Tx
		read_aux_data(&d, &tx_tmp) or_return
		if idx < 0 || idx >= i64(n_txs) do return .Inconsistent
		tx := &t.txs[idx]
		tx.aux_data = span_from(&d, start)
		tx.aux_scripts = tx_tmp.aux_scripts
		tx.flags += {.Aux_Data}
		append(&seen_aux, int(idx))
	}
	if d.v >= 9 {
		sort_ints(seen_aux[:])
		for k in 1 ..< len(seen_aux) {
			if seen_aux[k] == seen_aux[k - 1] do return .Duplicate_Key
		}
	}
	aux_bytes := d.r.data[aux_start:d.r.pos]

	// Phase-2 invalid transactions (Alonzo onwards).
	invalid_bytes: []u8
	if era >= .Alonzo {
		inv_start := d.r.pos
		idxs := make([dynamic]i64, d.scratch)
		inv := cbor.read_array(&d.r) or_return
		for cbor.more(&d.r, &inv) {
			v := cbor.read_int(&d.r) or_return
			if v < 0 || v >= i64(n_txs) do return .Inconsistent
			append(&idxs, v)
		}
		apply_valid_flags(t.txs[:], idxs[:])
		invalid_bytes = d.r.data[inv_start:d.r.pos]
	}
	b.body_size = d.r.pos - body_start
	cbor.end(&d.r, outer) or_return
	cbor.expect_end(&d.r) or_return

	// Transaction sizes as the ledger re-assembles them: a list header (one
	// byte), body, witnesses, the validity flag (Alonzo onwards, one byte),
	// and the auxiliary data or null (one byte).
	for &tx in t.txs {
		size := 1 + tx.body.len + tx.witnesses.len
		if era >= .Alonzo do size += 1
		size += tx.aux_data.len if .Aux_Data in tx.flags else 1
		tx.size = size
	}

	parts := Block_Parts {
		bodies    = bodies_bytes,
		witnesses = wits_bytes,
		aux_data  = aux_bytes,
		invalid   = invalid_bytes,
	}
	b.body_hash = body_hash(&parts)
	return .None
}

// alignedValidFlags: pairs the invalid-index list with the transactions the
// way Haskell does, without sorting it first. For each listed index x after
// the previous one p, (x - p - 1) valid flags then one invalid flag are
// emitted, and the flags are zipped with the transactions (extra flags
// dropped). An unsorted or repeated list therefore shifts which transactions
// are marked invalid, exactly as on the reference node.
apply_valid_flags :: proc "contextless" (txs: []Tx, idxs: []i64) {
	pos := 0
	prev: i64 = -1
	for x in idxs {
		for k: i64 = 0; k < x - prev - 1 && pos < len(txs); k += 1 {
			pos += 1 // valid
		}
		if pos < len(txs) {
			txs[pos].flags -= {.Valid}
			pos += 1
		}
		prev = x
	}
}

@(private = "file")
sort_ints :: proc(xs: []int) {
	slice.sort(xs)
}

// Decodes a standalone transaction (as submitted, or in chain-sync's tx
// payloads): Shelley to Mary `[body, witnesses, aux / null]`, Alonzo onwards
// `[body, witnesses, is_valid, aux / null]`, each a decodeRecordNamed.
// The transaction is the single row of `t.txs`.
decode_tx :: proc(data: []u8, era: base.Era, t: ^Block_Tables) -> (err: Error) {
	assert(era >= .Shelley)
	tables_reset(t)
	d := make_decoder(data, era, t)
	defer if err != .None do last_error_pos = d.r.pos
	c := read_rec(&d, 4 if era >= .Alonzo else 3) or_return

	tx: Tx
	start := d.r.pos
	read_tx_body(&d, &tx) or_return
	tx.body = span_from(&d, start)
	tx.id = base.Tx_Id(ccrypto.blake2b_256(d.r.data[start:d.r.pos]))

	start = d.r.pos
	read_witness_set(&d, &tx) or_return
	tx.witnesses = span_from(&d, start)

	if era >= .Alonzo {
		valid := cbor.read_bool(&d.r) or_return
		if valid do tx.flags += {.Valid}
	} else {
		tx.flags += {.Valid}
	}
	if read_null_or(&d) {
		start = d.r.pos
		read_aux_data(&d, &tx) or_return
		tx.aux_data = span_from(&d, start)
		tx.flags += {.Aux_Data}
	}
	cbor.end(&d.r, c) or_return
	cbor.expect_end(&d.r) or_return
	tx.size = u32(len(data))
	append(&t.txs, tx)
	return .None
}

// Byte offset at which the last failed standalone decode on this thread
// stopped. Diagnostics only.
@(thread_local)
last_error_pos: int

// Decodes a standalone transaction body.
decode_tx_body :: proc(data: []u8, era: base.Era, t: ^Block_Tables) -> (err: Error) {
	tables_reset(t)
	d := make_decoder(data, era, t)
	defer if err != .None do last_error_pos = d.r.pos
	tx: Tx
	read_tx_body(&d, &tx) or_return
	cbor.expect_end(&d.r) or_return
	tx.body = base.Span{0, u32(len(data))}
	append(&t.txs, tx)
	return .None
}

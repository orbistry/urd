package byron

import "core:math/bits"

import "urd:base"
import "urd:cbor"
import "urd:ccrypto"

// Byron blocks (byron/Block/Block.hs, Body.hs, Boundary.hs), docs B.1-B.3.

// Decoded rows of one block, flattened across its transactions. Reset and
// refilled per block, so capacity is reused.
Tables :: struct {
	txs:        [dynamic]Tx,
	inputs:     [dynamic]base.Tx_In,
	outputs:    [dynamic]Tx_Out,
	witnesses:  [dynamic]Witness,
	certs:      [dynamic]Delegation_Cert,
	// At most one per block.
	proposals:  [dynamic]Proposal,
	installers: [dynamic]Installer,
	votes:      [dynamic]Vote,
	// Scratch: Merkle leaves, and re-encodings of non-canonical transactions.
	leaves:     [dynamic]base.Hash32,
	encoder:    cbor.Writer,
}

tables_init :: proc(t: ^Tables, allocator := context.allocator) {
	t.txs = make([dynamic]Tx, allocator)
	t.inputs = make([dynamic]base.Tx_In, allocator)
	t.outputs = make([dynamic]Tx_Out, allocator)
	t.witnesses = make([dynamic]Witness, allocator)
	t.certs = make([dynamic]Delegation_Cert, allocator)
	t.proposals = make([dynamic]Proposal, allocator)
	t.installers = make([dynamic]Installer, allocator)
	t.votes = make([dynamic]Vote, allocator)
	t.leaves = make([dynamic]base.Hash32, allocator)
	t.encoder = cbor.writer(allocator)
}

tables_reset :: proc(t: ^Tables) {
	clear(&t.txs)
	clear(&t.inputs)
	clear(&t.outputs)
	clear(&t.witnesses)
	clear(&t.certs)
	clear(&t.proposals)
	clear(&t.installers)
	clear(&t.votes)
	clear(&t.leaves)
	cbor.writer_reset(&t.encoder)
}

tables_destroy :: proc(t: ^Tables) {
	delete(t.txs)
	delete(t.inputs)
	delete(t.outputs)
	delete(t.witnesses)
	delete(t.certs)
	delete(t.proposals)
	delete(t.installers)
	delete(t.votes)
	delete(t.leaves)
	cbor.writer_destroy(&t.encoder)
}

// A decoded Byron block. Its rows are in the tables it was decoded into.
Block :: struct {
	is_ebb:      bool,
	// Length of the block array: `blockLength` / `boundaryBlockLength`, which
	// the size rules bound.
	size:        u32,
	// The header within the block. `main` and `ebb` spans are relative to it.
	header:      base.Span,
	hash:        base.Block_Hash,
	main:        Header,
	ebb:         Ebb_Header,
	// Main blocks: the proof computed from the body. Comparing it with
	// `main.proof` is a rule (validateHeaderMatchesBody), see `proof_matches`.
	proof:       Body_Proof,
	// The delegation and update payloads as received.
	dlg_payload: base.Span,
	upd_payload: base.Span,
}

// Decodes a Byron block: the EBB or main block array inside the `[0/1, ...]`
// envelope (`decCBORABoundaryBlock` / `decCBORABlock`). `block` must be
// exactly that array.
decode_block :: proc(block: []u8, is_ebb: bool, epoch_slots: u64, t: ^Tables, b: ^Block) -> Error {
	tables_reset(t)
	b^ = {}
	b.is_ebb = is_ebb
	b.size = u32(len(block))
	d := Decoder {
		r    = cbor.reader(block),
		base = block,
		t    = t,
	}
	r := &d.r
	enforce_size(r, 3) or_return

	// The header decodes over its own bytes, so its spans are relative to it.
	start := r.pos
	hd := Decoder {
		r    = cbor.reader(block[start:]),
		base = block[start:],
	}
	if is_ebb {
		b.ebb = read_ebb_header(&hd.r) or_return
	} else {
		b.main = read_header(&hd, epoch_slots) or_return
	}
	r.pos = start + hd.r.pos
	b.header = span_from(&d, start)
	b.hash = header_hash(base.span_bytes(block, b.header), is_ebb)

	if is_ebb {
		drop_ebb_body(r) or_return
		return cbor.expect_end(r)
	}

	read_body(&d, b) or_return
	// Extra body data: [{}].
	enforce_size(r, 1) or_return
	drop_empty_attributes(r) or_return
	cbor.expect_end(r) or_return

	compute_proof(block, t, b)
	return .None
}

// Main block body: [txs, ssc, delegation, update].
@(private)
read_body :: proc(d: ^Decoder, b: ^Block) -> Error {
	r := &d.r
	enforce_size(r, 4) or_return
	read_tx_payload(d) or_return
	drop_ssc_payload(r) or_return
	s := r.pos
	read_delegation_payload(d) or_return
	b.dlg_payload = span_from(d, s)
	s = r.pos
	read_update_payload(d) or_return
	b.upd_payload = span_from(d, s)
	return .None
}

// EBB body and extra body data: an indefinite list of byte strings (any
// length), then [attributes], unordered.
@(private)
drop_ebb_body :: proc "contextless" (r: ^cbor.Reader) -> Error {
	c := read_list(r) or_return
	for cbor.more(r, &c) {
		_ = cbor.read_bytes(r) or_return
	}
	enforce_size(r, 1) or_return
	return drop_attributes(r)
}

// Whether the header's body proof matches the body.
proof_matches :: proc "contextless" (b: ^Block) -> bool {
	return b.proof == b.main.proof
}

// `recoverTxProof`, plus the delegation and update payload hashes
// (byron/Block/Validation.hs validateHeaderMatchesBody).
@(private)
compute_proof :: proc(block: []u8, t: ^Tables, b: ^Block) {
	b.proof.tx_count = u32(len(t.txs))

	// Merkle leaves: Blake2b-256 of 0x00 ‖ tx.
	for &tx in t.txs {
		s: ccrypto.Blake2b_256
		ccrypto.blake2b_256_init(&s)
		zero := [1]u8{0x00}
		ccrypto.blake2b_256_update(&s, zero[:])
		ccrypto.blake2b_256_update(&s, base.span_bytes(block, tx.body))
		append(&t.leaves, ccrypto.blake2b_256_final(&s))
	}
	b.proof.merkle_root = merkle_root(t.leaves[:])

	s: ccrypto.Blake2b_256
	ccrypto.blake2b_256_init(&s)
	open := [1]u8{0x9f}
	ccrypto.blake2b_256_update(&s, open[:])
	for &tx in t.txs {
		ccrypto.blake2b_256_update(&s, base.span_bytes(block, tx.witness_list))
	}
	close := [1]u8{cbor.BREAK}
	ccrypto.blake2b_256_update(&s, close[:])
	b.proof.witnesses_hash = ccrypto.blake2b_256_final(&s)

	b.proof.dlg_hash = ccrypto.blake2b_256(base.span_bytes(block, b.dlg_payload))
	b.proof.upd_hash = ccrypto.blake2b_256(base.span_bytes(block, b.upd_payload))
}

// `mtRoot . mkMerkleTreeDecoded` (byron/Common/Merkle.hs): the empty tree's
// root is Blake2b-256 of nothing; otherwise the leaves split at the largest
// power of two below their count (half of it when it is a power of two), and
// a branch is Blake2b-256 of 0x01 ‖ left ‖ right.
merkle_root :: proc "contextless" (leaves: []base.Hash32) -> base.Hash32 {
	if len(leaves) == 0 {
		return ccrypto.blake2b_256(nil)
	}
	return merkle_node(leaves)
}

@(private = "file")
merkle_node :: proc "contextless" (xs: []base.Hash32) -> base.Hash32 {
	n := len(xs)
	if n == 1 {
		return xs[0]
	}
	i := n >> 1 if n & (n - 1) == 0 else 1 << uint(bits.len(uint(n)) - 1)
	l := merkle_node(xs[:i])
	r := merkle_node(xs[i:])
	s: ccrypto.Blake2b_256
	ccrypto.blake2b_256_init(&s)
	one := [1]u8{0x01}
	ccrypto.blake2b_256_update(&s, one[:])
	ccrypto.blake2b_256_update(&s, l[:])
	ccrypto.blake2b_256_update(&s, r[:])
	return ccrypto.blake2b_256_final(&s)
}

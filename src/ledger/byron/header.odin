// Package byron decodes and validates Byron-era blocks (main blocks and epoch
// boundary blocks).
package byron

import "urd:base"
import "urd:cbor"
import "urd:ccrypto"

// The parts of a Byron header needed to place it on the chain.
Header_Info :: struct {
	hash:     base.Block_Hash,
	prev:     base.Block_Hash,
	slot:     base.Slot,
	epoch:    u64,
	// Byron's "difficulty" is the chain length: the block number. An EBB has
	// the same difficulty as the block before it.
	block_no: u64,
	is_ebb:   bool,
}

// The header hash is Blake2b-256 over the header bytes prefixed with the
// encoding of the block's `[0/1, ...]` sum tag (wrapBoundaryBytes /
// wrapHeaderBytes in cardano-ledger byron's Block/Header.hs).
header_hash :: proc "contextless" (header: []u8, is_ebb: bool) -> base.Block_Hash {
	s: ccrypto.Blake2b_256
	ccrypto.blake2b_256_init(&s)
	prefix := [2]u8{0x82, 0x00 if is_ebb else 0x01}
	ccrypto.blake2b_256_update(&s, prefix[:])
	ccrypto.blake2b_256_update(&s, header)
	return base.Block_Hash(ccrypto.blake2b_256_final(&s))
}

// `Proof`: what a main header commits to about its body.
Body_Proof :: struct {
	// `txpNumber`: the number of transactions.
	tx_count:       u32,
	// Merkle root over the transactions as received.
	merkle_root:    base.Hash32,
	// Blake2b-256 of 0x9f ‖ each witness list as received ‖ 0xff.
	witnesses_hash: base.Hash32,
	// Blake2b-256 of the delegation and update payloads as received.
	dlg_hash:       base.Hash32,
	upd_hash:       base.Hash32,
}

// A main-block header (`AHeader`, docs B.2.1). Spans are relative to the
// header's own bytes (the 5-array chain-sync delivers and the hash covers).
Header :: struct {
	// Compared to the configured magic by a rule, not at decode time.
	protocol_magic:   u32,
	prev:             base.Block_Hash,
	proof:            Body_Proof,
	epoch:            u64,
	// The slot within the epoch, not bounded by the epoch length.
	slot_in_epoch:    u64,
	// `toSlotNumber`: epoch * epoch_slots + slot_in_epoch (Word64, wrapping).
	slot:             base.Slot,
	// The genesis key the block is issued under (consensus data).
	issuer:           Vkey,
	// The chain length.
	difficulty:       u64,
	// The block signature: a heavyweight delegation certificate from the
	// genesis key to the signing key, and the signature.
	cert:             Delegation_Cert,
	signature:        Signature,
	protocol_version: Protocol_Version,
	software_version: Software_Version,
	// What the block signature covers (`recoverSignedBytes`):
	// 0x85 ‖ prev ‖ proof ‖ slot ‖ difficulty ‖ extra.
	prev_raw:         base.Span,
	proof_raw:        base.Span,
	slot_raw:         base.Span,
	difficulty_raw:   base.Span,
	extra_raw:        base.Span,
}

// An epoch boundary block header (`ABoundaryHeader`, docs B.2.2). Its
// protocol magic and body proof are dropped unchecked.
Ebb_Header :: struct {
	prev:            base.Block_Hash,
	// Epoch 0, or the "Genesis" attribute: `prev` is the genesis hash rather
	// than a header hash.
	prev_is_genesis: bool,
	epoch:           u64,
	difficulty:      u64,
}

// Decodes a main-block header that is exactly the bytes `header`.
// `epoch_slots` is the number of slots per epoch (10k).
decode_header :: proc "contextless" (header: []u8, epoch_slots: u64) -> (h: Header, err: Error) {
	d := Decoder {
		r    = cbor.reader(header),
		base = header,
	}
	h = read_header(&d, epoch_slots) or_return
	cbor.expect_end(&d.r) or_return
	return h, .None
}

// Decodes an EBB header that is exactly the bytes `header`.
decode_ebb_header :: proc "contextless" (header: []u8) -> (h: Ebb_Header, err: Error) {
	r := cbor.reader(header)
	h = read_ebb_header(&r) or_return
	cbor.expect_end(&r) or_return
	return h, .None
}

// `decCBORAHeader`: [magic, prev, proof, consensus, extra].
@(private)
read_header :: proc "contextless" (d: ^Decoder, epoch_slots: u64) -> (h: Header, err: Error) {
	r := &d.r
	enforce_size(r, 5) or_return
	h.protocol_magic = cbor.read_u32(r) or_return

	s := r.pos
	h.prev = base.Block_Hash(cbor.read_hash32(r) or_return)
	h.prev_raw = span_from(d, s)

	s = r.pos
	h.proof = read_body_proof(r) or_return
	h.proof_raw = span_from(d, s)

	// ConsensusData: [[epoch, slot], genesis key, [difficulty], signature].
	enforce_size(r, 4) or_return
	s = r.pos
	enforce_size(r, 2) or_return
	h.epoch = cbor.read_uint(r) or_return
	h.slot_in_epoch = cbor.read_uint(r) or_return
	h.slot_raw = span_from(d, s)
	h.slot = base.Slot(h.epoch * epoch_slots + h.slot_in_epoch)
	h.issuer = read_vkey(r) or_return
	s = r.pos
	enforce_size(r, 1) or_return
	h.difficulty = cbor.read_uint(r) or_return
	h.difficulty_raw = span_from(d, s)

	h.cert, h.signature = read_block_signature(d) or_return

	// Extra data: [protocol version, software version, {}, extra proof]. The
	// extra proof is any byte string, never checked.
	s = r.pos
	enforce_size(r, 4) or_return
	h.protocol_version = read_protocol_version(r) or_return
	h.software_version = read_software_version(d) or_return
	drop_empty_attributes(r) or_return
	_ = cbor.read_bytes(r) or_return
	h.extra_raw = span_from(d, s)
	return h, .None
}

// `BlockSignature`: [2, [certificate, signature]]. Tags 0 and 1 (plain and
// lightweight-delegation signatures) no longer decode.
@(private)
read_block_signature :: proc "contextless" (d: ^Decoder) -> (cert: Delegation_Cert, sig: Signature, err: Error) {
	r := &d.r
	enforce_size(r, 2) or_return
	tag := cbor.read_u8(r) or_return
	if tag != 2 {
		return cert, sig, .Invalid_Value
	}
	enforce_size(r, 2) or_return
	cert = read_delegation_cert(d) or_return
	sig = read_signature(r) or_return
	return cert, sig, .None
}

// `Proof`: [[count, merkle root, witnesses hash], ssc proof, dlg, upd].
@(private)
read_body_proof :: proc "contextless" (r: ^cbor.Reader) -> (p: Body_Proof, err: Error) {
	enforce_size(r, 4) or_return
	enforce_size(r, 3) or_return
	p.tx_count = cbor.read_u32(r) or_return
	p.merkle_root = cbor.read_hash32(r) or_return
	p.witnesses_hash = cbor.read_hash32(r) or_return
	drop_ssc_proof(r) or_return
	p.dlg_hash = cbor.read_hash32(r) or_return
	p.upd_hash = cbor.read_hash32(r) or_return
	return p, .None
}

// `decCBORABoundaryHeader`: [magic, prev, proof, [epoch, [difficulty]],
// [attributes]].
@(private)
read_ebb_header :: proc "contextless" (r: ^cbor.Reader) -> (h: Ebb_Header, err: Error) {
	enforce_size(r, 5) or_return
	// dropInt32.
	magic := cbor.read_int(r) or_return
	if magic < i64(min(i32)) || magic > i64(max(i32)) {
		return h, .Overflow
	}
	h.prev = base.Block_Hash(cbor.read_hash32(r) or_return)
	_ = cbor.read_bytes(r) or_return

	enforce_size(r, 2) or_return
	h.epoch = cbor.read_uint(r) or_return
	enforce_size(r, 1) or_return
	h.difficulty = cbor.read_uint(r) or_return

	// dropBoundaryExtraHeaderDataRetainGenesisTag: canonical attributes,
	// looking for 255 => "Genesis".
	enforce_size(r, 1) or_return
	n := read_map_definite(r) or_return
	prev := -1
	genesis := false
	for _ in 0 ..< n {
		key, value := read_attribute(r, &prev) or_return
		if key == 255 && string(value) == "Genesis" {
			genesis = true
		}
	}
	h.prev_is_genesis = h.epoch == 0 || genesis
	return h, .None
}

// Decodes a main-block (`is_ebb = false`) or EBB header and extracts its
// chain position.
decode_header_info :: proc "contextless" (
	header: []u8,
	is_ebb: bool,
	epoch_slots: u64,
) -> (
	info: Header_Info,
	err: cbor.Error,
) {
	if is_ebb {
		h := decode_ebb_header(header) or_return
		info.prev = h.prev
		info.epoch = h.epoch
		info.block_no = h.difficulty
		info.slot = base.Slot(h.epoch * epoch_slots)
	} else {
		h := decode_header(header, epoch_slots) or_return
		info.prev = h.prev
		info.epoch = h.epoch
		info.block_no = h.difficulty
		info.slot = h.slot
	}
	info.is_ebb = is_ebb
	info.hash = header_hash(header, is_ebb)
	return info, .None
}

// Splits a Byron block (the EBB or main block array) into its header bytes.
block_header :: proc(block: []u8) -> (header: []u8, err: cbor.Error) {
	r := cbor.reader(block)
	_ = cbor.read_array_len(&r, 3) or_return
	return cbor.span(&r)
}

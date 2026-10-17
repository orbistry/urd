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

// Extracts the chain position of a main-block header (`is_ebb = false`) or an
// EBB header. `epoch_slots` is the number of slots per Byron epoch (10k).
//
// Main header: [magic, prev, body_proof, [[epoch, slot], issuer, [difficulty], sig], extra]
// EBB header:  [magic, prev, body_proof, [epoch, [difficulty]], extra]
decode_header_info :: proc(header: []u8, is_ebb: bool, epoch_slots: u64) -> (info: Header_Info, err: cbor.Error) {
	r := cbor.reader(header)
	_ = cbor.read_array_len(&r, 5) or_return
	_ = cbor.read_u32(&r) or_return
	info.prev = base.Block_Hash(cbor.read_hash32(&r) or_return)
	cbor.skip(&r) or_return

	if is_ebb {
		_ = cbor.read_array_len(&r, 2) or_return
		info.epoch = cbor.read_uint(&r) or_return
		_ = cbor.read_array_len(&r, 1) or_return
		info.block_no = cbor.read_uint(&r) or_return
		info.slot = base.Slot(info.epoch * epoch_slots)
	} else {
		_ = cbor.read_array_len(&r, 4) or_return
		_ = cbor.read_array_len(&r, 2) or_return
		info.epoch = cbor.read_uint(&r) or_return
		slot_in_epoch := cbor.read_uint(&r) or_return
		cbor.skip(&r) or_return
		_ = cbor.read_array_len(&r, 1) or_return
		info.block_no = cbor.read_uint(&r) or_return
		info.slot = base.Slot(info.epoch * epoch_slots + slot_in_epoch)
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

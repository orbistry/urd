package ledger

import "urd:base"
import "urd:cbor"
import "urd:ledger/byron"

// Where a block sits on the chain, for any era.
Block_Info :: struct {
	point:    base.Point,
	// Hash of the previous block; for the first block, the genesis hash
	// (Byron) or `has_prev = false` (a chain starting in Shelley).
	prev:     base.Block_Hash,
	has_prev: bool,
	block_no: u64,
	era:      base.Era,
	is_ebb:   bool,
	// The header bytes (Byron: without the hash prefix).
	header:   []u8,
}

// Slots per Byron epoch (10k) on mainnet and preprod. Preview has no Byron
// blocks.
BYRON_EPOCH_SLOTS :: 21600

// Decodes a chain-sync (node-to-node) header: the hard-fork combinator's
// `[era_index, payload]`, where Byron's payload is `[[0/1, size], #6.24(bytes)]`
// and every later era's is `#6.24(bytes)`.
decode_wrapped_header :: proc(
	wrapped: []u8,
	byron_epoch_slots: u64 = BYRON_EPOCH_SLOTS,
) -> (
	info: Block_Info,
	err: cbor.Error,
) {
	r := cbor.reader(wrapped)
	cbor.expect_array_definite(&r, 2) or_return
	idx := cbor.read_uint(&r) or_return
	if idx > u64(base.Era.Dijkstra) {
		return {}, .Invalid_Value
	}
	info.era = base.Era(idx)

	if info.era == .Byron {
		cbor.expect_array_definite(&r, 2) or_return
		cbor.expect_array_definite(&r, 2) or_return
		kind := cbor.read_uint(&r) or_return
		_ = cbor.read_u32(&r) or_return
		if kind > 1 {
			return {}, .Invalid_Value
		}
		info.is_ebb = kind == 0
		info.header = cbor.read_embedded(&r) or_return
		cbor.expect_end(&r) or_return
		b := byron.decode_header_info(info.header, info.is_ebb, byron_epoch_slots) or_return
		info.point = base.Point {
			slot = b.slot,
			hash = b.hash,
		}
		info.block_no = b.block_no
		info.prev, info.has_prev = b.prev, true
		return info, .None
	}

	info.header = cbor.read_embedded(&r) or_return
	cbor.expect_end(&r) or_return
	hr := cbor.reader(info.header)
	h: Header
	decode_header(&hr, info.era, &h) or_return
	cbor.expect_end(&hr) or_return
	info.point = base.Point {
		slot = base.Slot(h.slot),
		hash = h.hash,
	}
	info.block_no = h.block_no
	info.prev, info.has_prev = h.prev, h.has_prev
	return info, .None
}

// Block_Info of a hard-fork wrapped block, as stored in the ImmutableDB and
// carried by block-fetch. Also returns the header's offset in `raw`.
decode_block_info :: proc(
	raw: []u8,
	byron_epoch_slots: u64 = BYRON_EPOCH_SLOTS,
) -> (
	info: Block_Info,
	header_offset: int,
	err: cbor.Error,
) {
	env := decode_envelope(raw) or_return
	info.era = env.era
	if env.era == .Byron {
		info.is_ebb = env.tag == .Byron_Ebb
		info.header = byron.block_header(env.block) or_return
		b := byron.decode_header_info(info.header, info.is_ebb, byron_epoch_slots) or_return
		info.point = base.Point {
			slot = b.slot,
			hash = b.hash,
		}
		info.block_no = b.block_no
		info.prev, info.has_prev = b.prev, true
	} else {
		r := cbor.reader(env.block)
		_ = cbor.read_array(&r) or_return
		start := r.pos
		h: Header
		decode_header(&r, env.era, &h) or_return
		info.header = env.block[start:r.pos]
		info.point = base.Point {
			slot = base.Slot(h.slot),
			hash = h.hash,
		}
		info.block_no = h.block_no
		info.prev, info.has_prev = h.prev, h.has_prev
	}
	header_offset = int(uintptr(raw_data(info.header)) - uintptr(raw_data(raw)))
	return info, header_offset, .None
}

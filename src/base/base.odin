// Package base holds the small value types shared by every other package:
// fixed-size hashes, chain coordinates, eras, and byte spans.
package base

Hash28 :: [28]u8
Hash32 :: [32]u8

Block_Hash  :: distinct Hash32
Tx_Id       :: distinct Hash32
Key_Hash    :: distinct Hash28
Script_Hash :: distinct Hash28

Slot     :: distinct u64
Epoch    :: distinct u64
Block_No :: distinct u64

// Ledger eras in hard-fork order. The numeric values are the era indices used
// by the hard-fork combinator (Byron = 0), e.g. in the chain-sync header
// wrapper. The block wrapper uses different tags: Byron blocks are tagged
// 0 (EBB) or 1 (main), and later eras are tagged with their index + 1.
Era :: enum u8 {
	Byron,
	Shelley,
	Allegra,
	Mary,
	Alonzo,
	Babbage,
	Conway,
	Dijkstra,
}

// A point on the chain. Origin is represented by ORIGIN_SLOT, which no real
// block can have (slot 0 is valid: it holds the genesis EBB).
Point :: struct {
	slot: Slot,
	hash: Block_Hash,
}

ORIGIN_SLOT :: Slot(max(u64))
ORIGIN :: Point{slot = ORIGIN_SLOT}

point_is_origin :: #force_inline proc "contextless" (p: Point) -> bool {
	return p.slot == ORIGIN_SLOT
}

// A byte range inside some owning buffer (usually a block's raw bytes).
// Eight bytes instead of a sixteen-byte slice, and stable if the buffer moves.
Span :: struct {
	off: u32,
	len: u32,
}

span_bytes :: #force_inline proc "contextless" (buf: []u8, s: Span) -> []u8 {
	return buf[s.off:][:s.len]
}

// Span of `sub` within `buf`. `sub` must be a subslice of `buf`.
span_of :: #force_inline proc "contextless" (buf, sub: []u8) -> Span {
	off := uintptr(raw_data(sub)) - uintptr(raw_data(buf))
	return Span{off = u32(off), len = u32(len(sub))}
}

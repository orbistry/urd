package byron

import "core:math"

import "urd:base"

// Permissive BFT (ouroboros-consensus Protocol/PBFT.hs, PBFT/State.hs;
// docs/rules/byron-chain.md §3) and the header envelope (HeaderValidation.hs,
// Byron/Ledger/HeaderValidation.hs; §4).

// The signature-window threshold most networks run with (the node
// configuration's PBftSignatureThreshold default).
PBFT_DEFAULT_THRESHOLD :: 0.22

Pbft_Error :: enum u8 {
	None,
	Invalid_Signature,
	// Slot before the last signed block's.
	Invalid_Slot,
	// The block's delegate key is no genesis key's current delegate.
	Not_Genesis_Delegate,
	// The genesis key signed more than the threshold of the last k blocks.
	Exceeded_Threshold,
}

// The genesis keys of the last k signed (main) blocks, as indices into the
// genesis key table, with a count per key. EBBs never enter it.
Pbft_State :: struct {
	ring:             []u8,
	head:             int,
	len:              int,
	counts:           []u32,
	last_signed_slot: base.Slot,
	has_signed:       bool,
	// floor(t * k), computed in f64 as the node does.
	threshold:        u64,
}

pbft_threshold :: proc "contextless" (t: f64, k: u64) -> u64 {
	return u64(math.floor(t * f64(k)))
}

pbft_init :: proc(
	s: ^Pbft_State,
	k: u64,
	genesis_keys: int,
	t: f64 = PBFT_DEFAULT_THRESHOLD,
	allocator := context.allocator,
) {
	assert(genesis_keys <= 256)
	s^ = {}
	s.ring = make([]u8, k, allocator)
	s.counts = make([]u32, genesis_keys, allocator)
	s.threshold = pbft_threshold(t, k)
}

pbft_destroy :: proc(s: ^Pbft_State, allocator := context.allocator) {
	delete(s.ring, allocator)
	delete(s.counts, allocator)
}

// `updateChainDepState` for a main block whose signature has been checked:
// the slot rule, the delegate lookup and the window threshold. `delegator` is
// the genesis key index whose current delegate signed (-1 if none). Changes
// nothing; `pbft_commit` records the block once it is accepted.
pbft_check :: proc "contextless" (s: ^Pbft_State, slot: base.Slot, delegator: int) -> Pbft_Error {
	if s.has_signed && slot < s.last_signed_slot {
		return .Invalid_Slot
	}
	if delegator < 0 {
		return .Not_Genesis_Delegate
	}
	// `append k` drops the oldest entry when the window is full; the count
	// includes the new block.
	count := u64(s.counts[delegator]) + 1
	if s.len == len(s.ring) && int(s.ring[s.head]) == delegator {
		count -= 1
	}
	if count > s.threshold {
		return .Exceeded_Threshold
	}
	return .None
}

pbft_commit :: proc "contextless" (s: ^Pbft_State, slot: base.Slot, delegator: int) {
	k := len(s.ring)
	if s.len == k {
		s.counts[s.ring[s.head]] -= 1
		s.ring[s.head] = u8(delegator)
		s.head = (s.head + 1) % k
	} else {
		s.ring[(s.head + s.len) % k] = u8(delegator)
		s.len += 1
	}
	s.counts[delegator] += 1
	s.last_signed_slot = slot
	s.has_signed = true
}

// ---------------------------------------------------------------------------
// Envelope

Envelope_Error :: enum u8 {
	None,
	Unexpected_Block_No,
	Unexpected_Slot,
	Unexpected_Prev_Hash,
	// An EBB whose slot is not an epoch's first (only through wrap-around).
	Ebb_Slot,
}

// The tip the envelope checks a new header against.
Tip :: struct {
	slot:     base.Slot,
	block_no: u64,
	hash:     base.Block_Hash,
	is_ebb:   bool,
	// No block yet.
	origin:   bool,
}

// `validateEnvelope` with Byron's `BasicEnvelopeValidation`: block numbers
// (an EBB repeats its predecessor's), slots (strictly increasing, except
// that a main block may share its EBB's slot) and previous hashes (a chain
// starts with an EBB whose previous hash is the genesis).
check_envelope :: proc "contextless" (
	tip: ^Tip,
	is_ebb: bool,
	slot: base.Slot,
	block_no: u64,
	prev: base.Block_Hash,
	prev_is_genesis: bool,
	epoch_slots: u64,
) -> Envelope_Error {
	expected_no: u64 = 0
	min_slot: base.Slot = 0
	if !tip.origin {
		expected_no = tip.block_no if is_ebb && !tip.is_ebb else tip.block_no + 1
		min_slot = tip.slot if tip.is_ebb && !is_ebb else tip.slot + 1
		// `succ` on maxBound throws in Haskell: treat it as a rejection.
		if tip.block_no == max(u64) && expected_no == 0 do return .Unexpected_Block_No
		if tip.slot == base.Slot(max(u64)) && min_slot == 0 do return .Unexpected_Slot
	}
	if block_no != expected_no {
		return .Unexpected_Block_No
	}
	if slot < min_slot {
		return .Unexpected_Slot
	}
	if tip.origin {
		if !prev_is_genesis do return .Unexpected_Prev_Hash
	} else if prev_is_genesis || prev != tip.hash {
		return .Unexpected_Prev_Hash
	}
	if is_ebb && u64(slot) % epoch_slots != 0 {
		return .Ebb_Slot
	}
	return .None
}

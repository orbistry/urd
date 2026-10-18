package byron

import "urd:base"

// Byron chain validation as cardano-node runs it (docs/rules/byron-chain.md):
// the ledger tick (`applyChainTick`), `validateBlock` / `validateBoundary`,
// the consensus envelope and PBFT. A block is checked against scratch copies
// of the small states and an overlay of the UTxO; nothing changes unless the
// whole block is valid.

Chain_Error_Kind :: enum u8 {
	None,
	Envelope,
	// A main header longer than the adopted maxHeaderSize.
	Header_Too_Large,
	// A main block longer than the adopted maxBlockSize.
	Block_Too_Large,
	// An EBB longer than 2,000,000 bytes.
	Boundary_Too_Large,
	// An EBB's previous hash does not match (genesis or header hash).
	Boundary_Prev_Hash,
	// A body proof does not match the body.
	Proof,
	Delegation,
	Utxo,
	Update,
	Pbft,
	// A main header whose protocol magic differs from the configuration's.
	// cardano-node does not check it while validating, but its integrity
	// check rejects the block once it becomes immutable, so urd rejects it
	// at once (docs/rules/byron-chain.md open question 1).
	Protocol_Magic,
}

Chain_Error :: struct {
	kind:       Chain_Error_Kind,
	envelope:   Envelope_Error,
	delegation: Delegation_Error,
	utxo:       Utxo_Error,
	update:     Update_Error,
	pbft:       Pbft_Error,
	// The failing transaction, for Utxo.
	tx:         int,
}

// The largest EBB `updateChainBoundary` accepts.
MAX_BOUNDARY_SIZE :: 2_000_000

// The configuration and state of a Byron chain.
Chain :: struct {
	genesis_hash:    base.Hash32,
	protocol_magic:  u32,
	requires_magic:  bool,
	k:               u64,
	epoch_slots:     u64,

	// `ChainValidationState`.
	last_slot:       u64,
	// `cvsPreviousHash`: the genesis hash until the first block.
	prev_hash:       base.Block_Hash,
	prev_genesis:    bool,
	utxo:            Utxo,
	delegation:      Delegation_State,
	update:          Update_State,
	// Magnitudes of bignum protocol parameters, which update states refer to
	// by span. Append-only; only genesis delegates' proposals add to it.
	bignums:         [dynamic]u8,

	// Header state: the envelope's tip and PBFT.
	tip:             Tip,
	pbft:            Pbft_State,

	// Scratch, reused per block.
	next_delegation: Delegation_State,
	next_update:     Update_State,
	overlay:         Utxo_Overlay,
}

// The initial chain state (`initialChainValidationState` and the consensus
// genesis state). `requires_magic` is the network's RequiresNetworkMagic and
// `threshold` its PBftSignatureThreshold.
chain_init :: proc(
	c: ^Chain,
	g: ^Genesis,
	requires_magic: bool,
	threshold: f64 = PBFT_DEFAULT_THRESHOLD,
	allocator := context.allocator,
) -> Delegation_Error {
	context.allocator = allocator
	c^ = {}
	c.genesis_hash = g.hash
	c.protocol_magic = g.protocol_magic
	c.requires_magic = requires_magic
	c.k = g.k
	c.epoch_slots = epoch_slots(g)
	c.prev_hash = base.Block_Hash(g.hash)
	c.prev_genesis = true
	utxo_init(&c.utxo)
	genesis_utxo(g, requires_magic, &c.utxo)
	delegation_init(&c.delegation, g) or_return
	update_init(&c.update, g)
	c.tip = Tip {
		origin = true,
	}
	pbft_init(&c.pbft, g.k, len(g.genesis_keys), threshold)

	c.next_delegation = Delegation_State {
		delegates  = make([]base.Key_Hash, len(g.genesis_keys)),
		activated  = make([]u64, len(g.genesis_keys)),
		scheduled  = make([dynamic]Scheduled_Delegation),
		key_epochs = make([dynamic]Key_Epoch),
	}
	update_init(&c.next_update, g)
	c.bignums = make([dynamic]u8)
	utxo_overlay_init(&c.overlay)
	return .None
}

chain_destroy :: proc(c: ^Chain, allocator := context.allocator) {
	context.allocator = allocator
	utxo_destroy(&c.utxo)
	delegation_destroy(&c.delegation)
	delete(c.next_delegation.delegates)
	delete(c.next_delegation.activated)
	delete(c.next_delegation.scheduled)
	delete(c.next_delegation.key_epochs)
	update_destroy(&c.update)
	update_destroy(&c.next_update)
	pbft_destroy(&c.pbft)
	delete(c.bignums)
	utxo_overlay_destroy(&c.overlay)
}

// `applyChainTick` to `slot`, on the scratch states: the update system's
// epoch transition when `slot` opens a later epoch than the last block's,
// then delegation activation.
@(private = "file")
tick :: proc(c: ^Chain, slot: u64) {
	delegation_copy(&c.next_delegation, &c.delegation)
	update_copy(&c.next_update, &c.update)
	epoch := slot / c.epoch_slots
	if epoch > c.last_slot / c.epoch_slots {
		update_epoch_transition(&c.next_update, c.k, epoch, c.epoch_slots)
	}
	delegation_tick(&c.next_delegation, epoch, slot)
}

@(private = "file")
commit :: proc(c: ^Chain) {
	c.delegation, c.next_delegation = c.next_delegation, c.delegation
	c.update, c.next_update = c.next_update, c.update
}

// Validates a decoded block (`decode_block` into `t`) and applies it. On
// failure the chain is unchanged.
chain_apply :: proc(c: ^Chain, block: []u8, b: ^Block, t: ^Tables) -> (err: Chain_Error) {
	if b.is_ebb {
		return apply_boundary(c, block, b)
	}
	mark := len(c.bignums)
	defer if err.kind != .None {
		resize(&c.bignums, mark)
	}
	h := &b.main
	slot := u64(h.slot)
	epoch := slot / c.epoch_slots
	tick(c, slot)

	// Envelope.
	if e := check_envelope(&c.tip, false, h.slot, h.difficulty, h.prev, false, c.epoch_slots); e != .None {
		return {kind = .Envelope, envelope = e}
	}
	if h.protocol_magic != c.protocol_magic {
		return {kind = .Protocol_Magic}
	}

	// validateBlock, against the ticked state.
	params := &c.next_update.params
	if !natural_le_u64(&params.max_header_size, u64(b.header.len), c.bignums[:]) {
		return {kind = .Header_Too_Large}
	}
	if !natural_le_u64(&params.max_block_size, u64(b.size), c.bignums[:]) {
		return {kind = .Block_Too_Large}
	}
	if !proof_matches(b) {
		return {kind = .Proof}
	}
	// Body certificates are scheduled 2k slots ahead, so the delegation map
	// the update system and PBFT see is the ticked one either way.
	if e := delegation_apply_certs(&c.next_delegation, t.certs[:], block, c.protocol_magic, epoch, slot, c.k);
	   e != .None {
		return {kind = .Delegation, delegation = e}
	}
	delegate := vkey_hash(&h.cert.delegate)
	uenv := Update_Env {
		k              = c.k,
		protocol_magic = c.protocol_magic,
		slot           = slot,
		delegation     = &c.next_delegation,
		pool           = &c.bignums,
	}
	if e := update_register(&c.next_update, &uenv, t, block, h.protocol_version, delegate); e != .None {
		return {kind = .Update, update = e}
	}

	// PBFT, against the ticked delegation map.
	if !verify_block_signature(h, base.span_bytes(block, b.header), c.protocol_magic) {
		return {kind = .Pbft, pbft = .Invalid_Signature}
	}
	delegator := delegator_of(&c.next_delegation, delegate)
	if e := pbft_check(&c.pbft, h.slot, delegator); e != .None {
		return {kind = .Pbft, pbft = e}
	}

	// The transactions last: on success they are committed to the UTxO.
	env := Utxo_Env {
		protocol_magic = c.protocol_magic,
		requires_magic = c.requires_magic,
		max_tx_size    = params.max_tx_size,
		fee_policy     = params.tx_fee_policy,
		pool           = c.bignums[:],
	}
	if e, failed := utxo_apply_block(&env, &c.utxo, &c.overlay, t, block); e != .None {
		return {kind = .Utxo, utxo = e, tx = failed}
	}

	// Everything passed: commit.
	pbft_commit(&c.pbft, h.slot, delegator)
	update_transition_info(&c.next_update, h.difficulty)
	commit(c)
	c.last_slot = slot
	c.prev_hash = b.hash
	c.prev_genesis = false
	c.tip = Tip {
		slot     = h.slot,
		block_no = h.difficulty,
		hash     = b.hash,
	}
	return {}
}

// `validateBoundary`: the previous hash (genesis or header), the 2 MB limit,
// then the EBB's slot becomes the last slot. PBFT ignores EBBs.
@(private = "file")
apply_boundary :: proc(c: ^Chain, block: []u8, b: ^Block) -> (err: Chain_Error) {
	e := &b.ebb
	slot := e.epoch * c.epoch_slots
	tick(c, slot)
	if ee := check_envelope(&c.tip, true, base.Slot(slot), e.difficulty, e.prev, e.prev_is_genesis, c.epoch_slots);
	   ee != .None {
		return {kind = .Envelope, envelope = ee}
	}
	if c.prev_genesis != e.prev_is_genesis || e.prev != c.prev_hash {
		return {kind = .Boundary_Prev_Hash}
	}
	if b.size > MAX_BOUNDARY_SIZE {
		return {kind = .Boundary_Too_Large}
	}
	commit(c)
	c.last_slot = slot
	c.prev_hash = b.hash
	c.prev_genesis = false
	c.tip = Tip {
		slot     = base.Slot(slot),
		block_no = e.difficulty,
		hash     = b.hash,
		is_ebb   = true,
	}
	return {}
}

// The first epoch of Shelley, once the chain knows it (the hard-fork
// combinator's `TriggerHardForkAtVersion 2`).
chain_transition_epoch :: proc "contextless" (c: ^Chain) -> (epoch: u64, ok: bool) {
	if c.tip.origin {
		return 0, false
	}
	return update_transition_epoch(&c.update, 2, c.last_slot, c.tip.block_no, c.k, c.epoch_slots)
}

package byron

import "core:slice"

import "urd:base"

// Heavyweight delegation (byron/Delegation/Validation/{Scheduling,
// Activation,Interface}.hs; docs/rules/byron-chain.md §6.2).
//
// The delegation map's domain is always exactly the genesis keys (it starts
// as the identity, and only genesis keys may delegate), so it is an array
// indexed like `genesis_keys`. It is one to one: a key delegates for at most
// one genesis key.

Delegation_Error :: enum u8 {
	None,
	// The certificate's issuer is not a genesis key.
	Non_Genesis_Delegator,
	// The certificate's epoch is neither the current nor the next one.
	Wrong_Epoch,
	// The issuer already delegated for that epoch.
	Multiple_Delegations_For_Epoch,
	// The issuer already has a delegation scheduled for the same slot.
	Multiple_Delegations_For_Slot,
	Invalid_Certificate,
}

Scheduled_Delegation :: struct {
	slot:      u64,
	delegator: u8,
	delegate:  base.Key_Hash,
}

Key_Epoch :: struct {
	epoch:     u64,
	delegator: u8,
}

Delegation_State :: struct {
	genesis_keys: []base.Key_Hash,
	// Activation state: each genesis key's current delegate, and the slot of
	// its last activation (`delegationSlots`).
	delegates:    []base.Key_Hash,
	activated:    []u64,
	// Scheduling state: pending delegations in certificate order, and the
	// (epoch, delegator) pairs already used.
	scheduled:    [dynamic]Scheduled_Delegation,
	key_epochs:   [dynamic]Key_Epoch,
}

// `initialState`: every genesis key delegates to itself, then the genesis
// certificates are scheduled with k = 0 at epoch 0, slot 0 (in the order of
// their issuers' key hashes, as `M.elems` yields them) and activated at once.
delegation_init :: proc(s: ^Delegation_State, g: ^Genesis, allocator := context.allocator) -> Delegation_Error {
	n := len(g.genesis_keys)
	assert(n <= 256)
	s.genesis_keys = slice.clone(g.genesis_keys, allocator)
	s.delegates = slice.clone(g.genesis_keys, allocator)
	s.activated = make([]u64, n, allocator)
	s.scheduled = make([dynamic]Scheduled_Delegation, allocator)
	s.key_epochs = make([dynamic]Key_Epoch, allocator)

	Entry :: struct {
		issuer: base.Key_Hash,
		cert:   ^Genesis_Delegation,
	}
	entries := make([]Entry, len(g.delegations), context.temp_allocator)
	for &c, i in g.delegations {
		entries[i] = Entry{vkey_hash(&c.issuer), &c}
	}
	slice.sort_by(entries, proc(a, b: Entry) -> bool {
		a, b := a, b
		return string(a.issuer[:]) < string(b.issuer[:])
	})
	for e in entries {
		i, activation := schedule_check(s, e.issuer, e.cert.epoch, 0, 0, 0) or_return
		if !verify_genesis_delegation(e.cert, g.protocol_magic) {
			return .Invalid_Certificate
		}
		schedule_commit(s, i, activation, vkey_hash(&e.cert.delegate), e.cert.epoch)
	}
	delegation_tick(s, 0, 0)
	return .None
}

delegation_destroy :: proc(s: ^Delegation_State, allocator := context.allocator) {
	delete(s.genesis_keys, allocator)
	delete(s.delegates, allocator)
	delete(s.activated, allocator)
	delete(s.scheduled)
	delete(s.key_epochs)
}

// Copies `src` into `dst`, reusing `dst`'s memory (both share the genesis
// key table).
delegation_copy :: proc(dst, src: ^Delegation_State) {
	dst.genesis_keys = src.genesis_keys
	copy(dst.delegates, src.delegates)
	copy(dst.activated, src.activated)
	clear(&dst.scheduled)
	append(&dst.scheduled, ..src.scheduled[:])
	clear(&dst.key_epochs)
	append(&dst.key_epochs, ..src.key_epochs[:])
}

// The genesis key a key currently delegates for (`lookupR`), or -1.
delegator_of :: proc "contextless" (s: ^Delegation_State, delegate: base.Key_Hash) -> int {
	for d, i in s.delegates {
		if d == delegate do return i
	}
	return -1
}

@(private = "file")
genesis_index :: proc "contextless" (s: ^Delegation_State, key: base.Key_Hash) -> int {
	for k, i in s.genesis_keys {
		if k == key do return i
	}
	return -1
}

// `scheduleCertificate`'s checks before the signature, in its order: the
// issuer is a genesis key, the epoch is the current or the next one, and the
// issuer has neither delegated for that epoch nor scheduled a delegation for
// the same activation slot (`currentSlot + 2k`).
@(private = "file")
schedule_check :: proc "contextless" (
	s: ^Delegation_State,
	delegator: base.Key_Hash,
	cert_epoch, epoch, slot, k: u64,
) -> (
	index: int,
	activation: u64,
	err: Delegation_Error,
) {
	index = genesis_index(s, delegator)
	if index < 0 {
		return -1, 0, .Non_Genesis_Delegator
	}
	if cert_epoch < epoch || cert_epoch > epoch + 1 {
		return index, 0, .Wrong_Epoch
	}
	for ke in s.key_epochs {
		if ke.epoch == cert_epoch && int(ke.delegator) == index do return index, 0, .Multiple_Delegations_For_Epoch
	}
	activation = slot + 2 * k
	for sd in s.scheduled {
		if sd.slot == activation && int(sd.delegator) == index do return index, 0, .Multiple_Delegations_For_Slot
	}
	return index, activation, .None
}

@(private = "file")
schedule_commit :: proc(s: ^Delegation_State, index: int, activation: u64, delegate: base.Key_Hash, cert_epoch: u64) {
	append(&s.scheduled, Scheduled_Delegation{slot = activation, delegator = u8(index), delegate = delegate})
	append(&s.key_epochs, Key_Epoch{epoch = cert_epoch, delegator = u8(index)})
}

// `updateDelegation` for a block's certificates at the block's epoch and
// slot: each is scheduled 2k slots ahead, in payload order, then the state is
// ticked at the block's slot. On failure the state may be partly changed, so
// callers work on a copy (`delegation_copy`).
delegation_apply_certs :: proc(
	s: ^Delegation_State,
	certs: []Delegation_Cert,
	block: []u8,
	magic: u32,
	epoch, slot, k: u64,
) -> Delegation_Error {
	for &c in certs {
		i, activation := schedule_check(s, vkey_hash(&c.issuer), c.epoch, epoch, slot, k) or_return
		if !verify_certificate(&c, block, magic) {
			return .Invalid_Certificate
		}
		schedule_commit(s, i, activation, vkey_hash(&c.delegate), c.epoch)
	}
	delegation_tick(s, epoch, slot)
	return .None
}

// `tickDelegation`: activate, in order, the scheduled delegations due by
// `slot`, then keep only later ones and the epoch registrations from `epoch`.
delegation_tick :: proc(s: ^Delegation_State, epoch, slot: u64) {
	kept := 0
	for sd in s.scheduled {
		if sd.slot <= slot {
			activate(s, sd)
		} else {
			s.scheduled[kept] = sd
			kept += 1
		}
	}
	resize(&s.scheduled, kept)
	kept = 0
	for ke in s.key_epochs {
		if ke.epoch >= epoch {
			s.key_epochs[kept] = ke
			kept += 1
		}
	}
	resize(&s.key_epochs, kept)
}

// `activateDelegation`: only if the delegate does not already delegate for
// some genesis key, and the slot is after the delegator's last activation
// (or is slot 0).
@(private = "file")
activate :: proc "contextless" (s: ^Delegation_State, sd: Scheduled_Delegation) {
	if delegator_of(s, sd.delegate) >= 0 {
		return
	}
	i := int(sd.delegator)
	if !(s.activated[i] < sd.slot || sd.slot == 0) {
		return
	}
	s.delegates[i] = sd.delegate
	s.activated[i] = sd.slot
}

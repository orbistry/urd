package byron

import "core:math/bits"

import "urd:base"
import "urd:ccrypto"

// The Byron update system (byron/Update/Validation/{Interface,Registration,
// Voting,Endorsement}.hs; docs/rules/byron-delegation-update.md §2, §4).
//
// The ledger's PUP, SUP, vote, registration-slot and confirmation maps are all
// keyed by proposal id and pruned together, so they are one array of
// proposal entries here. Every mutation needs a genesis delegate's signature,
// so the arrays stay small; they are copied per block (see `Chain`).

Update_Error :: enum u8 {
	None,
	// Registration (registerProposal).
	Invalid_Proposer,
	Invalid_Proposal_Signature,
	Null_Update_Proposal,
	Duplicate_Protocol_Version,
	Invalid_Protocol_Version,
	Proposal_Too_Large,
	Max_Block_Size_Too_Large,
	Max_Tx_Size_Too_Large,
	Invalid_Script_Version,
	System_Tag_Too_Long,
	System_Tag_Not_Ascii,
	Duplicate_Software_Version,
	Application_Name_Too_Long,
	Application_Name_Not_Ascii,
	Invalid_Software_Version,
	// Votes (registerVote).
	Vote_Proposal_Not_Registered,
	Vote_Not_Delegate,
	Vote_Already_Cast,
	Invalid_Vote_Signature,
	// Endorsement: unreachable, since protocol versions are unique.
	Multiple_Proposals_For_Version,
}

APP_NAME_MAX :: 48 // 12 code points of at most 4 bytes

Candidate :: struct {
	// The slot of the block whose endorsement made it a candidate.
	slot:    u64,
	version: Protocol_Version,
	params:  Protocol_Parameters,
}

App_Version :: struct {
	name:     [APP_NAME_MAX]u8,
	name_len: u8,
	number:   u32,
	slot:     u64,
}

// One registered proposal: its protocol part (a PUP), its software part (a
// SUP, until confirmed), the genesis keys that voted for it, and whether and
// when it was confirmed.
Proposal_Entry :: struct {
	id:             base.Hash32,
	registered:     u64,
	// Genesis key indices.
	voters:         [4]u64,
	confirmed_slot: u64,
	confirmed:      bool,
	has_pup:        bool,
	has_sup:        bool,
	sup_name_len:   u8,
	sup_number:     u32,
	sup_name:       [APP_NAME_MAX]u8,
	pup_version:    Protocol_Version,
	pup_params:     Protocol_Parameters,
}

Endorsement :: struct {
	version: Protocol_Version,
	genesis: u8,
}

// `ByronTransitionInfo` (consensus): the block number at which each current
// candidate version became a candidate.
Transition_Entry :: struct {
	version:  Protocol_Version,
	block_no: u64,
}

Update_State :: struct {
	adopted_version: Protocol_Version,
	params:          Protocol_Parameters,
	// Highest version first.
	candidates:      [dynamic]Candidate,
	app_versions:    [dynamic]App_Version,
	proposals:       [dynamic]Proposal_Entry,
	endorsements:    [dynamic]Endorsement,
	transition:      [dynamic]Transition_Entry,
}

update_init :: proc(u: ^Update_State, g: ^Genesis, allocator := context.allocator) {
	u^ = {}
	u.params = g.params
	u.candidates = make([dynamic]Candidate, allocator)
	u.app_versions = make([dynamic]App_Version, allocator)
	u.proposals = make([dynamic]Proposal_Entry, allocator)
	u.endorsements = make([dynamic]Endorsement, allocator)
	u.transition = make([dynamic]Transition_Entry, allocator)
}

update_destroy :: proc(u: ^Update_State) {
	delete(u.candidates)
	delete(u.app_versions)
	delete(u.proposals)
	delete(u.endorsements)
	delete(u.transition)
}

update_copy :: proc(dst, src: ^Update_State) {
	dst.adopted_version = src.adopted_version
	dst.params = src.params
	copy_rows(&dst.candidates, src.candidates[:])
	copy_rows(&dst.app_versions, src.app_versions[:])
	copy_rows(&dst.proposals, src.proposals[:])
	copy_rows(&dst.endorsements, src.endorsements[:])
	copy_rows(&dst.transition, src.transition[:])
}

@(private = "file")
copy_rows :: proc(dst: ^[dynamic]$T, src: []T) {
	clear(dst)
	append(dst, ..src)
}

// The vote and endorsement threshold (`upAdptThd`): floor(minThd / 10^15 *
// genesis keys), exactly. minThd <= 10^15 and there are at most 255 keys, so
// the product fits.
@(private)
threshold :: proc "contextless" (u: ^Update_State, genesis_keys: int) -> u64 {
	return u.params.softfork_rule.min_thd * u64(genesis_keys) / LOVELACE_PORTION_DENOMINATOR
}

// `addSlotCount`: Word64 addition saturating at the top.
@(private = "file")
add_slots :: #force_inline proc "contextless" (a, b: u64) -> u64 {
	s, carry := bits.add_u64(a, b, 0)
	return max(u64) if carry != 0 else s
}

// ---------------------------------------------------------------------------
// Epoch transition: adoption

// `registerEpoch` / `tryBumpVersion`, at the tick into `epoch`: adopt the
// first candidate (the highest version) that has been stable for 4k slots
// by the epoch's first slot, unless it is already adopted. Adoption replaces
// every parameter and clears all proposals, votes, endorsements and
// candidates (not the application versions).
update_epoch_transition :: proc(u: ^Update_State, k, epoch, epoch_slots: u64) {
	first := epoch * epoch_slots
	for &c in u.candidates {
		if add_slots(c.slot, 4 * k) > first do continue
		if c.version == u.adopted_version do return
		u.adopted_version = c.version
		u.params = c.params
		clear(&u.candidates)
		clear(&u.proposals)
		clear(&u.endorsements)
		return
	}
}

// ---------------------------------------------------------------------------
// Per-block registration

// What `registerUpdate` needs from the chain.
Update_Env :: struct {
	k:              u64,
	protocol_magic: u32,
	slot:           u64,
	delegation:     ^Delegation_State,
	// Bignum magnitudes of parameters in the update state.
	pool:           ^[dynamic]u8,
}

// `registerUpdate` for a main block: its proposal, its votes (then the
// confirmed software updates), the header's endorsement, then expiry.
update_register :: proc(
	u: ^Update_State,
	env: ^Update_Env,
	t: ^Tables,
	block: []u8,
	version: Protocol_Version,
	delegate: base.Key_Hash,
) -> Update_Error {
	if len(t.proposals) > 0 {
		register_proposal(u, env, t, &t.proposals[0], block) or_return
	}
	for &v in t.votes {
		register_vote(u, env, &v, block) or_return
	}
	// Software updates take effect when their proposal is confirmed.
	for &p in u.proposals {
		if !p.has_sup || !p.confirmed do continue
		set_app_version(u, p.sup_name[:p.sup_name_len], p.sup_number, env.slot)
		p.has_sup = false
	}
	register_endorsement(u, env, version, delegate) or_return
	prune(u, env.slot)
	return .None
}

@(private)
find_app :: proc "contextless" (u: ^Update_State, name: []u8) -> int {
	for &a, i in u.app_versions {
		if string(a.name[:a.name_len]) == string(name) do return i
	}
	return -1
}

@(private)
set_app_version :: proc(u: ^Update_State, name: []u8, number: u32, slot: u64) {
	i := find_app(u, name)
	if i < 0 {
		a := App_Version {
			name_len = u8(len(name)),
		}
		copy(a.name[:], name)
		append(&u.app_versions, a)
		i = len(u.app_versions) - 1
	}
	u.app_versions[i].number = number
	u.app_versions[i].slot = slot
}

@(private)
find_proposal :: proc "contextless" (u: ^Update_State, id: base.Hash32) -> int {
	for &p, i in u.proposals {
		if p.id == id do return i
	}
	return -1
}

// `registerProposal` (Registration.hs): proposer and signature, then the
// protocol part if it changes the version or parameters, then the software
// part if it changes the application's version.
@(private)
register_proposal :: proc(u: ^Update_State, env: ^Update_Env, t: ^Tables, p: ^Proposal, block: []u8) -> Update_Error {
	if delegator_of(env.delegation, vkey_hash(&p.from)) < 0 {
		return .Invalid_Proposer
	}
	if !verify_proposal(p, block, env.protocol_magic) {
		return .Invalid_Proposal_Signature
	}

	// The new parameters, with any bignum magnitudes copied into the pool.
	mark := len(env.pool)
	next := apply_update(&u.params, &p.params, block, env.pool)
	pv := p.protocol_version
	pv_changed := !(pv == u.adopted_version && params_equal(&next, &u.params, env.pool[:]))
	name := base.span_bytes(block, p.software_version.name)
	number := p.software_version.number
	app := find_app(u, name)
	sv_changed := app < 0 || u.app_versions[app].number != number
	// Two staging-network blocks are exempt from the null-proposal rule.
	exempt := env.protocol_magic == 633343913 && (env.slot == 969188 || env.slot == 1915231)
	if !pv_changed && !sv_changed && !exempt {
		resize(env.pool, mark)
		return .Null_Update_Proposal
	}

	entry := Proposal_Entry {
		id         = ccrypto.blake2b_256(base.span_bytes(block, p.raw)),
		registered = env.slot,
	}
	if pv_changed {
		if e := check_protocol_update(u, p, &next, pv, env.pool[:]); e != .None {
			resize(env.pool, mark)
			return e
		}
		entry.has_pup = true
		entry.pup_version = pv
		entry.pup_params = next
	} else {
		resize(env.pool, mark)
	}
	if sv_changed {
		check_software_update(u, t, p, block, name, number, app) or_return
		entry.has_sup = true
		entry.sup_number = number
		entry.sup_name_len = u8(len(name))
		copy(entry.sup_name[:], name)
	}
	// An identical id cannot be registered twice: its version or application
	// is already taken.
	if i := find_proposal(u, entry.id); i >= 0 {
		u.proposals[i] = entry
	} else {
		append(&u.proposals, entry)
	}
	return .None
}

// `registerProtocolUpdate`.
@(private)
check_protocol_update :: proc(
	u: ^Update_State,
	p: ^Proposal,
	next: ^Protocol_Parameters,
	pv: Protocol_Version,
	pool: []u8,
) -> Update_Error {
	for &e in u.proposals {
		if e.has_pup && e.pup_version == pv do return .Duplicate_Protocol_Version
	}
	if !version_can_follow(pv, u.adopted_version) {
		return .Invalid_Protocol_Version
	}
	if !natural_le_u64(&u.params.max_proposal_size, u64(p.raw.len), pool) {
		return .Proposal_Too_Large
	}
	if !natural_le_double(&next.max_block_size, &u.params.max_block_size, pool) {
		return .Max_Block_Size_Too_Large
	}
	if natural_cmp(&next.max_tx_size, &next.max_block_size, pool) >= 0 {
		return .Max_Tx_Size_Too_Large
	}
	if next.script_version - u.params.script_version > 1 {
		return .Invalid_Script_Version
	}
	return .None
}

// `pvCanFollow`: a higher version whose major is the same (minor + 1) or one
// more (minor 0); alt is free. Word16 arithmetic wraps.
version_can_follow :: proc "contextless" (next, adopted: Protocol_Version) -> bool {
	if !version_less(adopted, next) do return false
	switch next.major - adopted.major {
	case 0:
		return next.minor == adopted.minor + 1
	case 1:
		return next.minor == 0
	}
	return false
}

version_less :: proc "contextless" (a, b: Protocol_Version) -> bool {
	if a.major != b.major do return a.major < b.major
	if a.minor != b.minor do return a.minor < b.minor
	return a.alt < b.alt
}

// `registerSoftwareUpdate`.
@(private)
check_software_update :: proc(
	u: ^Update_State,
	t: ^Tables,
	p: ^Proposal,
	block: []u8,
	name: []u8,
	number: u32,
	app: int,
) -> Update_Error {
	for &m in t.installers[p.metadata.start:base.range_end(p.metadata)] {
		tag := base.span_bytes(block, m.system_tag)
		if code_points(tag) > 10 do return .System_Tag_Too_Long
		if !is_ascii(tag) do return .System_Tag_Not_Ascii
	}
	for &e in u.proposals {
		if e.has_sup && string(e.sup_name[:e.sup_name_len]) == string(name) do return .Duplicate_Software_Version
	}
	if code_points(name) > 12 do return .Application_Name_Too_Long
	if !is_ascii(name) do return .Application_Name_Not_Ascii
	// `svCanFollow`.
	if app < 0 {
		if number > 1 do return .Invalid_Software_Version
	} else if number != u.app_versions[app].number + 1 {
		return .Invalid_Software_Version
	}
	return .None
}

// `Text.length` of valid UTF-8.
@(private = "file")
code_points :: proc "contextless" (b: []u8) -> int {
	n := 0
	for c in b {
		if c & 0xc0 != 0x80 do n += 1
	}
	return n
}

@(private = "file")
is_ascii :: proc "contextless" (b: []u8) -> bool {
	for c in b {
		if c >= 0x80 do return false
	}
	return true
}

// `registerVote` (Voting.hs): the proposal is registered, the voter is a
// delegate whose genesis key has not voted on it, and the signature holds.
// A proposal is confirmed once the threshold of genesis keys has voted.
@(private)
register_vote :: proc(u: ^Update_State, env: ^Update_Env, v: ^Vote, block: []u8) -> Update_Error {
	i := find_proposal(u, v.proposal_id)
	if i < 0 {
		return .Vote_Proposal_Not_Registered
	}
	g := delegator_of(env.delegation, vkey_hash(&v.voter))
	if g < 0 {
		return .Vote_Not_Delegate
	}
	p := &u.proposals[i]
	word, bit := g / 64, u64(1) << uint(g % 64)
	if p.voters[word] & bit != 0 {
		return .Vote_Already_Cast
	}
	if !verify_vote(v, block, env.protocol_magic) {
		return .Invalid_Vote_Signature
	}
	p.voters[word] |= bit
	votes := 0
	for w in p.voters do votes += int(bits.count_ones(w))
	if u64(votes) >= threshold(u, len(env.delegation.genesis_keys)) && !p.confirmed {
		p.confirmed = true
		p.confirmed_slot = env.slot
	}
	return .None
}

// `registerEndorsement`: the header's protocol version endorses the one
// protocol update with that version, if it was confirmed at least 2k slots
// ago (earlier endorsements are dropped, not deferred). Once the threshold
// of genesis keys endorses it, it becomes a candidate unless a candidate of
// the same or a higher version exists.
@(private)
register_endorsement :: proc(
	u: ^Update_State,
	env: ^Update_Env,
	pv: Protocol_Version,
	delegate: base.Key_Hash,
) -> Update_Error {
	found := -1
	for &p, i in u.proposals {
		if !p.has_pup || p.pup_version != pv do continue
		if found >= 0 do return .Multiple_Proposals_For_Version
		found = i
	}
	if found < 0 {
		return .None
	}
	p := &u.proposals[found]
	if !p.confirmed || add_slots(p.confirmed_slot, 2 * env.k) > env.slot {
		return .None
	}
	if g := delegator_of(env.delegation, delegate); g >= 0 {
		seen := false
		for e in u.endorsements {
			if e.version == pv && int(e.genesis) == g do seen = true
		}
		if !seen do append(&u.endorsements, Endorsement{version = pv, genesis = u8(g)})
	}
	n := 0
	for e in u.endorsements {
		if e.version == pv do n += 1
	}
	if u64(n) >= threshold(u, len(env.delegation.genesis_keys)) {
		if len(u.candidates) == 0 || version_less(u.candidates[0].version, pv) {
			inject_at(&u.candidates, 0, Candidate{slot = env.slot, version = pv, params = p.pup_params})
		}
	}
	return .None
}

// Expiry: unconfirmed proposals older than the TTL go, with their votes;
// endorsements are kept only for versions some remaining proposal has.
@(private)
prune :: proc(u: ^Update_State, slot: u64) {
	ttl := u.params.update_proposal_ttl
	kept := 0
	for p in u.proposals {
		if p.confirmed || slot <= add_slots(p.registered, ttl) {
			u.proposals[kept] = p
			kept += 1
		}
	}
	resize(&u.proposals, kept)
	kept = 0
	for e in u.endorsements {
		live := false
		for &p in u.proposals {
			if p.has_pup && p.pup_version == e.version do live = true
		}
		if live {
			u.endorsements[kept] = e
			kept += 1
		}
	}
	resize(&u.endorsements, kept)
}

// ---------------------------------------------------------------------------
// Hard fork to Shelley (consensus: ByronHFC.hs byronTransition)

// After each main block: versions that are still candidates keep the block
// number at which they became one, new candidates get this block's number,
// and the rest are dropped.
update_transition_info :: proc(u: ^Update_State, block_no: u64) {
	kept := 0
	for e in u.transition {
		for &c in u.candidates {
			if c.version == e.version {
				u.transition[kept] = e
				kept += 1
				break
			}
		}
	}
	resize(&u.transition, kept)
	outer: for &c in u.candidates {
		for e in u.transition {
			if e.version == c.version do continue outer
		}
		append(&u.transition, Transition_Entry{version = c.version, block_no = block_no})
	}
}

// The first epoch of the next era, once known (`byronTransition` with
// `TriggerHardForkAtVersion major`): a candidate with that major version that
// is stable (the tip is 2k slots past it, or k blocks past the block that
// made it a candidate) ends Byron at floor((slot + 4k) / es) + 1.
update_transition_epoch :: proc "contextless" (
	u: ^Update_State,
	major: u16,
	tip_slot, tip_block_no, k, epoch_slots: u64,
) -> (
	epoch: u64,
	ok: bool,
) {
	for &c in u.candidates {
		if c.version.major != major do continue
		stable := tip_slot >= c.slot && tip_slot - c.slot >= 2 * k
		if !stable {
			for e in u.transition {
				if e.version == c.version && tip_block_no >= e.block_no && tip_block_no - e.block_no >= k {
					stable = true
				}
			}
		}
		if stable {
			return (c.slot + 4 * k) / epoch_slots + 1, true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Parameters

// `apply`: the update's present fields over `base_params`. Bignum magnitudes
// from the block are copied into `pool`, so the result refers only to it.
@(private)
apply_update :: proc(
	base_params: ^Protocol_Parameters,
	ppu: ^PParams_Update,
	block: []u8,
	pool: ^[dynamic]u8,
) -> (
	p: Protocol_Parameters,
) {
	p = base_params^
	intern :: proc(n: Natural, block: []u8, pool: ^[dynamic]u8) -> Natural {
		if n.big.len == 0 do return n
		off := len(pool)
		append(pool, ..base.span_bytes(block, n.big))
		return Natural{small = n.small, big = base.Span{off = u32(off), len = n.big.len}}
	}
	for f in ppu.present {
		switch f {
		case .Script_Version:
			p.script_version = ppu.script_version
		case .Slot_Duration:
			p.slot_duration = intern(ppu.slot_duration, block, pool)
		case .Max_Block_Size:
			p.max_block_size = intern(ppu.max_block_size, block, pool)
		case .Max_Header_Size:
			p.max_header_size = intern(ppu.max_header_size, block, pool)
		case .Max_Tx_Size:
			p.max_tx_size = intern(ppu.max_tx_size, block, pool)
		case .Max_Proposal_Size:
			p.max_proposal_size = intern(ppu.max_proposal_size, block, pool)
		case .Mpc_Thd:
			p.mpc_thd = ppu.mpc_thd
		case .Heavy_Del_Thd:
			p.heavy_del_thd = ppu.heavy_del_thd
		case .Update_Vote_Thd:
			p.update_vote_thd = ppu.update_vote_thd
		case .Update_Proposal_Thd:
			p.update_proposal_thd = ppu.update_proposal_thd
		case .Update_Proposal_Ttl:
			p.update_proposal_ttl = ppu.update_proposal_ttl
		case .Softfork_Rule:
			p.softfork_rule = ppu.softfork_rule
		case .Tx_Fee_Policy:
			p.tx_fee_policy = ppu.tx_fee_policy
			b := Natural {
				small = ppu.tx_fee_policy.b.small,
				big   = ppu.tx_fee_policy.b.big,
			}
			p.tx_fee_policy.b.big = intern(b, block, pool).big
		case .Unlock_Stake_Epoch:
			p.unlock_stake_epoch = ppu.unlock_stake_epoch
		}
	}
	return p
}

// Field-wise equality; bignums compare by magnitude.
@(private)
params_equal :: proc "contextless" (a, b: ^Protocol_Parameters, pool: []u8) -> bool {
	return(
		a.script_version == b.script_version &&
		natural_cmp(&a.slot_duration, &b.slot_duration, pool) == 0 &&
		natural_cmp(&a.max_block_size, &b.max_block_size, pool) == 0 &&
		natural_cmp(&a.max_header_size, &b.max_header_size, pool) == 0 &&
		natural_cmp(&a.max_tx_size, &b.max_tx_size, pool) == 0 &&
		natural_cmp(&a.max_proposal_size, &b.max_proposal_size, pool) == 0 &&
		a.mpc_thd == b.mpc_thd &&
		a.heavy_del_thd == b.heavy_del_thd &&
		a.update_vote_thd == b.update_vote_thd &&
		a.update_proposal_thd == b.update_proposal_thd &&
		a.update_proposal_ttl == b.update_proposal_ttl &&
		a.softfork_rule == b.softfork_rule &&
		a.tx_fee_policy.a == b.tx_fee_policy.a &&
		a.tx_fee_policy.b.negative == b.tx_fee_policy.b.negative &&
		a.tx_fee_policy.b.small == b.tx_fee_policy.b.small &&
		string(base.span_bytes(pool, a.tx_fee_policy.b.big)) == string(base.span_bytes(pool, b.tx_fee_policy.b.big)) &&
		a.unlock_stake_epoch == b.unlock_stake_epoch \
	)
}

// Compares two Naturals whose magnitudes are in `pool`.
natural_cmp :: proc "contextless" (a, b: ^Natural, pool: []u8) -> int {
	ab := base.span_bytes(pool, a.big)
	bb := base.span_bytes(pool, b.big)
	if len(ab) != len(bb) {
		// No leading zeros: a longer magnitude (or any bignum against a
		// small value) is larger.
		return -1 if len(ab) < len(bb) else 1
	}
	if len(ab) == 0 {
		if a.small == b.small do return 0
		return -1 if a.small < b.small else 1
	}
	for i in 0 ..< len(ab) {
		if ab[i] != bb[i] do return -1 if ab[i] < bb[i] else 1
	}
	return 0
}

// `v <= n`.
natural_le_u64 :: proc "contextless" (n: ^Natural, v: u64, pool: []u8) -> bool {
	return n.big.len > 0 || v <= n.small
}

// `a <= 2 * b`, without overflow.
@(private)
natural_le_double :: proc "contextless" (a, b: ^Natural, pool: []u8) -> bool {
	if a.big.len == 0 && b.big.len == 0 {
		return u128(a.small) <= 2 * u128(b.small)
	}
	if b.big.len == 0 {
		// a has more than 64 bits; 2b has at most 65.
		ab := base.span_bytes(pool, a.big)
		return len(ab) == 9 && ab[0] == 1 && u128(1) << 64 | u128(bits_from(ab[1:])) <= 2 * u128(b.small)
	}
	if a.big.len == 0 {
		return true
	}
	// Both big: compare a with b shifted left by one bit.
	ab := base.span_bytes(pool, a.big)
	bb := base.span_bytes(pool, b.big)
	carry := bb[0] >> 7
	n := len(bb) + int(carry)
	if len(ab) != n {
		return len(ab) < n
	}
	for i in 0 ..< n {
		// Byte i of 2b, most significant first.
		j := i - int(carry)
		hi: u8 = 0 if j < 0 else bb[j] << 1
		lo: u8 = 0 if j + 1 >= len(bb) else bb[j + 1] >> 7
		d := hi | lo
		if ab[i] != d do return ab[i] < d
	}
	return true
}

@(private = "file")
bits_from :: proc "contextless" (b: []u8) -> u64 {
	v: u64
	for c in b do v = v << 8 | u64(c)
	return v
}

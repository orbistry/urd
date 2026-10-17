package ledger

import "core:encoding/endian"
import "core:slice"

import "urd:base"

// Duplicate detection for Conway's ordered sets (OSet) of certificates and
// proposal procedures. Haskell rejects two structurally equal elements. Each
// element is serialised into an injective key (fixed-width fields,
// length-prefixed variable parts) in the block scratch; equal keys mean equal
// elements, so a sort and one pass over neighbours finds duplicates in
// O(n log n) whatever the input.

@(private = "file")
Key :: struct {
	d:   ^Decoder,
	buf: [dynamic]u8,
}

@(private = "file")
put_u8 :: proc(k: ^Key, v: u8) {
	append(&k.buf, v)
}

@(private = "file")
put_u32 :: proc(k: ^Key, v: u32) {
	b: [4]u8
	endian.unchecked_put_u32be(b[:], v)
	append(&k.buf, ..b[:])
}

@(private = "file")
put_u64 :: proc(k: ^Key, v: u64) {
	b: [8]u8
	endian.unchecked_put_u64be(b[:], v)
	append(&k.buf, ..b[:])
}

@(private = "file")
put_bytes :: proc(k: ^Key, b: []u8) {
	put_u32(k, u32(len(b)))
	append(&k.buf, ..b)
}

@(private = "file")
put_span :: proc(k: ^Key, s: base.Span) {
	put_bytes(k, base.span_bytes(k.d.base, s))
}

@(private = "file")
put_hash28 :: proc(k: ^Key, h: base.Hash28) {
	h := h
	append(&k.buf, ..h[:])
}

@(private = "file")
put_hash32 :: proc(k: ^Key, h: base.Hash32) {
	h := h
	append(&k.buf, ..h[:])
}

@(private = "file")
put_cred :: proc(k: ^Key, c: Credential) {
	put_u8(k, u8(c.is_script))
	put_hash28(k, c.hash)
}

@(private = "file")
put_account :: proc(k: ^Key, a: Reward_Account) {
	put_u8(k, u8(a.network))
	put_cred(k, a.cred)
}

@(private = "file")
put_ratio :: proc(k: ^Key, r: Ratio) {
	put_u64(k, r.num)
	put_u64(k, r.den)
}

@(private = "file")
put_anchor :: proc(k: ^Key, a: Anchor) {
	put_u8(k, u8(a.present))
	if a.present {
		put_hash32(k, a.hash)
		put_span(k, a.url)
	}
}

@(private = "file")
put_action_id :: proc(k: ^Key, present: bool, g: Gov_Action_Id) {
	put_u8(k, u8(present))
	if present {
		put_hash32(k, base.Hash32(g.tx))
		put_u32(k, u32(g.index))
	}
}

@(private = "file")
put_pool_params :: proc(k: ^Key, p: ^Pool_Params) {
	put_hash28(k, p.operator)
	put_hash32(k, p.vrf_key_hash)
	put_u64(k, p.pledge)
	put_u64(k, p.cost)
	put_ratio(k, p.margin)
	put_account(k, p.reward_account)
	put_u32(k, p.owners.count)
	for i in 0 ..< p.owners.count {
		put_hash28(k, base.Hash28(k.d.t.key_hashes[p.owners.start + i]))
	}
	// TODO(conformance): relays are keyed by their encoding, so two encodings
	// of the same relays (a non-minimal port, say) count as different here
	// but are equal to the Haskell Ord.
	put_span(k, p.relays)
	put_u8(k, u8(p.has_metadata))
	if p.has_metadata {
		put_span(k, p.metadata_url)
		put_span(k, p.metadata_hash)
	}
}

@(private = "file")
put_cert :: proc(k: ^Key, c: ^Cert) {
	put_u8(k, u8(c.kind))
	put_cred(k, c.cred)
	put_cred(k, c.hot)
	put_hash28(k, c.pool)
	put_u8(k, u8(c.drep.kind))
	put_hash28(k, c.drep.hash)
	put_u64(k, c.coin)
	put_u64(k, c.epoch)
	put_anchor(k, c.anchor)
	if c.kind == .Pool_Registration {
		put_pool_params(k, &k.d.t.pool_params[c.index])
	}
}

@(private = "file")
put_pparams_update :: proc(k: ^Key, u: ^PParams_Update) {
	put_u64(k, transmute(u64)u.present)
	for p in u.present {
		#partial switch p {
		case .Cost_Models:
			put_u32(k, u.cost_models.count)
			for i in 0 ..< u.cost_models.count {
				cm := k.d.t.cost_models[u.cost_models.start + i]
				put_u8(k, cm.language)
				put_u32(k, cm.values.count)
				for j in 0 ..< cm.values.count {
					put_u64(k, u64(k.d.t.cost_values[cm.values.start + j]))
				}
			}
		case .Prices:
			put_ratio(k, u.prices_mem)
			put_ratio(k, u.prices_steps)
		case .Max_Tx_Ex_Units:
			put_u64(k, u.max_tx_ex.mem)
			put_u64(k, u.max_tx_ex.steps)
		case .Max_Block_Ex_Units:
			put_u64(k, u.max_block_ex.mem)
			put_u64(k, u.max_block_ex.steps)
		case .Pool_Voting_Thresholds:
			for r in u.pool_thresholds do put_ratio(k, r)
		case .Drep_Voting_Thresholds:
			for r in u.drep_thresholds do put_ratio(k, r)
		case .Extra_Entropy:
			put_u8(k, u8(u.extra_entropy.neutral))
			put_hash32(k, u.extra_entropy.hash)
		case .Protocol_Version:
			put_u32(k, u.pv_major)
			put_u32(k, u.pv_minor)
		case .A0, .Rho, .Tau, .D, .Min_Fee_Ref_Script_Cost:
			put_ratio(k, u.ratios[p])
		case:
			put_u64(k, u.ints[p])
		}
	}
}

@(private = "file")
put_proposal :: proc(k: ^Key, p: ^Proposal) {
	t := k.d.t
	put_u64(k, p.deposit)
	put_account(k, p.return_account)
	put_u8(k, u8(p.kind))
	put_action_id(k, p.has_prev, p.prev)
	put_u8(k, u8(p.has_policy))
	put_hash28(k, p.policy)
	put_anchor(k, p.anchor)
	switch p.kind {
	case .Parameter_Change:
		put_pparams_update(k, &t.pparam_updates[p.pparams])
	case .Hard_Fork:
		put_u32(k, p.pv_major)
		put_u32(k, p.pv_minor)
	case .Treasury_Withdrawals:
		put_u32(k, p.withdrawals.count)
		for i in 0 ..< p.withdrawals.count {
			w := t.treasury_wdrls[p.withdrawals.start + i]
			put_account(k, w.account)
			put_u64(k, w.coin)
		}
	case .Update_Committee:
		put_u32(k, p.removed.count)
		for i in 0 ..< p.removed.count {
			put_cred(k, t.committee_creds[p.removed.start + i].cred)
		}
		put_u32(k, p.added.count)
		for i in 0 ..< p.added.count {
			m := t.committee_creds[p.added.start + i]
			put_cred(k, m.cred)
			put_u64(k, m.epoch)
		}
		put_ratio(k, p.threshold)
	case .New_Constitution:
		put_anchor(k, p.constitution)
	case .No_Confidence, .Info:
	}
}

@(private = "file")
has_equal_keys :: proc(keys: [][]u8) -> bool {
	slice.sort_by(keys, proc(a, b: []u8) -> bool {return string(a) < string(b)})
	for i in 1 ..< len(keys) {
		if string(keys[i]) == string(keys[i - 1]) do return true
	}
	return false
}

certs_have_duplicates :: proc(d: ^Decoder, xs: []Cert) -> bool {
	k := Key {
		d   = d,
		buf = make([dynamic]u8, d.scratch),
	}
	offsets := make([]int, len(xs) + 1, d.scratch)
	for &c, i in xs {
		offsets[i] = len(k.buf)
		put_cert(&k, &c)
	}
	offsets[len(xs)] = len(k.buf)
	keys := make([][]u8, len(xs), d.scratch)
	for i in 0 ..< len(xs) do keys[i] = k.buf[offsets[i]:offsets[i + 1]]
	return has_equal_keys(keys)
}

proposals_have_duplicates :: proc(d: ^Decoder, xs: []Proposal) -> bool {
	k := Key {
		d   = d,
		buf = make([dynamic]u8, d.scratch),
	}
	offsets := make([]int, len(xs) + 1, d.scratch)
	for &p, i in xs {
		offsets[i] = len(k.buf)
		put_proposal(&k, &p)
	}
	offsets[len(xs)] = len(k.buf)
	keys := make([][]u8, len(xs), d.scratch)
	for i in 0 ..< len(xs) do keys[i] = k.buf[offsets[i]:offsets[i + 1]]
	return has_equal_keys(keys)
}

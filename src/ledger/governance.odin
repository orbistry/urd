package ledger

import "core:slice"

import "urd:base"
import "urd:cbor"

// Conway governance in the transaction body, docs/decoding/txbody.md §9.

Gov_Action_Id :: struct {
	tx:    base.Tx_Id,
	index: u16,
}

Voter_Kind :: enum u8 {
	Committee_Key    = 0,
	Committee_Script = 1,
	Drep_Key         = 2,
	Drep_Script      = 3,
	Pool             = 4,
}

Vote_Choice :: enum u8 {
	No      = 0,
	Yes     = 1,
	Abstain = 2,
}

Vote :: struct {
	voter_kind: Voter_Kind,
	voter:      base.Hash28,
	action:     Gov_Action_Id,
	vote:       Vote_Choice,
	anchor:     Anchor,
}

Gov_Action_Kind :: enum u8 {
	Parameter_Change     = 0,
	Hard_Fork            = 1,
	Treasury_Withdrawals = 2,
	No_Confidence        = 3,
	Update_Committee     = 4,
	New_Constitution     = 5,
	Info                 = 6,
}

Committee_Member :: struct {
	cred:  Credential,
	epoch: u64,
}

Proposal :: struct {
	deposit:        u64,
	return_account: Reward_Account,
	kind:           Gov_Action_Kind,
	has_prev:       bool,
	prev:           Gov_Action_Id,
	has_policy:     bool,
	policy:         base.Hash28,
	// Parameter_Change
	pparams:        u32,
	// Hard_Fork
	pv_major:       u32,
	pv_minor:       u32,
	// Treasury_Withdrawals (into treasury_wdrls)
	withdrawals:    Range,
	// Update_Committee (into committee_creds): removals carry epoch 0.
	removed:        Range,
	added:          Range,
	threshold:      Ratio,
	// New_Constitution
	constitution:   Anchor,
	anchor:         Anchor,
}

// `GovActionId`: RecD [tx id, Word16 index].
read_gov_action_id :: proc "contextless" (d: ^Decoder) -> (g: Gov_Action_Id, err: Error) {
	read_recd(d, 2) or_return
	g.tx = base.Tx_Id(read_hash32(d) or_return)
	g.index = cbor.read_u16(&d.r) or_return
	return g, .None
}

@(private = "file")
read_nullable_purpose :: proc "contextless" (d: ^Decoder, p: ^Proposal) -> Error {
	if read_null_or(d) {
		p.prev = read_gov_action_id(d) or_return
		p.has_prev = true
	}
	return .None
}

@(private = "file")
read_nullable_policy :: proc "contextless" (d: ^Decoder, p: ^Proposal) -> Error {
	if read_null_or(d) {
		p.policy = read_hash28(d) or_return
		p.has_policy = true
	}
	return .None
}

// Ord Voter: CommitteeVoter < DRepVoter < StakePoolVoter, and within a
// credential ScriptHashObj < KeyHashObj, then the hash.
voter_less :: proc(a, b: Vote) -> bool {
	rank :: proc "contextless" (k: Voter_Kind) -> int {
		switch k {
		case .Committee_Script:
			return 0
		case .Committee_Key:
			return 1
		case .Drep_Script:
			return 2
		case .Drep_Key:
			return 3
		case .Pool:
			return 4
		}
		return 5
	}
	ra, rb := rank(a.voter_kind), rank(b.voter_kind)
	if ra != rb do return ra < rb
	return hash28_less(a.voter, b.voter)
}

gov_action_id_less :: proc "contextless" (a, b: Gov_Action_Id) -> bool {
	if a.tx != b.tx do return hash32_less(base.Hash32(a.tx), base.Hash32(b.tx))
	return a.index < b.index
}

// VotingProcedures: { voter => { gov action id => [vote, anchor / null] } }.
// Repeated voters or actions fail (v9), and so does a voter with no votes.
// Rows are left sorted by (voter, action), the ledger's map order.
read_voting_procedures :: proc(d: ^Decoder) -> (r: Range, err: Error) {
	r.start = u32(len(d.t.votes))
	voters := make([dynamic]Vote, d.scratch)
	outer := cbor.read_map(&d.r) or_return
	for cbor.more(&d.r, &outer) {
		tag, c := read_sum(d) or_return
		if tag == 5 || tag > 5 {
			return {}, .Invalid_Value
		}
		voter_kind := Voter_Kind(tag)
		voter := read_hash28(d) or_return
		end_sum(d, c, 1) or_return
		append(&voters, Vote{voter_kind = voter_kind, voter = voter})

		inner := cbor.read_map(&d.r) or_return
		first := len(d.t.votes)
		for cbor.more(&d.r, &inner) {
			v := Vote {
				voter_kind = voter_kind,
				voter      = voter,
			}
			v.action = read_gov_action_id(d) or_return
			read_recd(d, 2) or_return
			choice := cbor.read_int(&d.r) or_return
			if choice < 0 || choice > 2 do return {}, .Invalid_Value
			v.vote = Vote_Choice(choice)
			v.anchor = read_nullable_anchor(d) or_return
			append(&d.t.votes, v)
		}
		if len(d.t.votes) == first {
			return {}, .Empty
		}
	}
	slice.sort_by(voters[:], voter_less)
	for i in 1 ..< len(voters) {
		if voters[i].voter_kind == voters[i - 1].voter_kind && voters[i].voter == voters[i - 1].voter {
			return {}, .Duplicate_Key
		}
	}
	rows := d.t.votes[r.start:]
	slice.sort_by(rows, proc(a, b: Vote) -> bool {
		if a.voter_kind != b.voter_kind || a.voter != b.voter do return voter_less(a, b)
		return gov_action_id_less(a.action, b.action)
	})
	for i in 1 ..< len(rows) {
		if rows[i].voter_kind == rows[i - 1].voter_kind &&
		   rows[i].voter == rows[i - 1].voter &&
		   rows[i].action == rows[i - 1].action {
			return {}, .Duplicate_Key
		}
	}
	r.count = u32(len(rows))
	return r, .None
}

// ProposalProcedure: RecD [deposit, return account, gov action, anchor].
read_proposal :: proc(d: ^Decoder) -> (p: Proposal, err: Error) {
	read_recd(d, 4) or_return
	p.deposit = read_coin(d) or_return
	p.return_account = read_reward_account(d) or_return
	tag, c := read_sum(d) or_return
	if tag > 6 {
		return {}, .Invalid_Value
	}
	p.kind = Gov_Action_Kind(tag)
	fields := 0
	switch p.kind {
	case .Parameter_Change:
		read_nullable_purpose(d, &p) or_return
		p.pparams = read_pparams_update(d) or_return
		read_nullable_policy(d, &p) or_return
		fields = 3
	case .Hard_Fork:
		read_nullable_purpose(d, &p) or_return
		p.pv_major, p.pv_minor = read_proposed_protver(d) or_return
		fields = 2
	case .Treasury_Withdrawals:
		p.withdrawals.start = u32(len(d.t.treasury_wdrls))
		m := cbor.read_map(&d.r) or_return
		for cbor.more(&d.r, &m) {
			w: Withdrawal
			w.account = read_reward_account(d) or_return
			w.coin = read_coin(d) or_return
			append(&d.t.treasury_wdrls, w)
		}
		n := sort_map_rows(d, d.t.treasury_wdrls[p.withdrawals.start:], proc(a, b: Withdrawal) -> bool {
			return reward_account_less(a.account, b.account)
		}) or_return
		resize(&d.t.treasury_wdrls, int(p.withdrawals.start) + n)
		p.withdrawals.count = u32(n)
		read_nullable_policy(d, &p) or_return
		fields = 2
	case .No_Confidence:
		read_nullable_purpose(d, &p) or_return
		fields = 1
	case .Update_Committee:
		read_nullable_purpose(d, &p) or_return
		p.removed.start = u32(len(d.t.committee_creds))
		s := read_set(d) or_return
		for cbor.more(&d.r, &s) {
			append(&d.t.committee_creds, Committee_Member{cred = read_credential(d) or_return})
		}
		n := sort_map_rows(d, d.t.committee_creds[p.removed.start:], committee_member_less) or_return
		resize(&d.t.committee_creds, int(p.removed.start) + n)
		p.removed.count = u32(n)

		p.added.start = u32(len(d.t.committee_creds))
		m := cbor.read_map(&d.r) or_return
		for cbor.more(&d.r, &m) {
			cm: Committee_Member
			cm.cred = read_credential(d) or_return
			cm.epoch = cbor.read_uint(&d.r) or_return
			append(&d.t.committee_creds, cm)
		}
		n = sort_map_rows(d, d.t.committee_creds[p.added.start:], committee_member_less) or_return
		resize(&d.t.committee_creds, int(p.added.start) + n)
		p.added.count = u32(n)
		p.threshold = read_interval(d, .Unit) or_return
		fields = 4
	case .New_Constitution:
		read_nullable_purpose(d, &p) or_return
		read_recd(d, 2) or_return
		p.constitution = read_anchor(d) or_return
		read_nullable_policy(d, &p) or_return
		fields = 2
	case .Info:
	}
	end_sum(d, c, fields) or_return
	p.anchor = read_anchor(d) or_return
	return p, .None
}

committee_member_less :: proc(a, b: Committee_Member) -> bool {
	return credential_less(a.cred, b.cred)
}

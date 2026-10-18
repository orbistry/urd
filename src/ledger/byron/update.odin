package byron

import "urd:base"
import "urd:cbor"

// Update payload: software and protocol update proposals and votes
// (byron/Update/Payload.hs, Proposal.hs, Vote.hs,
// ProtocolParametersUpdate.hs), docs B.3.10.

PParam :: enum u8 {
	Script_Version,
	Slot_Duration,
	Max_Block_Size,
	Max_Header_Size,
	Max_Tx_Size,
	Max_Proposal_Size,
	Mpc_Thd,
	Heavy_Del_Thd,
	Update_Vote_Thd,
	Update_Proposal_Thd,
	Update_Proposal_Ttl,
	Softfork_Rule,
	Tx_Fee_Policy,
	Unlock_Stake_Epoch,
}

// `SoftforkRule`: three `LovelacePortion`s.
Softfork_Rule :: struct {
	init_thd:      u64,
	min_thd:       u64,
	thd_decrement: u64,
}

// A `Fixed E9` value: an Integer counting 10^-9 units. Magnitudes beyond 64
// bits keep their big-endian bytes (`big`, relative to the decoding base).
// The value is `small` (or `big`) when !negative, else `-1 - magnitude`.
Nano :: struct {
	small:    u64,
	big:      base.Span,
	negative: bool,
}

// `TxSizeLinear`: minimum fee `a + b * size`.
Tx_Size_Linear :: struct {
	// Lovelace: the decoded Nano rounded half-even to a Word64 (wrapping),
	// then bounded by mkLovelace.
	a: u64,
	// Lovelace per byte, exactly (`toRational`).
	b: Nano,
}

// A `Natural`: the value when it fits 64 bits, otherwise its big-endian
// magnitude (no leading zeros) in `big`, relative to the decoding base or,
// once in the update state, to the chain's bignum pool. The update rules
// compare parameters with each other exactly (docs/rules/
// byron-delegation-update.md §5), so large values are kept whole.
Natural :: struct {
	small: u64,
	big:   base.Span,
}

// `ProtocolParametersUpdate`: each field is a `Maybe`; `present` says which
// were given.
PParams_Update :: struct {
	present:             bit_set[PParam;u16],
	script_version:      u16,
	slot_duration:       Natural,
	max_block_size:      Natural,
	max_header_size:     Natural,
	max_tx_size:         Natural,
	max_proposal_size:   Natural,
	mpc_thd:             u64,
	heavy_del_thd:       u64,
	update_vote_thd:     u64,
	update_proposal_thd: u64,
	update_proposal_ttl: u64,
	softfork_rule:       Softfork_Rule,
	tx_fee_policy:       Tx_Size_Linear,
	unlock_stake_epoch:  u64,
}

// An entry of a proposal's metadata map.
Installer :: struct {
	system_tag: base.Span,
	hash:       base.Hash32,
}

// `AProposal`. Spans are relative to the block.
Proposal :: struct {
	// The proposal as received; its hash is the `UpId`.
	raw:              base.Span,
	// Fields 1 to 5 as received; the signature covers 0x85 followed by them.
	body:             base.Span,
	protocol_version: Protocol_Version,
	params:           PParams_Update,
	software_version: Software_Version,
	// Rows of `Tables.installers`.
	metadata:         base.Range,
	from:             Vkey,
	sig:              Signature,
}

// `AVote`. The decision bit is decoded and dropped: the signed bytes always
// say True.
Vote :: struct {
	// The vote as received; its hash is the `VoteId`.
	raw:             base.Span,
	// The proposal id as received; the signature covers
	// 0x82 ‖ proposal_id_raw ‖ 0xf5.
	proposal_id_raw: base.Span,
	proposal_id:     base.Hash32,
	voter:           Vkey,
	sig:             Signature,
}

// [proposal?, votes]: a `Maybe` (definite array of 0 or 1) and an indefinite
// list.
@(private)
read_update_payload :: proc(d: ^Decoder) -> Error {
	r := &d.r
	enforce_size(r, 2) or_return
	n := read_array_definite(r) or_return
	switch n {
	case 0:
	case 1:
		p := read_proposal(d) or_return
		append(&d.t.proposals, p)
	case:
		return .Length_Mismatch
	}
	c := read_list(r) or_return
	for cbor.more(r, &c) {
		v := read_vote(d) or_return
		append(&d.t.votes, v)
	}
	return .None
}

@(private)
read_proposal :: proc(d: ^Decoder) -> (p: Proposal, err: Error) {
	r := &d.r
	start := r.pos
	enforce_size(r, 7) or_return
	body_start := r.pos
	p.protocol_version = read_protocol_version(r) or_return
	p.params = read_pparams_update(d) or_return
	p.software_version = read_software_version(d) or_return

	// Metadata: Map SystemTag InstallerHash, a definite map with Text keys
	// strictly increasing (Haskell `Ord Text`: bytewise on valid UTF-8).
	p.metadata.start = u32(len(d.t.installers))
	n := read_map_definite(r) or_return
	prev: []u8
	for i in 0 ..< n {
		tag := read_text(r) or_return
		if i > 0 && string(tag) <= string(prev) {
			return p, .Not_Sorted
		}
		prev = tag
		h := read_installer_hash(r) or_return
		append(&d.t.installers, Installer{system_tag = base.span_of(d.base, tag), hash = h})
	}
	p.metadata.count = u32(n)

	drop_empty_attributes(r) or_return
	p.body = span_from(d, body_start)
	p.from = read_vkey(r) or_return
	p.sig = read_signature(r) or_return
	p.raw = span_from(d, start)
	return p, .None
}

// `InstallerHash`: [bytes, Hash, bytes, bytes]; only the second is checked.
@(private)
read_installer_hash :: proc "contextless" (r: ^cbor.Reader) -> (h: base.Hash32, err: Error) {
	enforce_size(r, 4) or_return
	_ = cbor.read_bytes(r) or_return
	h = cbor.read_hash32(r) or_return
	_ = cbor.read_bytes(r) or_return
	_ = cbor.read_bytes(r) or_return
	return h, .None
}

@(private)
read_vote :: proc "contextless" (d: ^Decoder) -> (v: Vote, err: Error) {
	r := &d.r
	start := r.pos
	enforce_size(r, 4) or_return
	v.voter = read_vkey(r) or_return
	id_start := r.pos
	v.proposal_id = cbor.read_hash32(r) or_return
	v.proposal_id_raw = span_from(d, id_start)
	_ = cbor.read_bool(r) or_return
	v.sig = read_signature(r) or_return
	v.raw = span_from(d, start)
	return v, .None
}

@(private)
read_pparams_update :: proc "contextless" (d: ^Decoder) -> (u: PParams_Update, err: Error) {
	r := &d.r
	enforce_size(r, 14) or_return
	for param in PParam {
		n := read_array_definite(r) or_return
		if n == 0 {
			continue
		}
		if n != 1 {
			return u, .Length_Mismatch
		}
		u.present += {param}
		switch param {
		case .Script_Version:
			u.script_version = cbor.read_u16(r) or_return
		case .Slot_Duration:
			u.slot_duration = read_natural(d) or_return
		case .Max_Block_Size:
			u.max_block_size = read_natural(d) or_return
		case .Max_Header_Size:
			u.max_header_size = read_natural(d) or_return
		case .Max_Tx_Size:
			u.max_tx_size = read_natural(d) or_return
		case .Max_Proposal_Size:
			u.max_proposal_size = read_natural(d) or_return
		case .Mpc_Thd:
			u.mpc_thd = read_lovelace_portion(r) or_return
		case .Heavy_Del_Thd:
			u.heavy_del_thd = read_lovelace_portion(r) or_return
		case .Update_Vote_Thd:
			u.update_vote_thd = read_lovelace_portion(r) or_return
		case .Update_Proposal_Thd:
			u.update_proposal_thd = read_lovelace_portion(r) or_return
		case .Update_Proposal_Ttl:
			u.update_proposal_ttl = cbor.read_uint(r) or_return
		case .Softfork_Rule:
			enforce_size(r, 3) or_return
			u.softfork_rule.init_thd = read_lovelace_portion(r) or_return
			u.softfork_rule.min_thd = read_lovelace_portion(r) or_return
			u.softfork_rule.thd_decrement = read_lovelace_portion(r) or_return
		case .Tx_Fee_Policy:
			u.tx_fee_policy = read_tx_fee_policy(d) or_return
		case .Unlock_Stake_Epoch:
			u.unlock_stake_epoch = cbor.read_uint(r) or_return
		}
	}
	return u, .None
}

// `TxFeePolicy`: [0, #6.24(bytes .cbor [Nano a, Nano b])]; only tag 0.
@(private)
read_tx_fee_policy :: proc "contextless" (d: ^Decoder) -> (f: Tx_Size_Linear, err: Error) {
	r := &d.r
	enforce_size(r, 2) or_return
	tag := cbor.read_u8(r) or_return
	if tag != 0 {
		return f, .Invalid_Value
	}
	payload := read_nested(r) or_return
	p := cbor.reader(payload)
	f = read_tx_size_linear(d, &p) or_return
	cbor.expect_end(&p) or_return
	return f, .None
}

// `TxSizeLinear`: [Nano a, Nano b], with a rounded to lovelace.
@(private)
read_tx_size_linear :: proc "contextless" (d: ^Decoder, r: ^cbor.Reader) -> (f: Tx_Size_Linear, err: Error) {
	enforce_size(r, 2) or_return
	a := read_nano(d, r) or_return
	f.a = nano_round_word64(d, a)
	if f.a > MAX_LOVELACE {
		return f, .Invalid_Value
	}
	f.b = read_nano(d, r) or_return
	return f, .None
}

// `decodeNatural`: `decodeInteger`, non-negative.
@(private)
read_natural :: proc "contextless" (d: ^Decoder) -> (n: Natural, err: Error) {
	i := cbor.read_integer(&d.r) or_return
	if i.negative {
		return n, .Invalid_Value
	}
	n.small = i.small
	if i.big != nil {
		n.big = base.span_of(d.base, i.big)
	}
	return n, .None
}

// `decCBOR @Nano`: `MkFixed <$> decodeInteger`.
@(private)
read_nano :: proc "contextless" (d: ^Decoder, r: ^cbor.Reader) -> (n: Nano, err: Error) {
	i := cbor.read_integer(r) or_return
	n.small = i.small
	n.negative = i.negative
	if i.big != nil {
		n.big = base.span_of(d.base, i.big)
	}
	return n, .None
}

// `round :: Nano -> Word64`: `round . toRational`, half to even, with the
// integral part converted by `fromInteger` (modulo 2^64). Computed from
// |N| mod (10^9 * 2^64), which fixes both the quotient modulo 2^64 (and its
// parity) and the remainder.
@(private)
nano_round_word64 :: proc "contextless" (d: ^Decoder, n: Nano) -> u64 {
	E9 :: u128(1_000_000_000)
	M :: E9 << 64
	mag: u128
	if n.big.len == 0 {
		mag = u128(n.small)
		if n.negative {
			mag += 1 // -1 - small
		}
	} else {
		for b in base.span_bytes(d.base, n.big) {
			mag = (mag << 8 | u128(b)) % M
		}
		if n.negative {
			mag = (mag + 1) % M
		}
	}
	q := u64(mag / E9)
	rem := mag % E9
	if rem > E9 / 2 || (rem == E9 / 2 && q & 1 == 1) {
		q += 1
	}
	return ~q + 1 if n.negative else q
}

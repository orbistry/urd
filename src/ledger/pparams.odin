package ledger

import "urd:base"
import "urd:cbor"

// Protocol parameter updates, docs/decoding/txbody.md §8.

PParam :: enum u8 {
	Min_Fee_A               = 0,
	Min_Fee_B               = 1,
	Max_Block_Body_Size     = 2,
	Max_Tx_Size             = 3,
	Max_Block_Header_Size   = 4,
	Key_Deposit             = 5,
	Pool_Deposit            = 6,
	E_Max                   = 7,
	N_Opt                   = 8,
	A0                      = 9,
	Rho                     = 10,
	Tau                     = 11,
	D                       = 12,
	Extra_Entropy           = 13,
	Protocol_Version        = 14,
	Min_UTxO_Value          = 15,
	Min_Pool_Cost           = 16,
	Coins_Per_UTxO          = 17,
	Cost_Models             = 18,
	Prices                  = 19,
	Max_Tx_Ex_Units         = 20,
	Max_Block_Ex_Units      = 21,
	Max_Value_Size          = 22,
	Collateral_Percentage   = 23,
	Max_Collateral_Inputs   = 24,
	Pool_Voting_Thresholds  = 25,
	Drep_Voting_Thresholds  = 26,
	Committee_Min_Size      = 27,
	Committee_Max_Term      = 28,
	Gov_Action_Lifetime     = 29,
	Gov_Action_Deposit      = 30,
	Drep_Deposit            = 31,
	Drep_Activity           = 32,
	Min_Fee_Ref_Script_Cost = 33,
}

PParam_Set :: bit_set[PParam;u64]

Ex_Units :: struct {
	mem:   u64,
	steps: u64,
}

Nonce :: struct {
	hash:    base.Hash32,
	neutral: bool,
}

// A partial protocol parameter update. `ints` holds every integer-valued
// parameter, indexed by its key.
PParams_Update :: struct {
	present:         PParam_Set,
	ints:            [PParam]u64,
	ratios:          [PParam]Ratio,
	extra_entropy:   Nonce,
	pv_major:        u32,
	pv_minor:        u32,
	cost_models:     Range,
	prices_mem:      Ratio,
	prices_steps:    Ratio,
	max_tx_ex:       Ex_Units,
	max_block_ex:    Ex_Units,
	pool_thresholds: [5]Ratio,
	drep_thresholds: [10]Ratio,
}

Cost_Model :: struct {
	language: u8,
	values:   Range,
}

// Pre-Conway update proposal: one PParams update per genesis key, effective
// in `epoch`.
Update :: struct {
	proposals: Range,
	epoch:     u64,
}

Update_Proposal :: struct {
	genesis: base.Hash28,
	pparams: u32,
}

// Parameters each era's PParamsUpdate accepts.
@(private = "file")
era_params :: proc "contextless" (era: base.Era) -> PParam_Set {
	shelley := PParam_Set {
		.Min_Fee_A,
		.Min_Fee_B,
		.Max_Block_Body_Size,
		.Max_Tx_Size,
		.Max_Block_Header_Size,
		.Key_Deposit,
		.Pool_Deposit,
		.E_Max,
		.N_Opt,
		.A0,
		.Rho,
		.Tau,
		.D,
		.Extra_Entropy,
		.Protocol_Version,
		.Min_UTxO_Value,
		.Min_Pool_Cost,
	}
	alonzo_new := PParam_Set {
		.Coins_Per_UTxO,
		.Cost_Models,
		.Prices,
		.Max_Tx_Ex_Units,
		.Max_Block_Ex_Units,
		.Max_Value_Size,
		.Collateral_Percentage,
		.Max_Collateral_Inputs,
	}
	conway_new := PParam_Set {
		.Pool_Voting_Thresholds,
		.Drep_Voting_Thresholds,
		.Committee_Min_Size,
		.Committee_Max_Term,
		.Gov_Action_Lifetime,
		.Gov_Action_Deposit,
		.Drep_Deposit,
		.Drep_Activity,
		.Min_Fee_Ref_Script_Cost,
	}
	switch era {
	case .Byron:
		return {}
	case .Shelley, .Allegra, .Mary:
		return shelley
	case .Alonzo:
		return (shelley - {.Min_UTxO_Value}) + alonzo_new
	case .Babbage:
		return (shelley - {.Min_UTxO_Value, .D, .Extra_Entropy}) + alonzo_new
	case .Conway, .Dijkstra:
		return (shelley - {.Min_UTxO_Value, .D, .Extra_Entropy, .Protocol_Version}) + alonzo_new + conway_new
	}
	return {}
}

// Highest protocol major version `decodeProtVer @era` accepts:
// succ (ProtVerHigh era), capped by MaxVersion.
max_proposed_major :: proc "contextless" (era: base.Era) -> u32 {
	high: u32
	switch era {
	case .Byron:
		high = 1
	case .Shelley:
		high = 2
	case .Allegra:
		high = 3
	case .Mary:
		high = 4
	case .Alonzo:
		high = 6
	case .Babbage:
		high = 8
	case .Conway:
		high = 11
	case .Dijkstra:
		high = 12
	}
	return min(high + 1, MAX_PROTOCOL_VERSION)
}

// `decodeProtVer @era`: Rec [major, minor], major bounded per era.
read_proposed_protver :: proc "contextless" (d: ^Decoder) -> (major, minor: u32, err: Error) {
	c := read_rec(d, 2) or_return
	major = cbor.read_u32(&d.r) or_return
	if major > MAX_PROTOCOL_VERSION || major > max_proposed_major(d.era) {
		return 0, 0, .Invalid_Value
	}
	minor = cbor.read_u32(&d.r) or_return
	cbor.end(&d.r, c) or_return
	return major, minor, .None
}

// `ExUnits`: RecD [mem, steps], each Word64 no larger than maxBound :: Int64.
read_ex_units :: proc "contextless" (d: ^Decoder) -> (e: Ex_Units, err: Error) {
	read_recd(d, 2) or_return
	e.mem = cbor.read_uint(&d.r) or_return
	e.steps = cbor.read_uint(&d.r) or_return
	if e.mem > u64(max(i64)) || e.steps > u64(max(i64)) {
		return {}, .Overflow
	}
	return e, .None
}

// The PParamsUpdate sparse map of the decoder's era.
read_pparams_update :: proc(d: ^Decoder) -> (index: u32, err: Error) {
	u: PParams_Update
	allowed := era_params(d.era)
	m := cbor.read_map(&d.r) or_return
	for cbor.more(&d.r, &m) {
		key := cbor.read_uint(&d.r) or_return
		if key > 63 {
			return 0, .Unknown_Key
		}
		p := PParam(key)
		if key > u64(PParam.Min_Fee_Ref_Script_Cost) || p not_in allowed {
			return 0, .Unknown_Key
		}
		if p in u.present {
			return 0, .Duplicate_Key
		}
		u.present += {p}
		#partial switch p {
		case .Min_Fee_A,
		     .Min_Fee_B,
		     .Key_Deposit,
		     .Pool_Deposit,
		     .Min_UTxO_Value,
		     .Min_Pool_Cost,
		     .Coins_Per_UTxO,
		     .Gov_Action_Deposit,
		     .Drep_Deposit:
			u.ints[p] = cbor.read_uint(&d.r) or_return
		case .Max_Block_Body_Size,
		     .Max_Tx_Size,
		     .E_Max,
		     .Max_Value_Size,
		     .Committee_Max_Term,
		     .Gov_Action_Lifetime,
		     .Drep_Activity:
			u.ints[p] = u64(cbor.read_u32(&d.r) or_return)
		case .Max_Block_Header_Size, .N_Opt, .Collateral_Percentage, .Max_Collateral_Inputs, .Committee_Min_Size:
			u.ints[p] = u64(cbor.read_u16(&d.r) or_return)
		case .A0, .Min_Fee_Ref_Script_Cost:
			u.ratios[p] = read_interval(d, .Non_Negative) or_return
		case .Rho, .Tau, .D:
			u.ratios[p] = read_interval(d, .Unit) or_return
		case .Extra_Entropy:
			tag, c := read_sum(d) or_return
			switch tag {
			case 0:
				u.extra_entropy.neutral = true
				end_sum(d, c, 0) or_return
			case 1:
				u.extra_entropy.hash = read_hash32(d) or_return
				end_sum(d, c, 1) or_return
			case:
				return 0, .Invalid_Value
			}
		case .Protocol_Version:
			u.pv_major, u.pv_minor = read_proposed_protver(d) or_return
		case .Cost_Models:
			u.cost_models = read_cost_models(d) or_return
		case .Prices:
			read_recd(d, 2) or_return
			u.prices_mem = read_interval(d, .Non_Negative) or_return
			u.prices_steps = read_interval(d, .Non_Negative) or_return
		case .Max_Tx_Ex_Units:
			u.max_tx_ex = read_ex_units(d) or_return
		case .Max_Block_Ex_Units:
			u.max_block_ex = read_ex_units(d) or_return
		case .Pool_Voting_Thresholds:
			c := read_rec(d, 5) or_return
			for i in 0 ..< 5 do u.pool_thresholds[i] = read_interval(d, .Unit) or_return
			cbor.end(&d.r, c) or_return
		case .Drep_Voting_Thresholds:
			c := read_rec(d, 10) or_return
			for i in 0 ..< 10 do u.drep_thresholds[i] = read_interval(d, .Unit) or_return
			cbor.end(&d.r, c) or_return
		}
	}
	index = u32(len(d.t.pparam_updates))
	append(&d.t.pparam_updates, u)
	return index, .None
}

// Cost models, docs/decoding/txbody.md §8.5. Alonzo and Babbage accept only
// PlutusV1 (166 values) and PlutusV2 (175 values), last-wins on repeated
// languages. Conway accepts any Word8 language and any list length, and
// rejects repeated languages.
@(private = "file")
read_cost_models :: proc(d: ^Decoder) -> (r: Range, err: Error) {
	r.start = u32(len(d.t.cost_models))
	m := cbor.read_map(&d.r) or_return
	for cbor.more(&d.r, &m) {
		lang: u8
		if d.v >= 9 {
			lang = cbor.read_u8(&d.r) or_return
		} else {
			// Language: decodeEnumBounded (an Int in 0..3); V3/V4 are not
			// supported by the legacy decoder.
			l := cbor.read_int(&d.r) or_return
			if l < 0 || l > 1 do return {}, .Invalid_Value
			lang = u8(l)
		}
		cm := Cost_Model {
			language = lang,
		}
		cm.values.start = u32(len(d.t.cost_values))
		vals := cbor.read_array(&d.r) or_return
		for cbor.more(&d.r, &vals) {
			append(&d.t.cost_values, cbor.read_int(&d.r) or_return)
		}
		cm.values.count = u32(len(d.t.cost_values)) - cm.values.start
		if d.v < 9 {
			want: u32 = 166 if lang == 0 else 175
			if cm.values.count != want do return {}, .Length_Mismatch
		}
		append(&d.t.cost_models, cm)
	}
	n := sort_map_rows(
		d,
		d.t.cost_models[r.start:],
		proc(a, b: Cost_Model) -> bool {return a.language < b.language},
	) or_return
	resize(&d.t.cost_models, int(r.start) + n)
	r.count = u32(n)
	return r, .None
}

// Pre-Conway `Update`: RecD [{genesis key => PParamsUpdate}, epoch].
read_update :: proc(d: ^Decoder) -> (u: Update, err: Error) {
	read_recd(d, 2) or_return
	u.proposals.start = u32(len(d.t.update_proposals))
	m := cbor.read_map(&d.r) or_return
	for cbor.more(&d.r, &m) {
		g := read_hash28(d) or_return
		idx := read_pparams_update(d) or_return
		append(&d.t.update_proposals, Update_Proposal{genesis = g, pparams = idx})
	}
	n := sort_map_rows(d, d.t.update_proposals[u.proposals.start:], proc(a, b: Update_Proposal) -> bool {
		return hash28_less(a.genesis, b.genesis)
	}) or_return
	resize(&d.t.update_proposals, int(u.proposals.start) + n)
	u.proposals.count = u32(n)
	u.epoch = cbor.read_uint(&d.r) or_return
	return u, .None
}

package ledger

import "core:slice"

import "urd:base"
import "urd:cbor"
import "urd:ccrypto"

// Transaction bodies and outputs, docs/decoding/txbody.md §2 and §3.

// Keys each era's TxBody accepts (§2.9).
@(private = "file")
era_body_keys :: proc "contextless" (era: base.Era) -> bit_set[0 ..< 32] {
	shelley := bit_set[0 ..< 32]{0, 1, 2, 3, 4, 5, 6, 7}
	switch era {
	case .Byron:
		return {}
	case .Shelley:
		return shelley
	case .Allegra, .Mary:
		return shelley + {8, 9}
	case .Alonzo:
		return shelley + {8, 9, 11, 13, 14, 15}
	case .Babbage:
		return shelley + {8, 9, 11, 13, 14, 15, 16, 17, 18}
	case .Conway, .Dijkstra:
		return (shelley - {6}) + {8, 9, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
	}
	return {}
}

// Decodes a TxBody (a sparse map) into `tx` and the block tables. The caller
// sets the body span and computes the id.
read_tx_body :: proc(d: ^Decoder, tx: ^Tx) -> Error {
	t := d.t
	allowed := era_body_keys(d.era)
	conway := d.v >= 9
	seen: bit_set[0 ..< 32]

	tx.inputs.start = u32(len(t.inputs))
	tx.outputs.start = u32(len(t.outputs))
	tx.collateral.start = u32(len(t.collateral))
	tx.ref_inputs.start = u32(len(t.ref_inputs))
	tx.certs.start = u32(len(t.certs))
	tx.withdrawals.start = u32(len(t.withdrawals))
	tx.mint.start = u32(len(t.mint))
	tx.required_signers.start = u32(len(t.required_signers))
	tx.votes.start = u32(len(t.votes))
	tx.proposals.start = u32(len(t.proposals))

	m := cbor.read_map(&d.r) or_return
	for cbor.more(&d.r, &m) {
		key := cbor.read_uint(&d.r) or_return
		if key >= 32 || int(key) not_in allowed {
			return .Unknown_Key
		}
		if int(key) in seen {
			return .Duplicate_Key
		}
		seen += {int(key)}
		switch key {
		case 0:
			tx.inputs = read_tx_in_set(d, &t.inputs) or_return
		case 1:
			tx.outputs.start = u32(len(t.outputs))
			c := cbor.read_array(&d.r) or_return
			for cbor.more(&d.r, &c) {
				out := read_tx_out(d) or_return
				append(&t.outputs, out)
			}
			tx.outputs.count = u32(len(t.outputs)) - tx.outputs.start
		case 2:
			tx.fee = read_coin(d) or_return
		case 3:
			tx.ttl = cbor.read_uint(&d.r) or_return
			tx.flags += {.Ttl}
		case 4:
			if conway {
				// OSet: optional tag 258, repeated certificates fail.
				allow_tag(d, 258) or_return
			}
			c := cbor.read_array(&d.r) or_return
			for cbor.more(&d.r, &c) {
				cert := read_cert(d) or_return
				append(&t.certs, cert)
			}
			tx.certs.count = u32(len(t.certs)) - tx.certs.start
			if conway {
				if tx.certs.count == 0 do return .Empty
				if certs_have_duplicates(d, t.certs[tx.certs.start:]) do return .Duplicate_Key
			}
		case 5:
			c := cbor.read_map(&d.r) or_return
			for cbor.more(&d.r, &c) {
				w: Withdrawal
				w.account = read_reward_account(d) or_return
				w.coin = read_coin(d) or_return
				append(&t.withdrawals, w)
			}
			n := sort_map_rows(d, t.withdrawals[tx.withdrawals.start:], proc(a, b: Withdrawal) -> bool {
				return reward_account_less(a.account, b.account)
			}) or_return
			resize(&t.withdrawals, int(tx.withdrawals.start) + n)
			tx.withdrawals.count = u32(n)
			if conway && n == 0 do return .Empty
		case 6:
			tx.update = read_update(d) or_return
			tx.flags += {.Update}
		case 7:
			tx.aux_data_hash = read_hash32(d) or_return
			tx.flags += {.Aux_Data_Hash}
		case 8:
			tx.validity_start = cbor.read_uint(&d.r) or_return
			tx.flags += {.Validity_Start}
		case 9:
			if d.era == .Allegra {
				// Allegra's mint slot has type (): only null decodes.
				cbor.read_null(&d.r) or_return
				continue
			}
			read_multi_asset(d, &t.mint) or_return
			tx.mint.count = u32(len(t.mint)) - tx.mint.start
			if conway && tx.mint.count == 0 do return .Empty
			tx.flags += {.Mint}
		case 11:
			tx.script_data_hash = read_hash32(d) or_return
			tx.flags += {.Script_Data_Hash}
		case 13:
			tx.collateral = read_tx_in_set(d, &t.collateral) or_return
			if conway && tx.collateral.count == 0 do return .Empty
		case 14:
			s := read_set(d) or_return
			for cbor.more(&d.r, &s) {
				append(&t.required_signers, base.Key_Hash(read_hash28(d) or_return))
			}
			n := sort_unique_key_hashes(d, t.required_signers[tx.required_signers.start:]) or_return
			resize(&t.required_signers, int(tx.required_signers.start) + n)
			tx.required_signers.count = u32(n)
			if conway && n == 0 do return .Empty
		case 15:
			id := cbor.read_u8(&d.r) or_return
			if id > 1 do return .Invalid_Value
			tx.network_id = Network(id)
			tx.flags += {.Network_Id}
		case 16:
			tx.collateral_return = u32(len(t.outputs))
			out := read_tx_out(d) or_return
			append(&t.outputs, out)
			tx.flags += {.Collateral_Return}
		case 17:
			tx.total_collateral = read_coin(d) or_return
			tx.flags += {.Total_Collateral}
		case 18:
			tx.ref_inputs = read_tx_in_set(d, &t.ref_inputs) or_return
			if conway && tx.ref_inputs.count == 0 do return .Empty
		case 19:
			tx.votes = read_voting_procedures(d) or_return
			if tx.votes.count == 0 do return .Empty
		case 20:
			allow_tag(d, 258) or_return
			c := cbor.read_array(&d.r) or_return
			for cbor.more(&d.r, &c) {
				p := read_proposal(d) or_return
				append(&t.proposals, p)
			}
			tx.proposals.count = u32(len(t.proposals)) - tx.proposals.start
			if tx.proposals.count == 0 do return .Empty
			if proposals_have_duplicates(d, t.proposals[tx.proposals.start:]) do return .Duplicate_Key
		case 21:
			tx.treasury = read_coin(d) or_return
			tx.flags += {.Treasury}
		case 22:
			tx.donation = read_positive_coin(d) or_return
			tx.flags += {.Donation}
		}
	}
	required := bit_set[0 ..< 32]{0, 1, 2}
	if d.era == .Shelley {
		required += {3}
	}
	if required & seen != required {
		return .Missing_Key
	}
	return .None
}

// `Set TxIn`, sorted (the ledger's order, which redeemer indices refer to).
@(private = "file")
read_tx_in_set :: proc(d: ^Decoder, table: ^[dynamic]Tx_In) -> (r: Range, err: Error) {
	r.start = u32(len(table))
	c := read_set(d) or_return
	for cbor.more(&d.r, &c) {
		rc := read_rec(d, 2) or_return
		txin: Tx_In
		txin.id = base.Tx_Id(read_hash32(d) or_return)
		txin.index = cbor.read_u16(&d.r) or_return
		cbor.end(&d.r, rc) or_return
		append(table, txin)
	}
	xs := table[r.start:]
	slice.sort_by(xs, tx_in_less)
	n := unique_sorted(d, xs) or_return
	resize(table, int(r.start) + n)
	r.count = u32(n)
	return r, .None
}

// A transaction output of the decoder's era.
read_tx_out :: proc(d: ^Decoder) -> (out: Tx_Out, err: Error) {
	start := d.r.pos
	if d.era >= .Babbage {
		m := cbor.peek_major(&d.r) or_return
		if m == .Map {
			read_tx_out_map(d, &out) or_return
			out.raw = span_from(d, start)
			return out, .None
		}
	}

	c := cbor.read_array(&d.r) or_return
	if d.era < .Alonzo {
		// ShelleyTxOut: Rec [address, value].
		if !c.indefinite && c.n != 2 do return {}, .Length_Mismatch
		out.address = read_address(d) or_return
		out.coin, out.assets = read_value(d, &d.t.assets) or_return
		cbor.end(&d.r, c) or_return
	} else {
		// [address, value] or [address, value, datum hash].
		if !c.indefinite && c.n != 2 && c.n != 3 do return {}, .Length_Mismatch
		out.address = read_address(d) or_return
		out.coin, out.assets = read_value(d, &d.t.assets) or_return
		has_hash := c.n == 3
		if c.indefinite {
			b := cbor.peek_byte(&d.r) or_return
			if b == cbor.BREAK {
				d.r.pos += 1
			} else {
				has_hash = true
			}
		}
		if has_hash {
			out.datum_kind = .Hash
			out.datum_hash = read_hash32(d) or_return
			if c.indefinite {
				cbor.end(&d.r, c) or_return
			}
		}
	}
	out.raw = span_from(d, start)
	return out, .None
}

// Babbage map-form output: {0: address, 1: value, ? 2: datum option,
// ? 3: script ref}.
@(private = "file")
read_tx_out_map :: proc(d: ^Decoder, out: ^Tx_Out) -> Error {
	seen: bit_set[0 ..< 4]
	m := cbor.read_map(&d.r) or_return
	for cbor.more(&d.r, &m) {
		key := cbor.read_uint(&d.r) or_return
		if key > 3 do return .Unknown_Key
		if int(key) in seen do return .Duplicate_Key
		seen += {int(key)}
		switch key {
		case 0:
			out.address = read_address(d) or_return
		case 1:
			out.coin, out.assets = read_value(d, &d.t.assets) or_return
		case 2:
			tag, c := read_sum(d) or_return
			switch tag {
			case 0:
				out.datum_kind = .Hash
				out.datum_hash = read_hash32(d) or_return
			case 1:
				payload := read_inline_datum(d) or_return
				out.datum_kind = .Inline
				out.datum = span(d, payload)
				out.datum_hash = ccrypto.blake2b_256(payload)
			case:
				return .Invalid_Value
			}
			end_sum(d, c, 1) or_return
		case 3:
			inner := read_script_ref(d) or_return
			out.script_ref = span(d, inner)
		}
	}
	if seen & {0, 1} != {0, 1} {
		return .Missing_Key
	}
	return .None
}

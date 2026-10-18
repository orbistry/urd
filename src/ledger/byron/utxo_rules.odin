package byron

import "urd:base"
import "urd:cbor"

// The Byron UTxO rules (byron/UTxO/Validation.hs updateUTxO,
// updateUTxOTxWitness, validateTxAux, validateTx; docs/rules/byron-utxo.md).
//
// A block's transactions apply in order, each against the UTxO left by the
// ones before it. They are validated against an overlay (what the block has
// consumed and produced so far) over the store, and the overlay is committed
// only once the whole block is valid.

Utxo_Error :: enum u8 {
	None,
	// An input is not in the UTxO (UTxOMissingInput).
	Missing_Input,
	// A witness signature does not verify (TxValidationWitnessWrongSignature).
	Witness_Signature,
	// A witness key does not match its input's address
	// (TxValidationWitnessWrongKey).
	Witness_Key,
	// The `[tx, witnesses]` encoding is longer than maxTxSize.
	Tx_Too_Large,
	// A balance or the minimum fee is out of the Lovelace range, or the
	// outputs exceed the inputs (TxValidationLovelaceError).
	Lovelace,
	Fee_Too_Small,
	// Transaction or output-address unknown attributes of 128 bytes or more.
	Unknown_Attributes,
	Network_Magic,
	// An output's input is already in the UTxO (UTxOOverlappingUnion).
	Overlapping_Union,
}

// What the rules need from the chain state: the configuration's protocol
// magic and the current protocol parameters.
Utxo_Env :: struct {
	protocol_magic: u32,
	// RequiresNetworkMagic: output addresses must then carry the protocol
	// magic as their network magic, and must not otherwise.
	requires_magic: bool,
	max_tx_size:    Natural,
	fee_policy:     Tx_Size_Linear,
	// The bytes the parameters' bignum spans are relative to.
	pool:           []u8,
}

// Block-local state, reused across blocks.
Utxo_Overlay :: struct {
	// Store entries the block has spent.
	consumed: map[base.Tx_In]struct{},
	// Outputs the block has created and not spent, as rows of
	// `Tables.outputs`.
	produced: map[base.Tx_In]u32,
	// The distinct inputs of the transaction being applied.
	tx_ins:   map[base.Tx_In]struct{},
	scratch:  cbor.Writer,
}

utxo_overlay_init :: proc(o: ^Utxo_Overlay, allocator := context.allocator) {
	o.consumed = make(map[base.Tx_In]struct{}, allocator)
	o.produced = make(map[base.Tx_In]u32, allocator)
	o.tx_ins = make(map[base.Tx_In]struct{}, allocator)
	o.scratch = cbor.writer(allocator)
}

utxo_overlay_destroy :: proc(o: ^Utxo_Overlay) {
	delete(o.consumed)
	delete(o.produced)
	delete(o.tx_ins)
	cbor.writer_destroy(&o.scratch)
}

// Validates and applies the transactions of a decoded block (`updateUTxO`).
// On failure the store is unchanged and `failed` is the failing
// transaction's index.
utxo_apply_block :: proc(
	env: ^Utxo_Env,
	u: ^Utxo,
	o: ^Utxo_Overlay,
	t: ^Tables,
	block: []u8,
) -> (
	err: Utxo_Error,
	failed: int,
) {
	clear(&o.consumed)
	clear(&o.produced)
	for &tx, i in t.txs {
		if e := apply_tx(env, u, o, t, block, &tx); e != .None {
			return e, i
		}
	}
	for txin in o.consumed {
		utxo_remove(u, txin)
	}
	for txin, row in o.produced {
		// The UTxO holds the re-encoded address (`CompactAddress`), which is
		// also what Shelley inherits; it differs from the bytes received
		// only if those were not canonical.
		out := &t.outputs[row]
		address := base.span_bytes(block, out.raw)
		if !heads_minimal(address) {
			cbor.writer_reset(&o.scratch)
			r := cbor.reader(address)
			reencode_address(&o.scratch, &r)
			address = cbor.writer_bytes(&o.scratch)
		}
		utxo_insert(u, txin, address, out.lovelace)
	}
	utxo_maybe_compact(u)
	return .None, -1
}

@(private = "file")
Resolved :: struct {
	address:  []u8,
	lovelace: u64,
}

@(private = "file")
resolve :: proc(u: ^Utxo, o: ^Utxo_Overlay, t: ^Tables, block: []u8, txin: base.Tx_In) -> (r: Resolved, ok: bool) {
	if row, produced := o.produced[txin]; produced {
		out := &t.outputs[row]
		return Resolved{base.span_bytes(block, out.raw), out.lovelace}, true
	}
	if txin in o.consumed {
		return {}, false
	}
	e := utxo_get(u, txin) or_return
	return Resolved{utxo_address(u, e), e.lovelace}, true
}

// `updateUTxOTxWitness`: witnesses against the input addresses, then
// `validateTxAux`, then `updateUTxOTx` (`validateTx` and the UTxO update).
@(private = "file")
apply_tx :: proc(env: ^Utxo_Env, u: ^Utxo, o: ^Utxo_Overlay, t: ^Tables, block: []u8, tx: ^Tx) -> Utxo_Error {
	// Every input's address, in input order (duplicates included).
	inputs := t.inputs[tx.inputs.start:base.range_end(tx.inputs)]
	witnesses := t.witnesses[tx.witnesses.start:base.range_end(tx.witnesses)]
	sig_hash := tx_sig_hash(tx, block)
	for txin, i in inputs {
		r, ok := resolve(u, o, t, block, txin)
		if !ok {
			return .Missing_Input
		}
		// `zip addresses witnesses`: extra witnesses are ignored and missing
		// ones are not detected.
		if i < len(witnesses) {
			check_witness(env, &witnesses[i], sig_hash, r.address, &o.scratch) or_return
		}
	}

	// validateTxAux: size, then the fee over the distinct inputs.
	if !natural_le_u64(&env.max_tx_size, u64(tx.aux.len), env.pool) {
		return .Tx_Too_Large
	}
	clear(&o.tx_ins)
	balance_in: u128
	all_redeem := true
	for txin in inputs {
		if txin in o.tx_ins do continue
		o.tx_ins[txin] = {}
		r, _ := resolve(u, o, t, block, txin)
		balance_in += u128(r.lovelace)
		a, _ := parse_address(r.address)
		all_redeem &&= a.type == .Redeem
	}
	// `txOutputUTxO` indexes outputs with `[0 ..] :: [Word16]`, so outputs
	// past index 65535 are in neither the balance nor the UTxO (unreachable
	// within 2 MB blocks).
	n_outputs := min(tx.outputs.count, 65536)
	balance_out: u128
	for &out in t.outputs[tx.outputs.start:][:n_outputs] {
		balance_out += u128(out.lovelace)
	}
	// sumLovelace bounds both sums, subLovelace the difference.
	if balance_in > MAX_LOVELACE || balance_out > MAX_LOVELACE || balance_in < balance_out {
		return .Lovelace
	}
	fee := u64(balance_in - balance_out)
	min_fee: u64 = 0
	if !all_redeem {
		ok: bool
		min_fee, ok = tx_min_fee(&env.fee_policy, env.pool, tx.aux.len)
		if !ok {
			return .Lovelace
		}
	}
	if fee < min_fee {
		return .Fee_Too_Small
	}

	// validateTx: attribute sizes and output network magic (inputs were
	// resolved above).
	if tx.unknown_attrs_len >= 128 {
		return .Unknown_Attributes
	}
	for &out in t.outputs[tx.outputs.start:base.range_end(tx.outputs)] {
		if out.address.unknown_attrs_len >= 128 {
			return .Unknown_Attributes
		}
		if out.address.has_magic != env.requires_magic ||
		   (env.requires_magic && out.address.magic != env.protocol_magic) {
			return .Network_Magic
		}
	}

	// `UTxO.union (inputs </| utxo) (txOutputUTxO tx)`.
	for txin in o.tx_ins {
		if _, produced := o.produced[txin]; produced {
			delete_key(&o.produced, txin)
		} else {
			o.consumed[txin] = {}
		}
	}
	for k in 0 ..< n_outputs {
		txin := base.Tx_In {
			id    = tx.id,
			index = u16(k),
		}
		if _, exists := resolve(u, o, t, block, txin); exists {
			return .Overlapping_Union
		}
		o.produced[txin] = tx.outputs.start + k
	}
	return .None
}

// `validateWitness`: the signature over the transaction's hash, and the key
// matching the address (`checkVerKeyAddress` / `checkRedeemAddress`).
@(private = "file")
check_witness :: proc(
	env: ^Utxo_Env,
	w: ^Witness,
	sig_hash: base.Hash32,
	address: []u8,
	scratch: ^cbor.Writer,
) -> Utxo_Error {
	if !verify_tx_witness(w, sig_hash, env.protocol_magic) {
		return .Witness_Signature
	}
	key := w.key[:] if w.kind == .Ver_Key else w.key[:32]
	type := Addr_Type.Ver_Key if w.kind == .Ver_Key else Addr_Type.Redeem
	if !address_spent_by(address, type, key, scratch) {
		return .Witness_Key
	}
	return .None
}

// `checkAddrSpendingData`: the address's type matches the key's, and its root
// is the hash of [type, [type, key], attributes], with the attributes
// re-encoded (they equal the bytes received when those are canonical).
address_spent_by :: proc(address: []u8, type: Addr_Type, key: []u8, scratch: ^cbor.Writer) -> bool {
	a, err := parse_address(address)
	if err != .None || a.type != type {
		return false
	}
	attrs := address_attributes(address)
	if !heads_minimal(attrs) {
		cbor.writer_reset(scratch)
		r := cbor.reader(attrs)
		reencode_attributes(scratch, &r)
		attrs = cbor.writer_bytes(scratch)
	}
	return address_root(type, key, attrs) == a.root
}

// The attribute map inside a decoded address's payload.
@(private = "file")
address_attributes :: proc "contextless" (address: []u8) -> []u8 {
	r := cbor.reader(address)
	_, _ = cbor.read_array(&r)
	payload, _ := read_nested(&r)
	p := cbor.reader(payload)
	_, _ = cbor.read_array(&p)
	_, _ = cbor.read_bytes(&p)
	start := p.pos
	c, _ := cbor.read_map(&p)
	for _ in 0 ..< c.n {
		_, _ = cbor.read_uint(&p)
		_, _ = cbor.read_bytes(&p)
	}
	return payload[start:p.pos]
}

// `calculateTxSizeLinear`: a + ceiling(size * b), where the product goes
// through `fromInteger` to a Word64 (modulo 2^64) and the sum is
// `addLovelace` (no wrap, at most maxLovelace). Sizes are byte lengths, so
// they fit 32 bits and pass `integerToLovelace`.
tx_min_fee :: proc "contextless" (f: ^Tx_Size_Linear, fee_base: []u8, size: u32) -> (fee: u64, ok: bool) {
	// b = N / 10^9. With |N| * size reduced mod 10^9 * 2^64, the quotient by
	// 10^9 is right modulo 2^64 and the remainder exactly.
	E9 :: u128(1_000_000_000)
	M :: E9 << 64
	mag: u128
	if f.b.big.len == 0 {
		mag = u128(f.b.small)
		if f.b.negative {
			mag += 1 // -1 - small
		}
	} else {
		for b in base.span_bytes(fee_base, f.b.big) {
			mag = (mag << 8 | u128(b)) % M
		}
		if f.b.negative {
			mag = (mag + 1) % M
		}
	}
	// mag < 2^94 and size < 2^32, so the product fits.
	x := mag * u128(size) % M
	q := u64(x / E9)
	r := x % E9
	scaled: u64
	if !f.b.negative {
		scaled = q + (1 if r > 0 else 0) // ceiling of a positive quotient
	} else {
		scaled = ~q + 1 // ceiling of a negative one: -floor(|.|)
	}
	sum := f.a + scaled
	if sum < f.a || sum < scaled || sum > MAX_LOVELACE {
		return 0, false
	}
	return sum, true
}

package byron

import "core:hash"

import "urd:base"
import "urd:cbor"
import "urd:ccrypto"

// Transactions (byron/UTxO/Tx.hs, TxAux.hs, TxWitness.hs), docs B.3.1-B.3.6.

// One transaction of a block. Spans are relative to the block.
Tx :: struct {
	// The UTxO transaction id (`serializeCborHash`): Blake2b-256 of the
	// transaction's canonical re-encoding, which differs from the wire bytes
	// only if they use non-minimal heads.
	id:                base.Tx_Id,
	// `[tx, witnesses]` as received; its length is the size the fee and size
	// rules use.
	aux:               base.Span,
	// The `[inputs, outputs, attributes]` array as received: the Merkle leaf,
	// and (hashed) what the witnesses sign.
	body:              base.Span,
	// The witness list as received, hashed into the body proof.
	witness_list:      base.Span,
	inputs:            base.Range,
	outputs:           base.Range,
	witnesses:         base.Range,
	// `unknownAttributesLength` of the transaction attributes (all entries
	// are unknown); the UTxO rule requires it to be below 128.
	unknown_attrs_len: u32,
}

Tx_Out :: struct {
	// The address item as received (`[#6.24(payload), crc]`).
	raw:      base.Span,
	address:  Address,
	lovelace: u64,
}

Witness_Kind :: enum u8 {
	Ver_Key = 0,
	Redeem  = 2,
}

Witness :: struct {
	// Ver_Key: the extended key (Ed25519 key and chain code). Redeem: the
	// Ed25519 key in the first 32 bytes.
	key:  Vkey,
	sig:  Signature,
	kind: Witness_Kind,
}

// `ATxPayload`: an indefinite list of `[tx, witnesses]`.
@(private)
read_tx_payload :: proc(d: ^Decoder) -> Error {
	c := read_list(&d.r) or_return
	for cbor.more(&d.r, &c) {
		read_tx_aux(d) or_return
	}
	return .None
}

@(private)
read_tx_aux :: proc(d: ^Decoder) -> Error {
	start := d.r.pos
	enforce_size(&d.r, 2) or_return
	tx := read_tx(d) or_return
	tx.witnesses, tx.witness_list = read_witness_list(d) or_return
	tx.aux = span_from(d, start)
	tx.id = tx_id(d.t, base.span_bytes(d.base, tx.body))
	append(&d.t.txs, tx)
	return .None
}

// `Tx`: [inputs, outputs, attributes]. Fills the body fields of a `Tx`.
@(private)
read_tx :: proc(d: ^Decoder) -> (tx: Tx, err: Error) {
	t := d.t
	r := &d.r
	start := r.pos
	enforce_size(r, 3) or_return

	// Inputs and outputs: `NonEmpty`, an indefinite list with at least one
	// element.
	tx.inputs.start = u32(len(t.inputs))
	c := read_list(r) or_return
	for cbor.more(r, &c) {
		txin := read_tx_in(r) or_return
		append(&t.inputs, txin)
	}
	tx.inputs.count = u32(len(t.inputs)) - tx.inputs.start
	if tx.inputs.count == 0 {
		return tx, .Empty
	}

	tx.outputs.start = u32(len(t.outputs))
	c = read_list(r) or_return
	for cbor.more(r, &c) {
		out := read_tx_out(d) or_return
		append(&t.outputs, out)
	}
	tx.outputs.count = u32(len(t.outputs)) - tx.outputs.start
	if tx.outputs.count == 0 {
		return tx, .Empty
	}

	tx.unknown_attrs_len = read_unit_attributes(r) or_return
	tx.body = span_from(d, start)
	return tx, .None
}

// `TxOut`: [address, lovelace].
@(private)
read_tx_out :: proc "contextless" (d: ^Decoder) -> (out: Tx_Out, err: Error) {
	r := &d.r
	enforce_size(r, 2) or_return
	start := r.pos
	out.address = read_address(r) or_return
	out.raw = span_from(d, start)
	out.lovelace = read_lovelace(r) or_return
	return out, .None
}

// `TxWitness = Vector TxInWitness`: a definite list, possibly empty.
@(private)
read_witness_list :: proc(d: ^Decoder) -> (rows: base.Range, raw: base.Span, err: Error) {
	start := d.r.pos
	rows.start = u32(len(d.t.witnesses))
	n := read_array_definite(&d.r) or_return
	for _ in 0 ..< n {
		w := read_witness(&d.r) or_return
		append(&d.t.witnesses, w)
	}
	rows.count = u32(n)
	return rows, span_from(d, start), .None
}

// `TxIn`: [0, #6.24(bytes .cbor [txid, Word16 index])]. Only tag 0 exists.
@(private)
read_tx_in :: proc "contextless" (r: ^cbor.Reader) -> (txin: base.Tx_In, err: Error) {
	enforce_size(r, 2) or_return
	tag := cbor.read_u8(r) or_return
	if tag != 0 {
		return {}, .Invalid_Value
	}
	payload := read_nested(r) or_return
	p := cbor.reader(payload)
	enforce_size(&p, 2) or_return
	txin.id = base.Tx_Id(cbor.read_hash32(&p) or_return)
	txin.index = cbor.read_u16(&p) or_return
	cbor.expect_end(&p) or_return
	return txin, .None
}

// `TxInWitness`: [0, #6.24([vkey, sig])] or [2, #6.24([redeem_vkey, sig])].
@(private)
read_witness :: proc "contextless" (r: ^cbor.Reader) -> (w: Witness, err: Error) {
	n := read_array_definite(r) or_return
	tag := cbor.read_u8(r) or_return
	if tag != 0 && tag != 2 {
		return {}, .Invalid_Value
	}
	if n != 2 {
		return {}, .Length_Mismatch
	}
	payload := read_nested(r) or_return
	p := cbor.reader(payload)
	enforce_size(&p, 2) or_return
	if tag == 0 {
		w.kind = .Ver_Key
		w.key = read_vkey(&p) or_return
	} else {
		// `RedeemVerificationKey`: any byte string of exactly 32 bytes.
		w.kind = .Redeem
		k := cbor.read_bytes_n(&p, 32) or_return
		copy(w.key[:], k)
	}
	w.sig = read_signature(&p) or_return
	cbor.expect_end(&p) or_return
	return w, .None
}

// ---------------------------------------------------------------------------
// Transaction ids

// The id is `serializeCborHash tx`: the hash of the transaction re-encoded
// at version 1, not of the bytes received (byron/UTxO/UTxO.hs txOutputUTxO).
// The decoder only accepts the shapes the encoder produces (indefinite input
// and output lists, definite records, maps in key order, definite strings),
// and the parsed attribute values (derivation path, network magic) must
// already be canonical. So the re-encoding equals the wire bytes exactly when
// every head is minimal, including inside the CBOR-in-CBOR payloads of inputs
// and addresses, which are re-encoded from their decoded values; address
// CRCs then match too. Otherwise the transaction is re-encoded.
@(private)
tx_id :: proc(t: ^Tables, body: []u8) -> base.Tx_Id {
	if heads_minimal(body) {
		return base.Tx_Id(ccrypto.blake2b_256(body))
	}
	cbor.writer_reset(&t.encoder)
	reencode_tx(&t.encoder, body)
	return base.Tx_Id(ccrypto.blake2b_256(cbor.writer_bytes(&t.encoder)))
}

// Reports whether every head of `item` (one well-formed data item) uses the
// shortest encoding, also inside byte strings tagged 24, which hold nested
// CBOR. A false negative only costs a re-encoding, so overly deep nesting
// (never produced by a decoded transaction) just reports false.
heads_minimal :: proc "contextless" (item: []u8, depth := 0) -> bool {
	if depth > 4 {
		return false
	}
	r := cbor.reader(item)
	nested := false
	for !cbor.at_end(&r) {
		if r.data[r.pos] == cbor.BREAK {
			r.pos += 1
			nested = false
			continue
		}
		start := r.pos
		h, err := cbor.read_head(&r)
		if err != .None {
			return false
		}
		if h.info != cbor.INFO_INDEFINITE && r.pos - start != cbor.head_size(h.arg) {
			return false
		}
		#partial switch h.major {
		case .Bytes, .Text:
			if h.info == cbor.INFO_INDEFINITE || h.arg > u64(cbor.remaining(&r)) {
				return false
			}
			s := r.data[r.pos:][:h.arg]
			r.pos += int(h.arg)
			if nested && h.major == .Bytes && !heads_minimal(s, depth + 1) {
				return false
			}
		}
		nested = h.major == .Tag && h.arg == 24
	}
	return true
}

// Writes the version-1 encoding of a decoded transaction (`encCBOR Tx`):
// minimal heads, indefinite input and output lists, nested payloads re-encoded
// and address CRCs recomputed. `body` must have passed `read_tx_aux`.
reencode_tx :: proc(w: ^cbor.Writer, body: []u8) {
	r := cbor.reader(body)
	_, _ = cbor.read_array(&r)
	cbor.write_array(w, 3)

	c, _ := cbor.read_array(&r)
	cbor.write_array_indefinite(w)
	for cbor.more(&r, &c) {
		_, _ = cbor.read_array(&r)
		_, _ = cbor.read_uint(&r)
		payload, _ := read_nested(&r)
		p := cbor.reader(payload)
		_, _ = cbor.read_array(&p)
		id, _ := cbor.read_bytes(&p)
		index, _ := cbor.read_uint(&p)

		cbor.write_array(w, 2)
		cbor.write_uint(w, 0)
		m := cbor.embedded_begin(w)
		cbor.write_array(w, 2)
		cbor.write_bytes(w, id)
		cbor.write_uint(w, index)
		cbor.embedded_end(w, m)
	}
	cbor.write_break(w)

	c, _ = cbor.read_array(&r)
	cbor.write_array_indefinite(w)
	for cbor.more(&r, &c) {
		_, _ = cbor.read_array(&r)
		cbor.write_array(w, 2)
		reencode_address(w, &r)
		lovelace, _ := cbor.read_uint(&r)
		cbor.write_uint(w, lovelace)
	}
	cbor.write_break(w)

	reencode_attributes(w, &r)
}

// `encodeCrcProtected (root, attributes, type)`.
@(private)
reencode_address :: proc(w: ^cbor.Writer, r: ^cbor.Reader) {
	_, _ = cbor.read_array(r)
	payload, _ := read_nested(r)
	_, _ = cbor.read_uint(r)

	p := cbor.reader(payload)
	_, _ = cbor.read_array(&p)
	root, _ := cbor.read_bytes(&p)

	cbor.write_array(w, 2)
	m := cbor.embedded_begin(w)
	cbor.write_array(w, 3)
	cbor.write_bytes(w, root)
	reencode_attributes(w, &p)
	type, _ := cbor.read_uint(&p)
	cbor.write_uint(w, type)
	payload_len := len(w.buf) - m - 9
	cbor.embedded_end(w, m)
	crc := hash.crc32(w.buf[len(w.buf) - payload_len:])
	cbor.write_uint(w, u64(crc))
}

// `encCBORAttributes`: a definite map in key order. Parsed values (address
// derivation path and network magic) re-encode to the canonical bytes they
// were required to have, so every value is written back as received.
@(private)
reencode_attributes :: proc(w: ^cbor.Writer, r: ^cbor.Reader) {
	c, _ := cbor.read_map(r)
	cbor.write_map(w, c.n)
	for _ in 0 ..< c.n {
		key, _ := cbor.read_uint(r)
		value, _ := cbor.read_bytes(r)
		cbor.write_uint(w, key)
		cbor.write_bytes(w, value)
	}
}

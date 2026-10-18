package byron

import "core:crypto/sha3"
import "core:encoding/base64"
import "core:encoding/hex"
import "core:encoding/json"
import "core:hash"
import "core:slice"
import "core:strconv"

import "urd:base"
import "urd:cbor"
import "urd:ccrypto"

// The Byron genesis configuration (cardano-ledger byron Genesis/*.hs), loaded
// from the genesis JSON file. Loading happens once at start-up, so it
// allocates freely from the allocator it is given.

// The full protocol parameters (`ProtocolParameters`): the genesis file's
// blockVersionData, later changed by adopted update proposals.
Protocol_Parameters :: struct {
	script_version:      u16,
	// Milliseconds.
	slot_duration:       Natural,
	max_block_size:      Natural,
	max_header_size:     Natural,
	max_tx_size:         Natural,
	max_proposal_size:   Natural,
	mpc_thd:             u64,
	heavy_del_thd:       u64,
	update_vote_thd:     u64,
	update_proposal_thd: u64,
	// Slots.
	update_proposal_ttl: u64,
	softfork_rule:       Softfork_Rule,
	tx_fee_policy:       Tx_Size_Linear,
	unlock_stake_epoch:  u64,
}

// A genesis heavyweight delegation certificate.
Genesis_Delegation :: struct {
	issuer:   Vkey,
	delegate: Vkey,
	epoch:    u64,
	sig:      Signature,
}

// A genesis AVVM balance: a redeem key and its lovelace.
Avvm_Entry :: struct {
	key:      [32]u8,
	lovelace: u64,
}

// A genesis non-AVVM balance: an address (CBOR bytes) and its lovelace.
Balance_Entry :: struct {
	address:  []u8,
	lovelace: u64,
}

Genesis :: struct {
	// Blake2b-256 of the file's canonical JSON rendering: the previous hash
	// of the genesis EBB, and what node configurations pin.
	hash:           base.Hash32,
	protocol_magic: u32,
	// Security parameter; an epoch is 10k slots.
	k:              u64,
	// Seconds since the Unix epoch.
	start_time:     i64,
	params:         Protocol_Parameters,
	// bootStakeholders: the genesis keys (hashes of their verification keys)
	// and their weights.
	genesis_keys:   []base.Key_Hash,
	key_weights:    []u16,
	delegations:    []Genesis_Delegation,
	avvm:           []Avvm_Entry,
	non_avvm:       []Balance_Entry,
}

Genesis_Error :: enum u8 {
	None,
	Json,
	Missing_Field,
	Invalid_Field,
}

epoch_slots :: #force_inline proc "contextless" (g: ^Genesis) -> u64 {
	return 10 * g.k
}

// Parses a Byron genesis file. Everything in the result is allocated from
// `allocator`.
genesis_parse :: proc(data: []u8, allocator := context.allocator) -> (g: Genesis, err: Genesis_Error) {
	context.allocator = allocator
	root, jerr := json.parse(
		data,
		json.DEFAULT_SPECIFICATION,
		parse_integers = true,
		allocator = context.temp_allocator,
	)
	if jerr != .None {
		return g, .Json
	}
	obj, is_object := root.(json.Object)
	if !is_object {
		return g, .Json
	}
	canonical := make([dynamic]u8, context.temp_allocator)
	render_canonical(&canonical, root) or_return
	g.hash = ccrypto.blake2b_256(canonical[:])

	consts := field_object(obj, "protocolConsts") or_return
	g.k = field_u64(consts, "k") or_return
	magic := field_u64(consts, "protocolMagic") or_return
	if magic > u64(max(u32)) {
		return g, .Invalid_Field
	}
	g.protocol_magic = u32(magic)
	start := field_u64(obj, "startTime") or_return
	g.start_time = i64(start)

	g.params = parse_protocol_parameters(field_object(obj, "blockVersionData") or_return) or_return

	stakeholders := field_object(obj, "bootStakeholders") or_return
	g.genesis_keys = make([]base.Key_Hash, len(stakeholders))
	g.key_weights = make([]u16, len(stakeholders))
	i := 0
	for key, weight in stakeholders {
		parse_hex(g.genesis_keys[i][:], key) or_return
		w := weight.(json.Integer) or_else -1
		if w < 0 || w > i64(max(u16)) {
			return g, .Invalid_Field
		}
		g.key_weights[i] = u16(w)
		i += 1
	}

	heavy := field_object(obj, "heavyDelegation") or_return
	g.delegations = make([]Genesis_Delegation, len(heavy))
	i = 0
	for _, v in heavy {
		cert, cert_ok := v.(json.Object)
		if !cert_ok {
			return g, .Invalid_Field
		}
		d := &g.delegations[i]
		parse_base64(d.issuer[:], field_string(cert, "issuerPk") or_return, base64.DEC_TABLE) or_return
		parse_base64(d.delegate[:], field_string(cert, "delegatePk") or_return, base64.DEC_TABLE) or_return
		parse_hex(d.sig[:], field_string(cert, "cert") or_return) or_return
		d.epoch = field_u64(cert, "omega") or_return
		i += 1
	}

	avvm := field_object(obj, "avvmDistr") or_return
	g.avvm = make([]Avvm_Entry, len(avvm))
	i = 0
	for key, v in avvm {
		e := &g.avvm[i]
		parse_base64(e.key[:], key, base64.DEC_URL_TABLE) or_return
		e.lovelace = parse_decimal(v) or_return
		i += 1
	}

	non_avvm := field_object(obj, "nonAvvmBalances") or_return
	g.non_avvm = make([]Balance_Entry, len(non_avvm))
	i = 0
	for addr, v in non_avvm {
		e := &g.non_avvm[i]
		e.address = base58_decode(addr) or_return
		e.lovelace = parse_decimal(v) or_return
		i += 1
	}
	return g, .None
}

genesis_destroy :: proc(g: ^Genesis, allocator := context.allocator) {
	context.allocator = allocator
	delete(g.genesis_keys)
	delete(g.key_weights)
	delete(g.delegations)
	delete(g.avvm)
	for e in g.non_avvm {
		delete(e.address)
	}
	delete(g.non_avvm)
}

// Canonical JSON (Haskell canonical-json's `renderCanonicalJSON`): no
// whitespace, object keys sorted, integers only, and strings escaping just
// `"` and `\`.
@(private = "file")
render_canonical :: proc(out: ^[dynamic]u8, v: json.Value) -> Genesis_Error {
	switch x in v {
	case json.Null:
		append(out, "null")
	case json.Boolean:
		append(out, "true" if x else "false")
	case json.Integer:
		buf: [32]u8
		append(out, strconv.write_int(buf[:], x, 10))
	case json.Float:
		return .Invalid_Field
	case json.String:
		append(out, '"')
		for c in transmute([]u8)x {
			if c == '"' || c == '\\' {
				append(out, '\\')
			}
			append(out, c)
		}
		append(out, '"')
	case json.Array:
		append(out, '[')
		for e, i in x {
			if i > 0 do append(out, ',')
			render_canonical(out, e) or_return
		}
		append(out, ']')
	case json.Object:
		keys := make([]string, len(x), context.temp_allocator)
		i := 0
		for k in x {
			keys[i] = k
			i += 1
		}
		slice.sort(keys)
		append(out, '{')
		for k, j in keys {
			if j > 0 do append(out, ',')
			render_canonical(out, json.String(k)) or_return
			append(out, ':')
			render_canonical(out, x[k]) or_return
		}
		append(out, '}')
	}
	return .None
}

@(private = "file")
parse_protocol_parameters :: proc(o: json.Object) -> (p: Protocol_Parameters, err: Genesis_Error) {
	script := field_u64(o, "scriptVersion") or_return
	if script > u64(max(u16)) {
		return p, .Invalid_Field
	}
	p.script_version = u16(script)
	p.slot_duration.small = parse_decimal(o["slotDuration"]) or_return
	p.max_block_size.small = parse_decimal(o["maxBlockSize"]) or_return
	p.max_header_size.small = parse_decimal(o["maxHeaderSize"]) or_return
	p.max_tx_size.small = parse_decimal(o["maxTxSize"]) or_return
	p.max_proposal_size.small = parse_decimal(o["maxProposalSize"]) or_return
	p.mpc_thd = parse_decimal(o["mpcThd"]) or_return
	p.heavy_del_thd = parse_decimal(o["heavyDelThd"]) or_return
	p.update_vote_thd = parse_decimal(o["updateVoteThd"]) or_return
	p.update_proposal_thd = parse_decimal(o["updateProposalThd"]) or_return
	p.update_proposal_ttl = parse_decimal(o["updateImplicit"]) or_return
	p.unlock_stake_epoch = parse_decimal(o["unlockStakeEpoch"]) or_return
	sf := field_object(o, "softforkRule") or_return
	p.softfork_rule.init_thd = parse_decimal(sf["initThd"]) or_return
	p.softfork_rule.min_thd = parse_decimal(sf["minThd"]) or_return
	p.softfork_rule.thd_decrement = parse_decimal(sf["thdDecrement"]) or_return
	// txFeePolicy: summand and multiplier in Nano (10^-9 lovelace) units.
	fee := field_object(o, "txFeePolicy") or_return
	summand := parse_decimal(fee["summand"]) or_return
	p.tx_fee_policy.a = nano_round_word64(nil, Nano{small = summand})
	p.tx_fee_policy.b = Nano {
		small = parse_decimal(fee["multiplier"]) or_return,
	}
	return p, .None
}

@(private = "file")
field_object :: proc(o: json.Object, key: string) -> (v: json.Object, err: Genesis_Error) {
	f, ok := o[key]
	if !ok {
		return nil, .Missing_Field
	}
	is_object: bool
	v, is_object = f.(json.Object)
	if !is_object {
		return nil, .Invalid_Field
	}
	return v, .None
}

@(private = "file")
field_string :: proc(o: json.Object, key: string) -> (v: string, err: Genesis_Error) {
	f, ok := o[key]
	if !ok {
		return "", .Missing_Field
	}
	s, is_string := f.(json.String)
	if !is_string {
		return "", .Invalid_Field
	}
	return s, .None
}

@(private = "file")
field_u64 :: proc(o: json.Object, key: string) -> (v: u64, err: Genesis_Error) {
	f, ok := o[key]
	if !ok {
		return 0, .Missing_Field
	}
	n, is_int := f.(json.Integer)
	if !is_int || n < 0 {
		return 0, .Invalid_Field
	}
	return u64(n), .None
}

// Decimal strings (the file's encoding of Word64 quantities).
@(private = "file")
parse_decimal :: proc(v: json.Value) -> (n: u64, err: Genesis_Error) {
	s, ok := v.(json.String)
	if !ok {
		return 0, .Invalid_Field
	}
	if len(s) == 0 {
		return 0, .Invalid_Field
	}
	for c in transmute([]u8)s {
		if c < '0' || c > '9' {
			return 0, .Invalid_Field
		}
	}
	n, ok = strconv.parse_u64_of_base(s, 10)
	return n, .None if ok else .Invalid_Field
}

@(private = "file")
parse_hex :: proc(dst: []u8, s: string) -> Genesis_Error {
	b, ok := hex.decode(transmute([]u8)s, context.temp_allocator)
	if !ok || len(b) != len(dst) {
		return .Invalid_Field
	}
	copy(dst, b)
	return .None
}

@(private = "file")
parse_base64 :: proc(dst: []u8, s: string, table: [256]i8) -> Genesis_Error {
	b, err := base64.decode(s, table, allocator = context.temp_allocator)
	if err != nil || len(b) != len(dst) {
		return .Invalid_Field
	}
	copy(dst, b)
	return .None
}

// Bitcoin-alphabet base58, as Byron addresses are written in JSON.
@(private = "file")
base58_decode :: proc(s: string) -> (b: []u8, err: Genesis_Error) {
	ALPHABET :: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	// Little-endian base-256 accumulator.
	acc := make([dynamic]u8, context.temp_allocator)
	zeros := 0
	for c, i in transmute([]u8)s {
		d := -1
		for a, j in transmute([]u8)string(ALPHABET) {
			if a == c {
				d = j
				break
			}
		}
		if d < 0 {
			return nil, .Invalid_Field
		}
		if d == 0 && len(acc) == 0 && zeros == i {
			zeros += 1
			continue
		}
		carry := d
		for k in 0 ..< len(acc) {
			carry += int(acc[k]) * 58
			acc[k] = u8(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			append(&acc, u8(carry & 0xff))
			carry >>= 8
		}
	}
	b = make([]u8, zeros + len(acc))
	for k in 0 ..< len(acc) {
		b[zeros + k] = acc[len(acc) - 1 - k]
	}
	return b, .None
}

// ---------------------------------------------------------------------------
// Genesis UTxO

// The root of an address (`addressHash`): Blake2b-224 of SHA3-256 of the
// version-1 encoding of [type, [type, key], attributes]. `attributes` is the
// encoded attribute map.
address_root :: proc(type: Addr_Type, key: []u8, attributes: []u8) -> base.Hash28 {
	head: [16]u8
	head[0] = 0x83
	head[1] = u8(type)
	head[2] = 0x82
	head[3] = u8(type)
	n := 4 + cbor.put_head(head[4:], .Bytes, u64(len(key)))
	parts := [3][]u8{head[:n], key, attributes}
	digest := sha3_256_parts(parts[:])
	return ccrypto.blake2b_224(digest[:])
}

// The address of an AVVM redeem key (`makeRedeemAddress`): no derivation
// path; the network magic attribute only when the network requires it.
// Writes the address's CBOR to `w` and returns it.
redeem_address :: proc(w: ^cbor.Writer, key: []u8, network_magic: Maybe(u32)) -> []u8 {
	attrs: [16]u8
	attrs_len := 1
	attrs[0] = 0xa0
	if m, ok := network_magic.?; ok {
		// {2: bytes(cbor(magic))}
		inner: [5]u8
		k := cbor.put_head(inner[:], .Unsigned, u64(m))
		attrs[0] = 0xa1
		attrs[1] = 0x02
		attrs[2] = 0x40 | u8(k)
		copy(attrs[3:], inner[:k])
		attrs_len = 3 + k
	}
	root := address_root(.Redeem, key, attrs[:attrs_len])

	start := len(w.buf)
	cbor.write_array(w, 2)
	m := cbor.embedded_begin(w)
	cbor.write_array(w, 3)
	cbor.write_bytes(w, root[:])
	cbor.write_raw(w, attrs[:attrs_len])
	cbor.write_uint(w, u64(Addr_Type.Redeem))
	payload_len := len(w.buf) - m - 9
	cbor.embedded_end(w, m)
	payload := w.buf[len(w.buf) - payload_len:]
	cbor.write_uint(w, u64(hash.crc32(payload)))
	return w.buf[start:]
}

// The input of a genesis balance (`genesisUtxo`): the hash of the address's
// CBOR, index 0.
genesis_tx_in :: proc "contextless" (address: []u8) -> base.Tx_In {
	return base.Tx_In{id = base.Tx_Id(ccrypto.blake2b_256(address)), index = 0}
}

@(private)
sha3_256_parts :: proc(parts: [][]u8) -> (digest: [32]u8) {
	ctx: sha3.Context
	sha3.init_256(&ctx)
	for part in parts {
		sha3.update(&ctx, part)
	}
	sha3.final(&ctx, digest[:])
	return digest
}

// Fills `u` with the genesis balances (`genesisUtxo`): each AVVM key's redeem
// address and each non-AVVM address, at input (hash of the address, 0).
// `requires_magic` is the network's RequiresNetworkMagic (false on mainnet),
// which decides whether redeem addresses carry the network magic attribute.
genesis_utxo :: proc(g: ^Genesis, requires_magic: bool, u: ^Utxo) {
	w := cbor.writer(context.temp_allocator)
	magic: Maybe(u32) = g.protocol_magic if requires_magic else nil
	for &e in g.avvm {
		cbor.writer_reset(&w)
		addr := redeem_address(&w, e.key[:], magic)
		utxo_insert(u, genesis_tx_in(addr), addr, e.lovelace)
	}
	for &e in g.non_avvm {
		// The id hashes the address re-encoded, so a non-canonical encoding
		// in the file is normalised first.
		addr := e.address
		if !heads_minimal(addr) {
			cbor.writer_reset(&w)
			r := cbor.reader(addr)
			reencode_address(&w, &r)
			addr = cbor.writer_bytes(&w)
		}
		utxo_insert(u, genesis_tx_in(addr), addr, e.lovelace)
	}
}

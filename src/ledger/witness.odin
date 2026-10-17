package ledger

import "core:crypto/sha3"
import "core:slice"

import "urd:base"
import "urd:cbor"
import "urd:ccrypto"

// Witness sets and auxiliary data, docs/decoding/witnesses-auxdata-byron.md
// §A.1, §A.2, §A.6, §A.7.

Vkey_Witness :: struct {
	vkey: [32]u8,
	sig:  [64]u8,
}

Bootstrap_Witness :: struct {
	vkey:       [32]u8,
	sig:        [64]u8,
	// Address root the witness stands for (bootstrapWitKeyHash).
	key_hash:   base.Hash28,
	chain_code: base.Span,
	attributes: base.Span,
}

Datum :: struct {
	hash:  base.Hash32,
	bytes: base.Span,
}

Redeemer_Tag :: enum u8 {
	Spend   = 0,
	Mint    = 1,
	Cert    = 2,
	Reward  = 3,
	Vote    = 4,
	Propose = 5,
}

Redeemer :: struct {
	tag:   Redeemer_Tag,
	index: u32,
	data:  base.Span,
	ex:    Ex_Units,
}

// Decodes a transaction witness set into the block tables.
read_witness_set :: proc(d: ^Decoder, tx: ^Tx) -> Error {
	t := d.t
	tx.vkey_witnesses.start = u32(len(t.vkey_witnesses))
	tx.bootstrap_wits.start = u32(len(t.bootstrap_wits))
	tx.scripts.start = u32(len(t.scripts))
	tx.datums.start = u32(len(t.datums))
	tx.redeemers.start = u32(len(t.redeemers))

	seen: bit_set[0 ..< 8]
	alonzo := d.era >= .Alonzo
	m := cbor.read_map(&d.r) or_return
	for cbor.more(&d.r, &m) {
		key := cbor.read_uint(&d.r) or_return
		if key > (7 if alonzo else 2) {
			return .Unknown_Key
		}
		if int(key) in seen {
			return .Duplicate_Key
		}
		seen += {int(key)}
		switch key {
		case 0:
			c := read_witness_list(d) or_return
			for cbor.more(&d.r, &c) {
				w: Vkey_Witness
				r := read_rec(d, 2) or_return
				read_fixed(&d.r, w.vkey[:]) or_return
				read_fixed(&d.r, w.sig[:]) or_return
				cbor.end(&d.r, r) or_return
				append(&t.vkey_witnesses, w)
			}
			check_nonempty(d, len(t.vkey_witnesses), int(tx.vkey_witnesses.start)) or_return
		case 1:
			first := len(t.scripts)
			c := read_witness_list(d) or_return
			for cbor.more(&d.r, &c) {
				read_native_script_into(d, &t.scripts) or_return
			}
			check_nonempty(d, len(t.scripts), first) or_return
		case 2:
			c := read_witness_list(d) or_return
			for cbor.more(&d.r, &c) {
				w := read_bootstrap_witness(d) or_return
				append(&t.bootstrap_wits, w)
			}
			check_nonempty(d, len(t.bootstrap_wits), int(tx.bootstrap_wits.start)) or_return
		case 3, 6, 7:
			kind: Script_Kind = .Plutus_V1 if key == 3 else (.Plutus_V2 if key == 6 else .Plutus_V3)
			first := len(t.scripts)
			c := read_witness_list(d) or_return
			for cbor.more(&d.r, &c) {
				read_plutus_script_into(d, kind, &t.scripts) or_return
			}
			if d.v >= 9 {
				if len(t.scripts) == first do return .Empty
				// scriptDecoderV9: a repeated script hash fails.
				xs := t.scripts[first:]
				slice.sort_by(xs, proc(a, b: Script) -> bool {return hash28_less(base.Hash28(a.hash), base.Hash28(b.hash))})
				for i in 1 ..< len(xs) {
					if xs[i].hash == xs[i - 1].hash do return .Duplicate_Key
				}
			}
		case 4:
			start := d.r.pos
			c := read_witness_list(d) or_return
			for cbor.more(&d.r, &c) {
				ds := d.r.pos
				validate_plutus_data(&d.r) or_return
				b := d.r.data[ds:d.r.pos]
				append(&t.datums, Datum{hash = ccrypto.blake2b_256(b), bytes = span(d, b)})
			}
			check_nonempty(d, len(t.datums), int(tx.datums.start)) or_return
			tx.datums_raw = span_from(d, start)
		case 5:
			start := d.r.pos
			read_redeemers(d) or_return
			tx.redeemers_raw = span_from(d, start)
		}
	}

	// Set and map semantics: duplicates collapse (the checks above already
	// rejected the cases where Conway fails on them).
	vk := t.vkey_witnesses[tx.vkey_witnesses.start:]
	slice.sort_by(vk, proc(a, b: Vkey_Witness) -> bool {
		a, b := a, b
		if a.vkey != b.vkey do return string(a.vkey[:]) < string(b.vkey[:])
		return string(a.sig[:]) < string(b.sig[:])
	})
	n := 0
	for i in 0 ..< len(vk) {
		if n > 0 && vk[n - 1] == vk[i] do continue
		vk[n] = vk[i]
		n += 1
	}
	resize(&t.vkey_witnesses, int(tx.vkey_witnesses.start) + n)
	tx.vkey_witnesses.count = u32(n)

	// Bootstrap witnesses are a Set ordered by key hash alone: of equal ones
	// the last decoded is kept.
	// TODO(conformance): Data.Set.fromList keeping the last duplicate is
	// assumed (containers is not in refs/).
	bw := t.bootstrap_wits[tx.bootstrap_wits.start:]
	n = sort_last_wins(bw, proc(a, b: Bootstrap_Witness) -> bool {return hash28_less(a.key_hash, b.key_hash)})
	resize(&t.bootstrap_wits, int(tx.bootstrap_wits.start) + n)
	tx.bootstrap_wits.count = u32(n)

	sc := t.scripts[tx.scripts.start:]
	n = sort_last_wins(sc, proc(a, b: Script) -> bool {return hash28_less(base.Hash28(a.hash), base.Hash28(b.hash))})
	resize(&t.scripts, int(tx.scripts.start) + n)
	tx.scripts.count = u32(n)

	ds := t.datums[tx.datums.start:]
	n = sort_last_wins(ds, proc(a, b: Datum) -> bool {return hash32_less(a.hash, b.hash)})
	resize(&t.datums, int(tx.datums.start) + n)
	tx.datums.count = u32(n)

	rd := t.redeemers[tx.redeemers.start:]
	n = sort_last_wins(rd, proc(a, b: Redeemer) -> bool {
		if a.tag != b.tag do return a.tag < b.tag
		return a.index < b.index
	})
	resize(&t.redeemers, int(tx.redeemers.start) + n)
	tx.redeemers.count = u32(n)
	return .None
}

// A witness list: below v9 a plain list (a tag fails), from v9 an optional
// tag 258 and the list must be non-empty (checked by the caller).
@(private = "file")
read_witness_list :: proc "contextless" (d: ^Decoder) -> (c: cbor.Container, err: Error) {
	if d.v >= 9 {
		allow_tag(d, 258) or_return
	}
	return cbor.read_array(&d.r)
}

@(private = "file")
check_nonempty :: #force_inline proc "contextless" (d: ^Decoder, now, before: int) -> Error {
	if d.v >= 9 && now == before {
		return .Empty
	}
	return .None
}

@(private = "file")
read_bootstrap_witness :: proc(d: ^Decoder) -> (w: Bootstrap_Witness, err: Error) {
	c := read_rec(d, 4) or_return
	read_fixed(&d.r, w.vkey[:]) or_return
	read_fixed(&d.r, w.sig[:]) or_return
	cc := cbor.read_bytes(&d.r) or_return
	attrs := cbor.read_bytes(&d.r) or_return
	cbor.end(&d.r, c) or_return
	w.chain_code = span(d, cc)
	w.attributes = span(d, attrs)
	w.key_hash = bootstrap_key_hash(w.vkey[:], cc, attrs)
	return w, .None
}

// bootstrapWitKeyHash: Blake2b-224(SHA3-256(prefix || key || chain code ||
// attributes)), the prefix encoding [0, [0, bytes(64)]] as Byron addresses do.
bootstrap_key_hash :: proc(vkey, chain_code, attributes: []u8) -> base.Hash28 {
	prefix := [6]u8{0x83, 0x00, 0x82, 0x00, 0x58, 0x40}
	ctx: sha3.Context
	sha3.init_256(&ctx)
	sha3.update(&ctx, prefix[:])
	sha3.update(&ctx, vkey)
	sha3.update(&ctx, chain_code)
	sha3.update(&ctx, attributes)
	digest: [32]u8
	sha3.final(&ctx, digest[:])
	return ccrypto.blake2b_224(digest[:])
}

// Redeemers: below v9 a list (possibly empty) of [tag, index, data, ex];
// from v9 that list (non-empty) or a non-empty map
// { [tag, index] => [data, ex] } whose value is a definite pair.
@(private = "file")
read_redeemers :: proc(d: ^Decoder) -> Error {
	max_tag: u64 = 5 if d.era >= .Conway else 3
	if d.v >= 9 {
		m := cbor.peek_major(&d.r) or_return
		if m == .Map {
			mp := cbor.read_map(&d.r) or_return
			n := 0
			for cbor.more(&d.r, &mp) {
				rd: Redeemer
				k := read_rec(d, 2) or_return
				read_redeemer_purpose(d, &rd, max_tag) or_return
				cbor.end(&d.r, k) or_return
				read_tuple(d, 2) or_return
				read_redeemer_payload(d, &rd) or_return
				append(&d.t.redeemers, rd)
				n += 1
			}
			return .Empty if n == 0 else .None
		}
	}
	l := cbor.read_array(&d.r) or_return
	n := 0
	for cbor.more(&d.r, &l) {
		rd: Redeemer
		c := read_rec(d, 4) or_return
		read_redeemer_purpose(d, &rd, max_tag) or_return
		read_redeemer_payload(d, &rd) or_return
		cbor.end(&d.r, c) or_return
		append(&d.t.redeemers, rd)
		n += 1
	}
	if d.v >= 9 && n == 0 {
		return .Empty
	}
	return .None
}

@(private = "file")
read_redeemer_purpose :: proc "contextless" (d: ^Decoder, rd: ^Redeemer, max_tag: u64) -> Error {
	tag := cbor.read_u8(&d.r) or_return
	if u64(tag) > max_tag {
		return .Invalid_Value
	}
	rd.tag = Redeemer_Tag(tag)
	rd.index = cbor.read_u32(&d.r) or_return
	return .None
}

@(private = "file")
read_redeemer_payload :: proc(d: ^Decoder, rd: ^Redeemer) -> Error {
	start := d.r.pos
	validate_plutus_data(&d.r) or_return
	rd.data = span_from(d, start)
	rd.ex = read_ex_units(d) or_return
	return .None
}

// ---------------------------------------------------------------------------
// Auxiliary data

// Shelley: a metadata map. Allegra/Mary: that, or RecD [metadata, scripts].
// Alonzo onwards: also #6.259({0: metadata, 1: native scripts, 2..: Plutus
// scripts}), where a Plutus key fails unless the decoder version has reached
// that language (V1 5, V2 7, V3 9, V4 12), even with an empty list.
read_aux_data :: proc(d: ^Decoder, tx: ^Tx) -> Error {
	tx.aux_scripts.start = u32(len(d.t.aux_scripts))
	defer tx.aux_scripts.count = u32(len(d.t.aux_scripts)) - tx.aux_scripts.start

	m := cbor.peek_major(&d.r) or_return
	#partial switch m {
	case .Map:
		return read_metadata(d)
	case .Array:
		if d.era < .Allegra do return .Unexpected_Major
		read_recd(d, 2) or_return
		read_metadata(d) or_return
		l := cbor.read_array(&d.r) or_return
		for cbor.more(&d.r, &l) {
			read_native_script_into(d, &d.t.aux_scripts) or_return
		}
		return .None
	case .Tag:
		if d.era < .Alonzo do return .Unexpected_Major
		tag := cbor.read_tag(&d.r) or_return
		if tag != 259 do return .Unexpected_Tag
		seen: bit_set[0 ..< 6]
		mp := cbor.read_map(&d.r) or_return
		for cbor.more(&d.r, &mp) {
			key := cbor.read_uint(&d.r) or_return
			if key > 5 do return .Unknown_Key
			if int(key) in seen do return .Duplicate_Key
			seen += {int(key)}
			switch key {
			case 0:
				read_metadata(d) or_return
			case 1:
				l := cbor.read_array(&d.r) or_return
				for cbor.more(&d.r, &l) {
					read_native_script_into(d, &d.t.aux_scripts) or_return
				}
			case 2, 3, 4, 5:
				min_version := [4]u32{5, 7, 9, 12}
				if d.v < min_version[key - 2] do return .Invalid_Value
				kind := Script_Kind(key - 1)
				l := cbor.read_array(&d.r) or_return
				for cbor.more(&d.r, &l) {
					b := cbor.read_bytes(&d.r) or_return
					append(&d.t.aux_scripts, Script{hash = script_hash(kind, b), kind = kind, bytes = span(d, b)})
				}
			}
		}
		return .None
	}
	return .Unexpected_Major
}

sort_u64 :: proc(xs: []u64) {
	slice.sort(xs)
}

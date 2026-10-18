package byron

import "core:bytes"
import "core:crypto/ed25519"
import "core:encoding/base64"
import "core:encoding/hex"
import "core:fmt"
import "core:hash"
import "core:os"
import "core:slice"
import "core:strings"
import "core:testing"

import "urd:base"
import "urd:cbor"
import "urd:ccrypto"

// Slots per epoch on mainnet and preprod (10k, k = 2160).
EPOCH_SLOTS :: 21600

GOLDEN :: "testdata/byron/golden/"
DINGO :: "testdata/byron/dingo/"

// cardano-ledger's golden files are hex, as dumps with offsets
// ("000: 8507...") when longer than a line.
@(private = "file")
read_golden :: proc(name: string) -> []u8 {
	data, err := os.read_entire_file(fmt.tprintf("%s%s", GOLDEN, name), context.temp_allocator)
	assert(err == nil, name)
	sb := strings.builder_make(context.temp_allocator)
	text := string(data)
	for line in strings.split_lines_iterator(&text) {
		i := strings.index(line, ": ")
		strings.write_string(&sb, strings.trim_space(line[i + 2:] if i >= 0 else line))
	}
	b, ok := hex.decode(transmute([]u8)strings.to_string(sb), context.temp_allocator)
	assert(ok, name)
	return b
}

@(private = "file")
Golden :: struct {
	name:   string,
	decode: proc(d: ^Decoder) -> Error,
}

// Every Byron golden value cardano-ledger encodes and round-trips, decoded
// with the matching reader, which must consume it exactly.
@(test)
test_ledger_goldens :: proc(t: ^testing.T) {
	cases := [?]Golden {
		{"block/Header", proc(d: ^Decoder) -> Error {_, err := read_header(d, EPOCH_SLOTS); return err}},
		{"block/BoundaryBlockHeader", proc(d: ^Decoder) -> Error {_, err := read_ebb_header(&d.r); return err}},
		{"block/Body", proc(d: ^Decoder) -> Error {b: Block; return read_body(d, &b)}},
		{"block/Proof", proc(d: ^Decoder) -> Error {_, err := read_body_proof(&d.r); return err}},
		{"block/BlockSignature", proc(d: ^Decoder) -> Error {_, _, err := read_block_signature(d); return err}},
		{"block/ExtraBodyData", proc(d: ^Decoder) -> Error {
				enforce_size(&d.r, 1) or_return
				return drop_empty_attributes(&d.r)
			}},
		{"block/BoundaryBody", proc(d: ^Decoder) -> Error {
				c := read_list(&d.r) or_return
				for cbor.more(&d.r, &c) do _ = cbor.read_bytes(&d.r) or_return
				return .None
			}},
		{"update/Proposal", proc(d: ^Decoder) -> Error {_, err := read_proposal(d); return err}},
		{"update/Payload", read_update_payload},
		{"update/Vote", proc(d: ^Decoder) -> Error {_, err := read_vote(d); return err}},
		{"update/ProtocolParametersUpdate", proc(d: ^Decoder) -> Error {_, err := read_pparams_update(d); return err}},
		{"update/ProtocolVersion", proc(d: ^Decoder) -> Error {_, err := read_protocol_version(&d.r); return err}},
		{"update/SoftwareVersion", proc(d: ^Decoder) -> Error {_, err := read_software_version(d); return err}},
		{"update/InstallerHash", proc(d: ^Decoder) -> Error {_, err := read_installer_hash(&d.r); return err}},
		{"update/SoftforkRule", proc(d: ^Decoder) -> Error {
				enforce_size(&d.r, 3) or_return
				for _ in 0 ..< 3 do _ = read_lovelace_portion(&d.r) or_return
				return .None
			}},
		{"update/SystemTag", proc(d: ^Decoder) -> Error {_, err := read_text(&d.r); return err}},
		{"update/ApplicationName", proc(d: ^Decoder) -> Error {_, err := read_text(&d.r); return err}},
		{"delegation/Certificate", proc(d: ^Decoder) -> Error {_, err := read_delegation_cert(d); return err}},
		{"delegation/DlgPayload", read_delegation_payload},
		{"utxo/Tx", proc(d: ^Decoder) -> Error {_, err := read_tx(d); return err}},
		{"utxo/TxPayload1", read_tx_payload},
		{"utxo/TxWitness", proc(d: ^Decoder) -> Error {_, _, err := read_witness_list(d); return err}},
		{"utxo/TxInWitness_VKWitness", proc(d: ^Decoder) -> Error {_, err := read_witness(&d.r); return err}},
		{"utxo/TxInWitness_RedeemWitness", proc(d: ^Decoder) -> Error {_, err := read_witness(&d.r); return err}},
		{"utxo/TxIn_Utxo", proc(d: ^Decoder) -> Error {_, err := read_tx_in(&d.r); return err}},
		{"utxo/TxInList", proc(d: ^Decoder) -> Error {
				c := read_list(&d.r) or_return
				for cbor.more(&d.r, &c) do _ = read_tx_in(&d.r) or_return
				return .None
			}},
		{"utxo/TxOut", proc(d: ^Decoder) -> Error {_, err := read_tx_out(d); return err}},
		{"utxo/TxOut1", proc(d: ^Decoder) -> Error {_, err := read_tx_out(d); return err}},
		{"utxo/TxOutList", proc(d: ^Decoder) -> Error {
				c := read_list(&d.r) or_return
				for cbor.more(&d.r, &c) do _ = read_tx_out(d) or_return
				return .None
			}},
		{"utxo/TxAttributes", proc(d: ^Decoder) -> Error {_, err := read_unit_attributes(&d.r); return err}},
		{"common/Attributes", proc(d: ^Decoder) -> Error {_, err := read_unit_attributes(&d.r); return err}},
		{"common/Address", proc(d: ^Decoder) -> Error {_, err := read_address(&d.r); return err}},
		{"common/Address0", proc(d: ^Decoder) -> Error {_, err := read_address(&d.r); return err}},
		{"common/Address1", proc(d: ^Decoder) -> Error {_, err := read_address(&d.r); return err}},
		{"common/Address2", proc(d: ^Decoder) -> Error {_, err := read_address(&d.r); return err}},
		{"common/Address3", proc(d: ^Decoder) -> Error {_, err := read_address(&d.r); return err}},
		{"common/Address4", proc(d: ^Decoder) -> Error {_, err := read_address(&d.r); return err}},
		{"common/TxFeePolicy_Linear", proc(d: ^Decoder) -> Error {_, err := read_tx_fee_policy(d); return err}},
		{"common/TxSizeLinear", proc(d: ^Decoder) -> Error {_, err := read_tx_size_linear(d, &d.r); return err}},
		{"common/Lovelace", proc(d: ^Decoder) -> Error {_, err := read_lovelace(&d.r); return err}},
		{"common/LovelacePortion", proc(d: ^Decoder) -> Error {_, err := read_lovelace_portion(&d.r); return err}},
		{"common/ChainDifficulty", proc(d: ^Decoder) -> Error {
				enforce_size(&d.r, 1) or_return
				_ = cbor.read_uint(&d.r) or_return
				return .None
			}},
		{"slotting/EpochAndSlotCount", proc(d: ^Decoder) -> Error {
				enforce_size(&d.r, 2) or_return
				_ = cbor.read_uint(&d.r) or_return
				_ = cbor.read_uint(&d.r) or_return
				return .None
			}},
		{"ssc/SscPayload_CommitmentsPayload", proc(d: ^Decoder) -> Error {return drop_ssc_payload(&d.r)}},
		{"ssc/SscPayload_OpeningsPayload", proc(d: ^Decoder) -> Error {return drop_ssc_payload(&d.r)}},
		{"ssc/SscPayload_SharesPayload", proc(d: ^Decoder) -> Error {return drop_ssc_payload(&d.r)}},
		{"ssc/SscPayload_CertificatesPayload", proc(d: ^Decoder) -> Error {return drop_ssc_payload(&d.r)}},
		{"ssc/SscProof_CommitmentsProof", proc(d: ^Decoder) -> Error {return drop_ssc_proof(&d.r)}},
		{"ssc/SscProof_OpeningsProof", proc(d: ^Decoder) -> Error {return drop_ssc_proof(&d.r)}},
		{"ssc/SscProof_SharesProof", proc(d: ^Decoder) -> Error {return drop_ssc_proof(&d.r)}},
		{"ssc/SscProof_CertificatesProof", proc(d: ^Decoder) -> Error {return drop_ssc_proof(&d.r)}},
	}

	tables: Tables
	tables_init(&tables)
	defer tables_destroy(&tables)
	for c in cases {
		data := read_golden(c.name)
		tables_reset(&tables)
		d := Decoder {
			r    = cbor.reader(data),
			base = data,
			t    = &tables,
		}
		err := c.decode(&d)
		if err == .None do err = cbor.expect_end(&d.r)
		testing.expectf(t, err == .None, "%s: %v at %d", c.name, err, d.r.pos)

		// The goldens are the Haskell encoder's output, so every transaction
		// in them is canonical and re-encodes to the same bytes.
		for &tx in tables.txs {
			check_canonical_tx(t, c.name, base.span_bytes(data, tx.body))
		}
	}
	free_all(context.temp_allocator)
}

@(test)
test_golden_values :: proc(t: ^testing.T) {
	tables: Tables
	tables_init(&tables)
	defer tables_destroy(&tables)

	data := read_golden("common/TxSizeLinear")
	d := Decoder {
		r    = cbor.reader(data),
		base = data,
		t    = &tables,
	}
	f, err := read_tx_size_linear(&d, &d.r)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, f.a, 99)
	testing.expect_value(t, f.b.small, 777_000_000_000)

	data = read_golden("utxo/Tx")
	d = Decoder {
		r    = cbor.reader(data),
		base = data,
		t    = &tables,
	}
	tx, terr := read_tx(&d)
	testing.expect_value(t, terr, Error.None)
	testing.expect_value(t, tx.inputs.count, 1)
	testing.expect_value(t, tables.inputs[0].index, 47)
	testing.expect_value(t, tables.outputs[0].lovelace, 47)
	testing.expect_value(t, tables.outputs[0].address.type, Addr_Type.Ver_Key)

	// Address3 carries a derivation path, network magic 9973261 and no
	// unknown attributes.
	data = read_golden("common/Address3")
	a, aerr := parse_address(data)
	testing.expect_value(t, aerr, Error.None)
	testing.expect(t, a.has_magic)
	testing.expect_value(t, a.magic, 9973261)
	testing.expect_value(t, a.unknown_attrs_len, 0)
	free_all(context.temp_allocator)
}

@(private = "file")
check_canonical_tx :: proc(t: ^testing.T, name: string, body: []u8) {
	testing.expectf(t, heads_minimal(body), "%s: transaction not canonical", name)
	w := cbor.writer(context.temp_allocator)
	reencode_tx(&w, body)
	testing.expectf(t, bytes.equal(cbor.writer_bytes(&w), body), "%s: re-encoding differs", name)
}

// ---------------------------------------------------------------------------
// Transaction ids of non-canonical transactions

// Writes `body` (a decoded transaction) back with every head the decoder
// accepts in a non-minimal form widened to 8 bytes, keeping the canonical
// points canonical (address type, attribute values) and recomputing address
// CRCs so the result still decodes.
@(private = "file")
denormalize_tx :: proc(w: ^cbor.Writer, body: []u8) {
	wide :: proc(w: ^cbor.Writer, major: cbor.Major, arg: u64) {
		append(&w.buf, u8(major) << 5 | 27)
		for i := 7; i >= 0; i -= 1 do append(&w.buf, u8(arg >> uint(8 * i)))
	}
	wide_bytes :: proc(w: ^cbor.Writer, b: []u8) {
		wide(w, .Bytes, u64(len(b)))
		append(&w.buf, ..b)
	}
	attributes :: proc(w: ^cbor.Writer, r: ^cbor.Reader) {
		c, _ := cbor.read_map(r)
		wide(w, .Map, u64(c.n))
		for _ in 0 ..< c.n {
			key, _ := cbor.read_uint(r)
			value, _ := cbor.read_bytes(r)
			wide(w, .Unsigned, key)
			wide_bytes(w, value)
		}
	}

	r := cbor.reader(body)
	_, _ = cbor.read_array(&r)
	wide(w, .Array, 3)

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

		inner := cbor.writer(context.temp_allocator)
		wide(&inner, .Array, 2)
		wide_bytes(&inner, id)
		wide(&inner, .Unsigned, index)
		wide(w, .Array, 2)
		wide(w, .Unsigned, 0)
		wide(w, .Tag, 24)
		wide_bytes(w, cbor.writer_bytes(&inner))
	}
	cbor.write_break(w)

	c, _ = cbor.read_array(&r)
	cbor.write_array_indefinite(w)
	for cbor.more(&r, &c) {
		_, _ = cbor.read_array(&r)
		_, _ = cbor.read_array(&r)
		payload, _ := read_nested(&r)
		_, _ = cbor.read_uint(&r)
		lovelace, _ := cbor.read_uint(&r)

		p := cbor.reader(payload)
		_, _ = cbor.read_array(&p)
		root, _ := cbor.read_bytes(&p)
		inner := cbor.writer(context.temp_allocator)
		wide(&inner, .Array, 3)
		wide_bytes(&inner, root)
		attributes(&inner, &p)
		type, _ := cbor.read_uint(&p)
		cbor.write_uint(&inner, type) // decodeWord8Canonical

		wide(w, .Array, 2)
		wide(w, .Array, 2)
		wide(w, .Tag, 24)
		wide_bytes(w, cbor.writer_bytes(&inner))
		wide(w, .Unsigned, u64(hash.crc32(cbor.writer_bytes(&inner))))
		wide(w, .Unsigned, lovelace)
	}
	cbor.write_break(w)
	attributes(w, &r)
}

// The id of a transaction received with non-minimal heads is the hash of its
// canonical re-encoding, not of the bytes received.
@(test)
test_noncanonical_tx_id :: proc(t: ^testing.T) {
	tables: Tables
	tables_init(&tables)
	defer tables_destroy(&tables)

	for name in ([]string{"utxo/Tx", "block/Body", "utxo/TxPayload1"}) {
		data := read_golden(name)
		d := Decoder {
			r    = cbor.reader(data),
			base = data,
			t    = &tables,
		}
		tables_reset(&tables)
		switch name {
		case "utxo/Tx":
			tx, err := read_tx(&d)
			testing.expect_value(t, err, Error.None)
			append(&tables.txs, tx)
		case "block/Body":
			b: Block
			testing.expect_value(t, read_body(&d, &b), Error.None)
		case:
			testing.expect_value(t, read_tx_payload(&d), Error.None)
		}
		testing.expect(t, len(tables.txs) > 0, name)
		bodies := make([][]u8, len(tables.txs), context.temp_allocator)
		for &tx, i in tables.txs do bodies[i] = base.span_bytes(data, tx.body)

		for body in bodies {
			want := ccrypto.blake2b_256(body)
			w := cbor.writer(context.temp_allocator)
			denormalize_tx(&w, body)
			wire := cbor.writer_bytes(&w)
			testing.expect(t, len(wire) > len(body), name)
			testing.expect(t, !heads_minimal(wire), name)

			// It still decodes, and its id is the canonical one.
			tables_reset(&tables)
			nd := Decoder {
				r    = cbor.reader(wire),
				base = wire,
				t    = &tables,
			}
			_, err := read_tx(&nd)
			testing.expectf(t, err == .None, "%s: %v", name, err)
			testing.expect(t, cbor.at_end(&nd.r), name)
			id, canonical := tx_id(&tables, wire)
			testing.expectf(t, base.Hash32(id) == want && !canonical, "%s: id differs", name)
		}
	}
	free_all(context.temp_allocator)
}

// ---------------------------------------------------------------------------
// Fee policy rounding

@(test)
test_nano_round :: proc(t: ^testing.T) {
	d: Decoder
	small :: proc(d: ^Decoder, v: u64, negative := false) -> u64 {
		return nano_round_word64(d, Nano{small = v, negative = negative})
	}
	testing.expect_value(t, small(&d, 99_000_000_000), 99)
	testing.expect_value(t, small(&d, 1_499_999_999), 1)
	testing.expect_value(t, small(&d, 1_500_000_000), 2) // half to even
	testing.expect_value(t, small(&d, 2_500_000_000), 2)
	testing.expect_value(t, small(&d, 2_500_000_001), 3)
	testing.expect_value(t, small(&d, 0, true), 0)                        // -1e-9
	testing.expect_value(t, small(&d, 1_499_999_999, true), max(u64) - 1) // -1.5 -> -2
	testing.expect_value(t, small(&d, 2_499_999_999, true), max(u64) - 1) // -2.5 -> -2

	// Bignums: (2^64 + q) * 10^9 + r keeps q modulo 2^64.
	big :: proc(t: ^testing.T, mag: []u8, negative: bool, want: u64) {
		d := Decoder {
			base = mag,
		}
		got := nano_round_word64(&d, Nano{big = base.span_of(mag, mag), negative = negative})
		testing.expectf(t, got == want, "%x: %d != %d", mag, got, want)
	}
	// 2^64 * 10^9 + 5 * 10^8 = 0x3b9aca00_00000000_00000000 + 0x1dcd6500
	big(t, []u8{0x3b, 0x9a, 0xca, 0x00, 0, 0, 0, 0, 0x1d, 0xcd, 0x65, 0x00}, false, 0)
	// (2^64 + 1) * 10^9 + 5 * 10^8
	big(t, []u8{0x3b, 0x9a, 0xca, 0x00, 0, 0, 0, 0, 0x59, 0x68, 0x2f, 0x00}, false, 2)
	// -1 - (2^64 * 10^9 + 5 * 10^8 - 1) = -(2^64 + 0.5) -> -2^64 -> 0
	big(t, []u8{0x3b, 0x9a, 0xca, 0x00, 0, 0, 0, 0, 0x1d, 0xcd, 0x64, 0xff}, true, 0)
}

// ---------------------------------------------------------------------------
// Real chains

// The whole preprod Byron era as served by a relay (dingo's fixture): the
// genesis EBB and 45 main blocks, as [type, block] pairs.
@(test)
test_preprod_byron_chain :: proc(t: ^testing.T) {
	data, err := os.read_entire_file(DINGO + "preprod-byron-chain.cbor", context.temp_allocator)
	testing.expect(t, err == nil)
	r := cbor.reader(data)
	n, aerr := read_array_definite(&r)
	testing.expect_value(t, aerr, Error.None)
	testing.expect_value(t, n, 46)

	tables: Tables
	tables_init(&tables)
	defer tables_destroy(&tables)
	outputs := make(map[base.Tx_Id]u32, context.temp_allocator)
	b: Block
	prev: base.Block_Hash
	txs, inchain, certs, proposals, votes := 0, 0, 0, 0, 0
	for i in 0 ..< n {
		_ = enforce_size(&r, 2)
		type, _ := cbor.read_uint(&r)
		block, _ := cbor.read_bytes(&r)
		is_ebb := type == 0
		derr := decode_block(block, is_ebb, EPOCH_SLOTS, &tables, &b)
		if !testing.expectf(t, derr == .None, "block %d: %v", i, derr) do return
		if is_ebb {
			testing.expectf(t, i == 0 && b.ebb.prev_is_genesis, "block %d: unexpected EBB", i)
		} else {
			testing.expectf(t, b.main.prev == prev, "block %d: does not extend its predecessor", i)
			testing.expectf(t, proof_matches(&b), "block %d: body proof mismatch", i)
			testing.expect_value(t, b.main.protocol_magic, 1)
			testing.expect_value(t, b.main.difficulty, u64(i))
		}
		prev = b.hash
		for &tx in tables.txs {
			check_canonical_tx(t, "preprod", base.span_bytes(block, tx.body))
			for k in tx.inputs.start ..< base.range_end(tx.inputs) {
				in_ := tables.inputs[k]
				if count, ok := outputs[in_.id]; ok {
					inchain += 1
					testing.expect(t, u32(in_.index) < count)
				}
			}
			outputs[tx.id] = tx.outputs.count
		}
		txs += len(tables.txs)
		certs += len(tables.certs)
		proposals += len(tables.proposals)
		votes += len(tables.votes)
	}
	testing.expect(t, cbor.at_end(&r))
	// The last block is the one before the Shelley hard fork.
	testing.expect_value(t, b.main.slot, 84242)
	// The hard fork to Shelley was voted on chain.
	testing.expect(t, proposals > 0 && votes > 0)
	fmt.printfln(
		"preprod Byron: %d txs (%d inputs spend earlier txs), %d certificates, %d proposals, %d votes",
		txs,
		inchain,
		certs,
		proposals,
		votes,
	)
	free_all(context.temp_allocator)
}

// Single mainnet and preprod main blocks (the era block, without envelope),
// named by slot.
@(test)
test_dingo_blocks :: proc(t: ^testing.T) {
	Case :: struct {
		file:  string,
		slot:  base.Slot,
		magic: u32,
	}
	tables: Tables
	tables_init(&tables)
	defer tables_destroy(&tables)
	for c in ([]Case{{"mainnet-byron-4471207.cbor", 4471207, 764824073}, {"mainnet-byron-last-4492799.cbor", 4492799, 764824073}, {"preprod-byron-last-84242.cbor", 84242, 1}}) {
		block, err := os.read_entire_file(fmt.tprintf("%s%s", DINGO, c.file), context.temp_allocator)
		testing.expect(t, err == nil, c.file)
		b: Block
		derr := decode_block(block, false, EPOCH_SLOTS, &tables, &b)
		testing.expectf(t, derr == .None, "%s: %v", c.file, derr)
		testing.expectf(t, proof_matches(&b), "%s: body proof mismatch", c.file)
		testing.expect_value(t, b.main.slot, c.slot)
		testing.expect_value(t, b.main.protocol_magic, c.magic)
		for &tx in tables.txs {
			check_canonical_tx(t, c.file, base.span_bytes(block, tx.body))
		}
	}
	free_all(context.temp_allocator)
}

// Every signature in the real Byron fixtures: block signatures, the delegation
// certificates in headers, transaction witnesses, proposals and votes. Each
// header's own protocol magic stands in for the configuration's (the pallas
// blocks come from mainnet, the legacy testnet and preprod).
@(test)
test_signatures :: proc(t: ^testing.T) {
	tables: Tables
	tables_init(&tables)
	defer tables_destroy(&tables)

	blocks := make([dynamic][]u8, context.temp_allocator)
	data, err := os.read_entire_file(DINGO + "preprod-byron-chain.cbor", context.temp_allocator)
	testing.expect(t, err == nil)
	r := cbor.reader(data)
	n, _ := read_array_definite(&r)
	for _ in 0 ..< n {
		_ = enforce_size(&r, 2)
		type, _ := cbor.read_uint(&r)
		block, _ := cbor.read_bytes(&r)
		if type == 1 do append(&blocks, block)
	}
	for f in ([]string{"mainnet-byron-4471207.cbor", "mainnet-byron-last-4492799.cbor"}) {
		block, _ := os.read_entire_file(fmt.tprintf("%s%s", DINGO, f), context.temp_allocator)
		append(&blocks, block)
	}
	for i in 1 ..= 8 {
		text, _ := os.read_entire_file(fmt.tprintf("testdata/blocks/pallas/byron%d.block", i), context.temp_allocator)
		raw, _ := hex.decode(transmute([]u8)strings.trim_space(string(text)), context.temp_allocator)
		// [1, block]: a main block in the hard-fork envelope.
		br := cbor.reader(raw)
		_ = enforce_size(&br, 2)
		tag, _ := cbor.read_uint(&br)
		testing.expect_value(t, tag, 1)
		append(&blocks, br.data[br.pos:])
	}

	counts: [5]int // blocks, witnesses, proposals, votes, payload certificates
	for block, i in blocks {
		b: Block
		derr := decode_block(block, false, EPOCH_SLOTS, &tables, &b)
		if !testing.expectf(t, derr == .None, "block %d: %v", i, derr) do continue
		magic := b.main.protocol_magic
		header := base.span_bytes(block, b.header)
		testing.expectf(t, verify_block_signature(&b.main, header, magic), "block %d: block signature", i)
		testing.expectf(t, verify_certificate(&b.main.cert, header, magic), "block %d: header certificate", i)
		counts[0] += 1
		for &tx in tables.txs {
			h := ccrypto.blake2b_256(base.span_bytes(block, tx.body))
			for k in tx.witnesses.start ..< base.range_end(tx.witnesses) {
				testing.expectf(t, verify_tx_witness(&tables.witnesses[k], h, magic), "block %d: witness %d", i, k)
				counts[1] += 1
			}
		}
		for &p in tables.proposals {
			testing.expectf(t, verify_proposal(&p, block, magic), "block %d: proposal", i)
			counts[2] += 1
		}
		for &v in tables.votes {
			testing.expectf(t, verify_vote(&v, block, magic), "block %d: vote", i)
			counts[3] += 1
		}
		for &c in tables.certs {
			testing.expectf(t, verify_certificate(&c, block, magic), "block %d: certificate", i)
			counts[4] += 1
		}

		// A flipped bit in the signed bytes breaks the block signature.
		tampered := make([]u8, len(header), context.temp_allocator)
		copy(tampered, header)
		tampered[b.main.difficulty_raw.off + 1] ~= 1
		testing.expectf(t, !verify_block_signature(&b.main, tampered, magic), "block %d: tampered header verifies", i)
	}
	testing.expect_value(t, counts, [5]int{55, 59, 4, 22, 0})
	free_all(context.temp_allocator)
}

GENESIS :: "testdata/byron/genesis/"

@(private = "file")
load_genesis :: proc(t: ^testing.T, name: string) -> (g: Genesis, ok: bool) {
	data, err := os.read_entire_file(fmt.tprintf("%s%s", GENESIS, name), context.temp_allocator)
	if !testing.expect(t, err == nil, name) do return g, false
	gerr: Genesis_Error
	g, gerr = genesis_parse(data, context.temp_allocator)
	return g, testing.expectf(t, gerr == .None, "%s: %v", name, gerr)
}

@(test)
test_genesis :: proc(t: ^testing.T) {
	Case :: struct {
		file:     string,
		// ByronGenesisHash in the network's node configuration.
		hash:     string,
		magic:    u32,
		avvm:     u64,
		non_avvm: int,
	}
	w := cbor.writer(context.temp_allocator)
	for c in ([]Case{{"mainnet.json", "5f20df933584822601f9e3f8c024eb5eb252fe8cefb24d1317dc3d432e940ebb", 764824073, 31_112_484_745_000_000, 0}, {"preprod.json", "d4b8de7a11d929a323373cbab6c1a9bdc931beffff11db111cf9d57356ee1937", 1, 0, 8}}) {
		g, ok := load_genesis(t, c.file)
		if !ok do continue
		want, _ := hex.decode(transmute([]u8)c.hash, context.temp_allocator)
		testing.expectf(t, bytes.equal(g.hash[:], want), "%s: genesis hash %x", c.file, g.hash)
		testing.expect_value(t, g.protocol_magic, c.magic)
		testing.expect_value(t, g.k, 2160)
		testing.expect_value(t, epoch_slots(&g), 21600)
		testing.expect_value(t, g.params.tx_fee_policy.a, 155381)
		testing.expect_value(t, g.params.tx_fee_policy.b.small, 43_946_000_000)
		testing.expect_value(t, len(g.non_avvm), c.non_avvm)

		// Every genesis key delegates once, with a valid certificate.
		testing.expect_value(t, len(g.genesis_keys), 7)
		testing.expect_value(t, len(g.delegations), 7)
		for &d in g.delegations {
			testing.expectf(t, verify_genesis_delegation(&d, g.protocol_magic), "%s: genesis certificate", c.file)
			kh := vkey_hash(&d.issuer)
			found := false
			for k in g.genesis_keys do found ||= k == kh
			testing.expectf(t, found, "%s: delegation issuer is not a genesis key", c.file)
		}

		avvm: u64
		for &e in g.avvm {
			cbor.writer_reset(&w)
			addr := redeem_address(&w, e.key[:], nil)
			a, aerr := parse_address(addr)
			testing.expect_value(t, aerr, Error.None)
			testing.expect_value(t, a.type, Addr_Type.Redeem)
			avvm += e.lovelace
		}
		testing.expect_value(t, avvm, c.avvm)
		if c.magic == 764824073 {
			// docs/rules/byron-genesis.md: this key's genesis input.
			key, _ := base64.decode(
				"-0BJDi-gauylk4LptQTgjMeo7kY9lTCbZv12vwOSTZk=",
				base64.DEC_URL_TABLE,
				allocator = context.temp_allocator,
			)
			cbor.writer_reset(&w)
			txin := genesis_tx_in(redeem_address(&w, key, nil))
			want_id, _ := hex.decode(
				transmute([]u8)string("8ee33c9906974706223d7d500d63bbee2369d7150f972757a9fdded2f706b938"),
				context.temp_allocator,
			)
			testing.expect(t, bytes.equal(txin.id[:], want_id) && txin.index == 0)
		}
		for &e in g.non_avvm {
			a, aerr := parse_address(e.address)
			testing.expect_value(t, aerr, Error.None)
			testing.expect(t, a.has_magic && a.magic == c.magic)
		}
	}
	free_all(context.temp_allocator)
}

@(test)
test_tx_min_fee :: proc(t: ^testing.T) {
	f := Tx_Size_Linear {
		a = 155381,
		b = Nano{small = 43_946_000_000},
	}
	fee, ok := tx_min_fee(&f, nil, 200)
	testing.expect(t, ok)
	testing.expect_value(t, fee, 155381 + 8790) // 200 * 43.946 = 8789.2, rounded up
	fee, ok = tx_min_fee(&f, nil, 0)
	testing.expect_value(t, fee, 155381)
	// A negative product wraps to a huge Word64, which `addLovelace` rejects.
	neg := Tx_Size_Linear {
		a = 1000,
		b = Nano{small = 1_499_999_999, negative = true}, // -1.5
	}
	_, ok = tx_min_fee(&neg, nil, 3)
	testing.expect(t, !ok)
	_, ok = tx_min_fee(&neg, nil, 0) // ceiling(0) = 0
	testing.expect(t, ok)
	// The largest small multiplier: ceiling(4096 * (2^64 - 1) / 10^9).
	large := Tx_Size_Linear {
		b = Nano{small = max(u64)},
	}
	fee, ok = tx_min_fee(&large, nil, 4096)
	testing.expect(t, ok && fee == 75_557_863_725_915)
	// A bignum multiplier of exactly 2^64 lovelace per byte scales to 2^64,
	// which `fromInteger` wraps to 0.
	mag := [12]u8{0x3b, 0x9a, 0xca, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	wrap := Tx_Size_Linear {
		a = 7,
		b = Nano{big = base.Span{off = 0, len = 12}},
	}
	fee, ok = tx_min_fee(&wrap, mag[:], 1)
	testing.expect(t, ok && fee == 7)
	over := Tx_Size_Linear {
		a = MAX_LOVELACE,
		b = Nano{small = 1_000_000_000},
	}
	_, ok = tx_min_fee(&over, nil, 1)
	testing.expect(t, !ok)
}

// A real block's transactions over a synthetic UTxO: each input with a
// witness gets the address of that witness's key (empty attributes), and the
// first input carries enough value for the outputs and the minimum fee.
@(private = "file")
Utxo_Fixture :: struct {
	block:  []u8,
	magic:  u32,
	tables: Tables,
	b:      Block,
}

@(private = "file")
synth_utxo :: proc(f: ^Utxo_Fixture, env: ^Utxo_Env, u: ^Utxo, skip_input := -1, wrong_key := -1, short := false) {
	w := cbor.writer(context.temp_allocator)
	ids := make(map[base.Tx_Id]bool, context.temp_allocator)
	for &tx in f.tables.txs do ids[tx.id] = true
	k := 0
	for &tx in f.tables.txs {
		outputs: u64
		for &out in f.tables.outputs[tx.outputs.start:base.range_end(tx.outputs)] do outputs += out.lovelace
		fee, _ := tx_min_fee(&env.fee_policy, nil, tx.aux.len)
		for i in 0 ..< tx.inputs.count {
			txin := f.tables.inputs[tx.inputs.start + i]
			defer k += 1
			if ids[txin.id] || k == skip_input do continue // produced in the block
			if _, present := u.entries[txin]; present do continue
			key: []u8
			type := Addr_Type.Ver_Key
			if i < tx.witnesses.count {
				wit := &f.tables.witnesses[tx.witnesses.start + i]
				key = wit.key[:] if wit.kind == .Ver_Key else wit.key[:32]
				type = .Ver_Key if wit.kind == .Ver_Key else .Redeem
			} else {
				key = make([]u8, 64, context.temp_allocator)
			}
			if k == wrong_key {
				other := make([]u8, len(key), context.temp_allocator)
				copy(other, key)
				other[0] ~= 1
				key = other
			}
			cbor.writer_reset(&w)
			attrs := [1]u8{0xa0}
			root := address_root(type, key, attrs[:])
			cbor.write_array(&w, 2)
			m := cbor.embedded_begin(&w)
			cbor.write_array(&w, 3)
			cbor.write_bytes(&w, root[:])
			cbor.write_raw(&w, attrs[:])
			cbor.write_uint(&w, u64(type))
			payload_len := len(w.buf) - m - 9
			cbor.embedded_end(&w, m)
			cbor.write_uint(&w, u64(hash.crc32(w.buf[len(w.buf) - payload_len:])))
			value: u64 = 0
			if i == 0 do value = outputs + fee - (1 if short else 0)
			utxo_insert(u, txin, cbor.writer_bytes(&w), value)
		}
	}
}

@(test)
test_utxo_rules :: proc(t: ^testing.T) {
	fixtures := make([dynamic]Utxo_Fixture, context.temp_allocator)
	for i in ([]int{2, 4, 5, 6, 7}) {
		text, _ := os.read_entire_file(fmt.tprintf("testdata/blocks/pallas/byron%d.block", i), context.temp_allocator)
		raw, _ := hex.decode(transmute([]u8)strings.trim_space(string(text)), context.temp_allocator)
		br := cbor.reader(raw)
		_ = enforce_size(&br, 2)
		_, _ = cbor.read_uint(&br)
		append(&fixtures, Utxo_Fixture{block = br.data[br.pos:]})
	}
	block, _ := os.read_entire_file(DINGO + "mainnet-byron-4471207.cbor", context.temp_allocator)
	append(&fixtures, Utxo_Fixture{block = block})

	o: Utxo_Overlay
	utxo_overlay_init(&o)
	defer utxo_overlay_destroy(&o)
	for &f, fi in fixtures {
		tables_init(&f.tables)
		defer tables_destroy(&f.tables)
		testing.expect_value(t, decode_block(f.block, false, EPOCH_SLOTS, &f.tables, &f.b), Error.None)
		magic := f.b.main.protocol_magic
		base_env := Utxo_Env {
			protocol_magic = magic,
			requires_magic = magic != 764824073,
			// Mainnet raised maxTxSize from 4096 to 65536 during Byron.
			max_tx_size = Natural{small = 65536},
			fee_policy = Tx_Size_Linear{a = 155381, b = Nano{small = 43_946_000_000}},
		}

		Case :: struct {
			name: string,
			want: Utxo_Error,
		}
		cases := [?]Case {
			{"valid", .None},
			{"missing input", .Missing_Input},
			{"wrong witness key", .Witness_Key},
			{"bad witness signature", .Witness_Signature},
			{"tx too large", .Tx_Too_Large},
			{"fee too small", .Fee_Too_Small},
			{"wrong network", .Network_Magic},
			{"overlapping output", .Overlapping_Union},
		}
		for c in cases {
			env := base_env
			u: Utxo
			utxo_init(&u, context.temp_allocator)
			switch c.name {
			case "missing input":
				synth_utxo(&f, &env, &u, skip_input = 0)
			case "wrong witness key":
				synth_utxo(&f, &env, &u, wrong_key = 0)
			case "fee too small":
				synth_utxo(&f, &env, &u, short = true)
			case "tx too large":
				synth_utxo(&f, &env, &u)
				env.max_tx_size = Natural {
					small = u64(f.tables.txs[0].aux.len) - 1,
				}
			case "wrong network":
				synth_utxo(&f, &env, &u)
				env.requires_magic = !env.requires_magic
			case "overlapping output":
				synth_utxo(&f, &env, &u)
				utxo_insert(&u, base.Tx_In{id = f.tables.txs[0].id, index = 0}, nil, 0)
			case:
				synth_utxo(&f, &env, &u)
			}
			before := u.total
			saved: Signature
			if c.name == "bad witness signature" {
				saved = f.tables.witnesses[0].sig
				f.tables.witnesses[0].sig[5] ~= 1
			}
			err, failed := utxo_apply_block(&env, &u, &o, &f.tables, f.block)
			if c.name == "bad witness signature" do f.tables.witnesses[0].sig = saved
			testing.expectf(t, err == c.want, "fixture %d, %s: %v (tx %d)", fi, c.name, err, failed)
			if c.want != .None {
				testing.expectf(t, u.total == before, "fixture %d, %s: UTxO changed", fi, c.name)
				continue
			}
			// The block spent what it consumed and kept every unspent output;
			// applying it again finds its inputs gone.
			fees: u64
			for &tx in f.tables.txs {
				fee, _ := tx_min_fee(&env.fee_policy, nil, tx.aux.len)
				fees += fee
			}
			testing.expectf(t, u.total == before - fees, "fixture %d: %d != %d - %d", fi, u.total, before, fees)
			err, _ = utxo_apply_block(&env, &u, &o, &f.tables, f.block)
			testing.expect_value(t, err, Utxo_Error.Missing_Input)
		}
	}
	free_all(context.temp_allocator)
}

// The whole preprod Byron chain through full validation from its genesis:
// every block is accepted, version 1.0.0 is adopted at epoch 2, 2.0.0
// becomes a candidate at slot 56163, and the chain knows Shelley starts at
// epoch 4 (docs/rules/byron-delegation-update.md §2.11).
// Compaction must move every surviving address. Mainnet epoch 9 crashed on
// the first compaction when it left most entries pointing into the old arena.
@(test)
test_utxo_compaction :: proc(t: ^testing.T) {
	u: Utxo
	utxo_init(&u)
	defer utxo_destroy(&u)
	N :: 30_000
	address :: proc(i: int) -> (a: [64]u8) {
		for &b, j in a do b = u8(i * 31 + j)
		return
	}
	txin :: proc(i: int) -> (x: base.Tx_In) {
		x.id[0], x.id[1], x.index = u8(i), u8(i >> 8), u16(i >> 16)
		return
	}
	for i in 0 ..< N {
		a := address(i)
		utxo_insert(&u, txin(i), a[:], u64(i))
	}
	// Spend two thirds: more than 1 MiB and more than half the arena dies.
	for i in 0 ..< N do if i % 3 != 0 do utxo_remove(&u, txin(i))
	utxo_maybe_compact(&u)
	testing.expect_value(t, u.dead, 0)
	testing.expect_value(t, len(u.addrs), N / 3 * 64)
	for i := 0; i < N; i += 3 {
		e, ok := utxo_get(&u, txin(i))
		a := address(i)
		if !testing.expect(t, ok && string(utxo_address(&u, e)) == string(a[:]), fmt.tprintf("entry %d", i)) do break
	}
}

@(test)
test_preprod_replay :: proc(t: ^testing.T) {
	g, ok := load_genesis(t, "preprod.json")
	if !ok do return
	c: Chain
	testing.expect_value(
		t,
		chain_init(&c, &g, requires_magic = true, allocator = context.temp_allocator),
		Delegation_Error.None,
	)

	data, err := os.read_entire_file(DINGO + "preprod-byron-chain.cbor", context.temp_allocator)
	testing.expect(t, err == nil)
	r := cbor.reader(data)
	n, _ := read_array_definite(&r)
	tables: Tables
	tables_init(&tables)
	defer tables_destroy(&tables)
	for i in 0 ..< n {
		_ = enforce_size(&r, 2)
		type, _ := cbor.read_uint(&r)
		block, _ := cbor.read_bytes(&r)
		b: Block
		testing.expect_value(t, decode_block(block, type == 0, epoch_slots(&g), &tables, &b), Error.None)
		cerr := chain_apply(&c, block, &b, &tables)
		if !testing.expectf(t, cerr.kind == .None, "block %d: %v", i, cerr) do return
		if i == 22 {
			testing.expect_value(t, c.update.adopted_version, Protocol_Version{1, 0, 0})
		}
	}
	testing.expect_value(t, c.last_slot, 84242)
	testing.expect_value(t, c.update.adopted_version, Protocol_Version{1, 0, 0})
	testing.expect(t, len(c.update.candidates) == 1 && c.update.candidates[0].slot == 56163)
	testing.expect_value(t, c.update.candidates[0].version, Protocol_Version{2, 0, 0})
	epoch, known := chain_transition_epoch(&c)
	testing.expect(t, known && epoch == 4)
	// Nothing was spent: the genesis UTxO is intact.
	testing.expect_value(t, utxo_len(&c.utxo), 8)
	testing.expect_value(t, c.utxo.total, 30_000_000_000_000_000)
	free_all(context.temp_allocator)
}

// ---------------------------------------------------------------------------
// Delegation rules over keys the test controls

@(private = "file")
Test_Key :: struct {
	priv: ed25519.Private_Key,
	xpub: Vkey,
	hash: base.Key_Hash,
}

@(private = "file")
test_key :: proc(seed: u8) -> (k: Test_Key) {
	s: [32]u8
	s[0] = seed
	_ = ed25519.private_key_set_bytes(&k.priv, s[:])
	ed25519.private_key_public_bytes(&k.priv, k.xpub[:32])
	k.xpub[32] = seed // chain code: part of the key hash, not of verification
	k.hash = vkey_hash(&k.xpub)
	return
}

// A certificate from `issuer` to `delegate` for `epoch`, signed over
// 0x0a ‖ magic ‖ bytes("00" ‖ delegate ‖ epoch). Its epoch bytes go to `buf`.
@(private = "file")
test_cert :: proc(
	issuer, delegate: ^Test_Key,
	epoch: u64,
	magic: u32,
	buf: ^[dynamic]u8,
	bad_sig := false,
) -> Delegation_Cert {
	c := Delegation_Cert {
		issuer   = issuer.xpub,
		delegate = delegate.xpub,
		epoch    = epoch,
	}
	start := len(buf)
	head: [9]u8
	append(buf, ..head[:cbor.put_head(head[:], .Unsigned, epoch)])
	c.epoch_raw = base.Span {
		off = u32(start),
		len = u32(len(buf) - start),
	}
	msg := make([dynamic]u8, context.temp_allocator)
	append(&msg, 0x0a)
	append(&msg, ..head[:cbor.put_head(head[:], .Unsigned, u64(magic))])
	append(&msg, ..head[:cbor.put_head(head[:], .Bytes, u64(66 + c.epoch_raw.len))])
	append(&msg, "00")
	append(&msg, ..delegate.xpub[:])
	append(&msg, ..buf[start:])
	ed25519.sign(&issuer.priv, msg[:], c.sig[:])
	if bad_sig do c.sig[0] ~= 1
	return c
}

@(test)
test_delegation_rules :: proc(t: ^testing.T) {
	MAGIC :: 42
	K :: 10
	genesis := [3]Test_Key{test_key(1), test_key(2), test_key(3)}
	delegates := [3]Test_Key{test_key(11), test_key(12), test_key(13)}
	other := test_key(99)
	buf := make([dynamic]u8, context.temp_allocator)

	g := Genesis {
		protocol_magic = MAGIC,
		k              = K,
	}
	g.genesis_keys = make([]base.Key_Hash, 3, context.temp_allocator)
	g.delegations = make([]Genesis_Delegation, 2, context.temp_allocator)
	for &k, i in genesis do g.genesis_keys[i] = k.hash
	// Genesis certificates: keys 0 and 1 delegate; key 2 stays self-delegated.
	for i in 0 ..< 2 {
		c := test_cert(&genesis[i], &delegates[i], 0, MAGIC, &buf)
		g.delegations[i] = Genesis_Delegation {
			issuer   = c.issuer,
			delegate = c.delegate,
			epoch    = 0,
			sig      = c.sig,
		}
	}
	s: Delegation_State
	testing.expect_value(t, delegation_init(&s, &g, context.temp_allocator), Delegation_Error.None)
	testing.expect_value(t, delegator_of(&s, delegates[0].hash), 0)
	testing.expect_value(t, delegator_of(&s, delegates[1].hash), 1)
	testing.expect_value(t, delegator_of(&s, genesis[2].hash), 2)

	// A certificate in a block at slot 100 activates at slot 100 + 2k.
	certs := [1]Delegation_Cert{test_cert(&genesis[2], &delegates[2], 0, MAGIC, &buf)}
	testing.expect_value(t, delegation_apply_certs(&s, certs[:], buf[:], MAGIC, 0, 100, K), Delegation_Error.None)
	delegation_tick(&s, 0, 119)
	testing.expect_value(t, delegator_of(&s, delegates[2].hash), -1)
	delegation_tick(&s, 0, 120)
	testing.expect_value(t, delegator_of(&s, delegates[2].hash), 2)
	testing.expect_value(t, delegator_of(&s, genesis[2].hash), -1)

	Case :: struct {
		name: string,
		want: Delegation_Error,
	}
	for c in ([]Case{{"another for the same epoch", .Multiple_Delegations_For_Epoch}, {"epoch two ahead", .Wrong_Epoch}, {"epoch in the past", .Wrong_Epoch}, {"not a genesis key", .Non_Genesis_Delegator}, {"bad signature", .Invalid_Certificate}, {"two in one block", .Multiple_Delegations_For_Slot}}) {
		scratch := s
		scratch.delegates = slice.clone(s.delegates, context.temp_allocator)
		scratch.activated = slice.clone(s.activated, context.temp_allocator)
		scratch.scheduled = slice.clone_to_dynamic(s.scheduled[:], context.temp_allocator)
		scratch.key_epochs = slice.clone_to_dynamic(s.key_epochs[:], context.temp_allocator)
		block: [2]Delegation_Cert
		n := 1
		epoch: u64 = 1 // the state is in epoch 1 below
		switch c.name {
		case "another for the same epoch":
			block[0] = test_cert(&genesis[0], &other, 1, MAGIC, &buf)
			block[1] = test_cert(&genesis[0], &delegates[0], 1, MAGIC, &buf)
			n = 2
		case "epoch two ahead":
			block[0] = test_cert(&genesis[0], &other, 3, MAGIC, &buf)
		case "epoch in the past":
			block[0] = test_cert(&genesis[0], &other, 0, MAGIC, &buf)
		case "not a genesis key":
			block[0] = test_cert(&delegates[0], &other, 1, MAGIC, &buf)
		case "bad signature":
			block[0] = test_cert(&genesis[0], &other, 1, MAGIC, &buf, bad_sig = true)
		case "two in one block":
			block[0] = test_cert(&genesis[0], &other, 1, MAGIC, &buf)
			block[1] = test_cert(&genesis[0], &delegates[0], 2, MAGIC, &buf)
			n = 2
		}
		err := delegation_apply_certs(&scratch, block[:n], buf[:], MAGIC, epoch, 30_000, K)
		testing.expectf(t, err == c.want, "%s: %v", c.name, err)
	}

	// A delegate that already serves another genesis key is dropped at
	// activation, without an error.
	certs[0] = test_cert(&genesis[0], &delegates[1], 1, MAGIC, &buf)
	testing.expect_value(t, delegation_apply_certs(&s, certs[:], buf[:], MAGIC, 1, 30_000, K), Delegation_Error.None)
	delegation_tick(&s, 1, 30_020)
	testing.expect_value(t, delegator_of(&s, delegates[0].hash), 0)
	testing.expect_value(t, delegator_of(&s, delegates[1].hash), 1)
	testing.expect_value(t, len(s.scheduled), 0)
	free_all(context.temp_allocator)
}

// ---------------------------------------------------------------------------
// Chain rejections, on the preprod chain

@(private = "file")
Preprod :: struct {
	g:      Genesis,
	blocks: [dynamic][]u8,
	ebb:    [dynamic]bool,
}

@(private = "file")
load_preprod :: proc(t: ^testing.T) -> (p: Preprod, ok: bool) {
	p.g = load_genesis(t, "preprod.json") or_return
	data, err := os.read_entire_file(DINGO + "preprod-byron-chain.cbor", context.temp_allocator)
	if !testing.expect(t, err == nil) do return p, false
	r := cbor.reader(data)
	n, _ := read_array_definite(&r)
	p.blocks = make([dynamic][]u8, context.temp_allocator)
	p.ebb = make([dynamic]bool, context.temp_allocator)
	for _ in 0 ..< n {
		_ = enforce_size(&r, 2)
		type, _ := cbor.read_uint(&r)
		block, _ := cbor.read_bytes(&r)
		append(&p.blocks, block)
		append(&p.ebb, type == 0)
	}
	return p, true
}

// Replays blocks [0, upto) into a fresh chain.
@(private = "file")
replay_to :: proc(
	t: ^testing.T,
	p: ^Preprod,
	c: ^Chain,
	tables: ^Tables,
	upto: int,
	threshold := PBFT_DEFAULT_THRESHOLD,
) {
	_ = chain_init(c, &p.g, requires_magic = true, threshold = threshold, allocator = context.temp_allocator)
	for i in 0 ..< upto {
		b: Block
		_ = decode_block(p.blocks[i], p.ebb[i], epoch_slots(&p.g), tables, &b)
		err := chain_apply(c, p.blocks[i], &b, tables)
		testing.expectf(t, err.kind == .None, "replay block %d: %v", i, err)
	}
}

@(test)
test_chain_rejections :: proc(t: ^testing.T) {
	p, ok := load_preprod(t)
	if !ok do return
	tables: Tables
	tables_init(&tables)
	defer tables_destroy(&tables)

	Case :: struct {
		name:  string,
		block: int,
		want:  Chain_Error_Kind,
	}
	cases := [?]Case {
		{"skipped block", 3, .Envelope},
		{"repeated block", 3, .Envelope},
		{"bad block signature", 3, .Pbft},
		{"unknown delegate", 3, .Pbft},
		{"signing window", 20, .Pbft},
		{"header too large", 3, .Header_Too_Large},
		{"block too large", 3, .Block_Too_Large},
		{"proof mismatch", 3, .Proof},
		{"wrong protocol magic", 3, .Protocol_Magic},
		{"wrong genesis hash", 0, .Boundary_Prev_Hash},
		{"vote cast twice", 2, .Update},
		{"proposal by a non-delegate", 2, .Update},
		{"bad proposal signature", 2, .Update},
	}
	for c in cases {
		chain: Chain
		threshold := 0.003 if c.name == "signing window" else PBFT_DEFAULT_THRESHOLD // 6 of 2160
		replay_to(t, &p, &chain, &tables, c.block, threshold)
		if c.name == "wrong genesis hash" do chain.prev_hash[0] ~= 1
		target := c.block
		switch c.name {
		case "skipped block":
			target = c.block + 1
		case "repeated block":
			target = c.block - 1
		}
		b: Block
		testing.expect_value(
			t,
			decode_block(p.blocks[target], p.ebb[target], epoch_slots(&p.g), &tables, &b),
			Error.None,
		)
		switch c.name {
		case "bad block signature":
			b.main.signature[3] ~= 1
		case "unknown delegate":
			b.main.cert.delegate[40] ~= 1 // chain code: same signing key, other key hash
		case "header too large":
			chain.update.params.max_header_size.small = u64(b.header.len) - 1
		case "block too large":
			chain.update.params.max_block_size.small = u64(b.size) - 1
		case "proof mismatch":
			b.proof.dlg_hash[0] ~= 1
		case "wrong protocol magic":
			b.main.protocol_magic += 1
		case "vote cast twice":
			append(&tables.votes, tables.votes[0])
		case "proposal by a non-delegate":
			tables.proposals[0].from[40] ~= 1
		case "bad proposal signature":
			tables.proposals[0].sig[0] ~= 1
		}
		if c.name == "signing window" {
			// Apply blocks until a genesis key signs a 7th time in the window.
			err: Chain_Error
			for i in c.block ..< len(p.blocks) {
				_ = decode_block(p.blocks[i], p.ebb[i], epoch_slots(&p.g), &tables, &b)
				if err = chain_apply(&chain, p.blocks[i], &b, &tables); err.kind != .None do break
			}
			testing.expectf(t, err.kind == .Pbft && err.pbft == .Exceeded_Threshold, "%s: %v", c.name, err)
			continue
		}
		before := chain.utxo.total
		err := chain_apply(&chain, p.blocks[target], &b, &tables)
		testing.expectf(t, err.kind == c.want, "%s: %v", c.name, err)
		testing.expect(t, chain.utxo.total == before)

		// The chain is unchanged: the unmodified next block still applies.
		if c.name == "wrong genesis hash" || c.name == "header too large" || c.name == "block too large" {
			continue
		}
		_ = decode_block(p.blocks[c.block], p.ebb[c.block], epoch_slots(&p.g), &tables, &b)
		err = chain_apply(&chain, p.blocks[c.block], &b, &tables)
		testing.expectf(t, err.kind == .None, "%s: the next block no longer applies: %v", c.name, err)
	}
	free_all(context.temp_allocator)
}

// ---------------------------------------------------------------------------
// The update system over proposals and votes the test signs

@(private = "file")
UK :: 10 // k: 2k = 20, 4k = 40, 100 slots per epoch
@(private = "file")
UMAGIC :: 7

@(private = "file")
Update_Fixture :: struct {
	keys:   [8]Test_Key, // 0 to 6 are genesis keys (self-delegated), 7 is not
	dlg:    Delegation_State,
	u:      Update_State,
	pool:   [dynamic]u8,
	tables: Tables,
	buf:    [dynamic]u8,
}

@(private = "file")
Test_Ppu :: struct {
	script: Maybe(u16),
	block:  Maybe(u64),
	tx:     Maybe(u64),
}

@(private = "file")
update_fixture :: proc(f: ^Update_Fixture) {
	for i in 0 ..< 8 do f.keys[i] = test_key(u8(i + 1))
	g := Genesis {
		protocol_magic = UMAGIC,
		k = UK,
		params = Protocol_Parameters {
			max_block_size = {small = 2_000_000},
			max_header_size = {small = 2_000_000},
			max_tx_size = {small = 4096},
			max_proposal_size = {small = 700},
			update_proposal_ttl = 10_000,
			softfork_rule = {min_thd = 600_000_000_000_000}, // 7 keys: threshold 4
		},
	}
	g.genesis_keys = make([]base.Key_Hash, 7, context.temp_allocator)
	for i in 0 ..< 7 do g.genesis_keys[i] = f.keys[i].hash
	_ = delegation_init(&f.dlg, &g, context.temp_allocator)
	update_init(&f.u, &g, context.temp_allocator)
	f.pool = make([dynamic]u8, context.temp_allocator)
	f.buf = make([dynamic]u8, context.temp_allocator)
	tables_init(&f.tables, context.temp_allocator)
}

// Encodes, signs and decodes a proposal; returns its id.
@(private = "file")
add_proposal :: proc(
	f: ^Update_Fixture,
	key: ^Test_Key,
	pv: Protocol_Version,
	ppu: Test_Ppu,
	app: string,
	number: u32,
	tag := "linux",
	bad_sig := false,
) -> base.Hash32 {
	body := cbor.writer(context.temp_allocator)
	cbor.write_array(&body, 3)
	cbor.write_uint(&body, u64(pv.major))
	cbor.write_uint(&body, u64(pv.minor))
	cbor.write_uint(&body, u64(pv.alt))
	cbor.write_array(&body, 14)
	for i in 0 ..< 14 {
		v: Maybe(u64)
		switch i {
		case 0:
			if s, ok := ppu.script.?; ok do v = u64(s)
		case 2:
			v = ppu.block
		case 4:
			v = ppu.tx
		}
		if x, ok := v.?; ok {
			cbor.write_array(&body, 1)
			cbor.write_uint(&body, x)
		} else {
			cbor.write_array(&body, 0)
		}
	}
	cbor.write_array(&body, 2)
	cbor.write_text(&body, app)
	cbor.write_uint(&body, u64(number))
	cbor.write_map(&body, 1)
	cbor.write_text(&body, tag)
	cbor.write_array(&body, 4)
	zero: [32]u8
	for _ in 0 ..< 4 do cbor.write_bytes(&body, zero[:])
	cbor.write_map(&body, 0)

	msg := make([dynamic]u8, context.temp_allocator)
	append(&msg, 0x04, UMAGIC, 0x85)
	append(&msg, ..cbor.writer_bytes(&body))
	sig: [64]u8
	ed25519.sign(&key.priv, msg[:], sig[:])
	if bad_sig do sig[0] ~= 1

	start := len(f.buf)
	append(&f.buf, 0x87)
	append(&f.buf, ..cbor.writer_bytes(&body))
	head: [9]u8
	append(&f.buf, ..head[:cbor.put_head(head[:], .Bytes, 64)])
	append(&f.buf, ..key.xpub[:])
	append(&f.buf, ..head[:cbor.put_head(head[:], .Bytes, 64)])
	append(&f.buf, ..sig[:])
	d := Decoder {
		r    = cbor.reader(f.buf[start:]),
		base = f.buf[:],
		t    = &f.tables,
	}
	p, err := read_proposal(&d)
	assert(err == .None)
	append(&f.tables.proposals, p)
	return ccrypto.blake2b_256(f.buf[start:])
}

@(private = "file")
add_vote :: proc(f: ^Update_Fixture, key: ^Test_Key, id: base.Hash32, bad_sig := false) {
	start := len(f.buf)
	append(&f.buf, 0x58, 0x20)
	id := id
	append(&f.buf, ..id[:])
	v := Vote {
		proposal_id = id,
		proposal_id_raw = base.Span{off = u32(start), len = 34},
		voter = key.xpub,
	}
	msg := make([dynamic]u8, context.temp_allocator)
	append(&msg, 0x06, UMAGIC, 0x82)
	append(&msg, ..f.buf[start:])
	append(&msg, 0xf5)
	ed25519.sign(&key.priv, msg[:], v.sig[:])
	if bad_sig do v.sig[0] ~= 1
	append(&f.tables.votes, v)
}

// One block's update payload, endorsing `pv` as `issuer`.
@(private = "file")
apply_update_block :: proc(f: ^Update_Fixture, slot: u64, pv: Protocol_Version = {}, issuer := 0) -> Update_Error {
	env := Update_Env {
		k              = UK,
		protocol_magic = UMAGIC,
		slot           = slot,
		delegation     = &f.dlg,
		pool           = &f.pool,
	}
	err := update_register(&f.u, &env, &f.tables, f.buf[:], pv, f.keys[issuer].hash)
	clear(&f.tables.proposals)
	clear(&f.tables.votes)
	clear(&f.tables.installers)
	return err
}

@(test)
test_update_registration :: proc(t: ^testing.T) {
	Case :: struct {
		name: string,
		want: Update_Error,
	}
	cases := [?]Case {
		{"protocol and software", .None},
		{"null update", .Null_Update_Proposal},
		{"proposer not a delegate", .Invalid_Proposer},
		{"bad proposal signature", .Invalid_Proposal_Signature},
		{"minor skipped", .Invalid_Protocol_Version},
		{"major skipped", .Invalid_Protocol_Version},
		{"major bump with minor", .Invalid_Protocol_Version},
		{"parameters without version", .Invalid_Protocol_Version},
		{"version taken", .Duplicate_Protocol_Version},
		{"protocol proposal too large", .Proposal_Too_Large},
		{"software proposal of any size", .None},
		{"block size doubled", .None},
		{"block size more than doubled", .Max_Block_Size_Too_Large},
		{"tx size not below block size", .Max_Tx_Size_Too_Large},
		{"script version +1", .None},
		{"script version +2", .Invalid_Script_Version},
		{"application name too long", .Application_Name_Too_Long},
		{"application name not ascii", .Application_Name_Not_Ascii},
		{"system tag too long", .System_Tag_Too_Long},
		{"new application at 2", .Invalid_Software_Version},
		{"application pending", .Duplicate_Software_Version},
	}
	for c in cases {
		f: Update_Fixture
		update_fixture(&f)
		k := &f.keys[0]
		err: Update_Error
		switch c.name {
		case "protocol and software":
			add_proposal(&f, k, {1, 0, 0}, {}, "cardano-sl", 1)
		case "null update":
			add_proposal(&f, k, {0, 0, 0}, {}, "cardano-sl", 1)
			_ = apply_update_block(&f, 5) // registers and confirms nothing
			f.u.app_versions = make([dynamic]App_Version, context.temp_allocator)
			set_app_version(&f.u, transmute([]u8)string("cardano-sl"), 1, 5)
			add_proposal(&f, k, {0, 0, 0}, {}, "cardano-sl", 1)
		case "proposer not a delegate":
			add_proposal(&f, &f.keys[7], {1, 0, 0}, {}, "cardano-sl", 1)
		case "bad proposal signature":
			add_proposal(&f, k, {1, 0, 0}, {}, "cardano-sl", 1, bad_sig = true)
		case "minor skipped":
			add_proposal(&f, k, {0, 2, 0}, {}, "a", 0)
		case "major skipped":
			add_proposal(&f, k, {2, 0, 0}, {}, "a", 0)
		case "major bump with minor":
			add_proposal(&f, k, {1, 1, 0}, {}, "a", 0)
		case "parameters without version":
			set_app_version(&f.u, transmute([]u8)string("a"), 0, 0)
			add_proposal(&f, k, {0, 0, 0}, {tx = 5000}, "a", 0)
		case "version taken":
			add_proposal(&f, k, {1, 0, 0}, {}, "a", 0)
			_ = apply_update_block(&f, 5)
			add_proposal(&f, k, {1, 0, 0}, {}, "b", 0)
		case "protocol proposal too large":
			f.u.params.max_proposal_size.small = 100
			add_proposal(&f, k, {1, 0, 0}, {}, "a", 0)
		case "software proposal of any size":
			f.u.params.max_proposal_size.small = 100
			add_proposal(&f, k, {0, 0, 0}, {}, "a", 0)
		case "block size doubled":
			add_proposal(&f, k, {1, 0, 0}, {block = 4_000_000}, "a", 0)
		case "block size more than doubled":
			add_proposal(&f, k, {1, 0, 0}, {block = 4_000_001}, "a", 0)
		case "tx size not below block size":
			add_proposal(&f, k, {1, 0, 0}, {tx = 2_000_000}, "a", 0)
		case "script version +1":
			add_proposal(&f, k, {1, 0, 0}, {script = 1}, "a", 0)
		case "script version +2":
			add_proposal(&f, k, {1, 0, 0}, {script = 2}, "a", 0)
		case "application name too long":
			add_proposal(&f, k, {0, 0, 0}, {}, "thirteen-char", 0)
		case "application name not ascii":
			add_proposal(&f, k, {0, 0, 0}, {}, "café", 0)
		case "system tag too long":
			add_proposal(&f, k, {0, 0, 0}, {}, "a", 0, tag = "linux-amd64")
		case "new application at 2":
			add_proposal(&f, k, {0, 0, 0}, {}, "a", 2)
		case "application pending":
			add_proposal(&f, k, {0, 0, 0}, {}, "a", 0)
			_ = apply_update_block(&f, 5)
			add_proposal(&f, k, {0, 0, 0}, {}, "a", 1)
		}
		err = apply_update_block(&f, 10)
		testing.expectf(t, err == c.want, "%s: %v", c.name, err)
	}
	free_all(context.temp_allocator)
}

@(test)
test_update_lifecycle :: proc(t: ^testing.T) {
	f: Update_Fixture
	update_fixture(&f)
	id := add_proposal(&f, &f.keys[0], {1, 0, 0}, {tx = 8192}, "cardano-sl", 1)
	testing.expect_value(t, apply_update_block(&f, 100), Update_Error.None)
	testing.expect(t, len(f.u.proposals) == 1 && f.u.proposals[0].has_pup && f.u.proposals[0].has_sup)

	// Votes: unregistered proposal, non-delegate, bad signature, then three
	// genesis keys (below the threshold of 4), one of them twice.
	other: base.Hash32
	other[0] = 1
	add_vote(&f, &f.keys[1], other)
	testing.expect_value(t, apply_update_block(&f, 101), Update_Error.Vote_Proposal_Not_Registered)
	add_vote(&f, &f.keys[7], id)
	testing.expect_value(t, apply_update_block(&f, 101), Update_Error.Vote_Not_Delegate)
	add_vote(&f, &f.keys[1], id, bad_sig = true)
	testing.expect_value(t, apply_update_block(&f, 101), Update_Error.Invalid_Vote_Signature)
	for i in 0 ..< 3 do add_vote(&f, &f.keys[i], id)
	testing.expect_value(t, apply_update_block(&f, 102), Update_Error.None)
	testing.expect(t, !f.u.proposals[0].confirmed)
	add_vote(&f, &f.keys[2], id)
	testing.expect_value(t, apply_update_block(&f, 103), Update_Error.Vote_Already_Cast)

	// The fourth genesis key confirms it, and the software update takes
	// effect at once.
	add_vote(&f, &f.keys[3], id)
	testing.expect_value(t, apply_update_block(&f, 110), Update_Error.None)
	testing.expect(t, f.u.proposals[0].confirmed && f.u.proposals[0].confirmed_slot == 110)
	testing.expect(t, !f.u.proposals[0].has_sup)
	testing.expect(t, len(f.u.app_versions) == 1 && f.u.app_versions[0].number == 1)

	// Endorsements count from confirmation + 2k; earlier ones are dropped.
	testing.expect_value(t, apply_update_block(&f, 129, {1, 0, 0}, 0), Update_Error.None)
	testing.expect_value(t, len(f.u.endorsements), 0)
	for i in 0 ..< 3 do testing.expect_value(t, apply_update_block(&f, 130 + u64(i), {1, 0, 0}, i), Update_Error.None)
	testing.expect_value(t, len(f.u.endorsements), 3)
	testing.expect_value(t, len(f.u.candidates), 0)
	// A key endorsing twice counts once.
	testing.expect_value(t, apply_update_block(&f, 133, {1, 0, 0}, 2), Update_Error.None)
	testing.expect_value(t, len(f.u.candidates), 0)
	testing.expect_value(t, apply_update_block(&f, 134, {1, 0, 0}, 3), Update_Error.None)
	testing.expect(t, len(f.u.candidates) == 1 && f.u.candidates[0].slot == 134)

	// Adoption at the first epoch whose first slot is 4k past the candidate.
	update_epoch_transition(&f.u, UK, 1, 100) // slot 100 < 134 + 40
	testing.expect_value(t, f.u.adopted_version, Protocol_Version{})
	update_epoch_transition(&f.u, UK, 2, 100) // slot 200 >= 174
	testing.expect_value(t, f.u.adopted_version, Protocol_Version{1, 0, 0})
	testing.expect_value(t, f.u.params.max_tx_size.small, 8192)
	testing.expect(t, len(f.u.candidates) == 0 && len(f.u.proposals) == 0 && len(f.u.endorsements) == 0)
	testing.expect_value(t, len(f.u.app_versions), 1)
	free_all(context.temp_allocator)
}

@(test)
test_update_expiry :: proc(t: ^testing.T) {
	f: Update_Fixture
	update_fixture(&f)
	f.u.params.update_proposal_ttl = 50
	a := add_proposal(&f, &f.keys[0], {1, 0, 0}, {}, "a", 0)
	testing.expect_value(t, apply_update_block(&f, 100), Update_Error.None)
	b := add_proposal(&f, &f.keys[1], {0, 1, 0}, {}, "b", 0)
	testing.expect_value(t, apply_update_block(&f, 110), Update_Error.None)
	for i in 0 ..< 4 do add_vote(&f, &f.keys[i], b)
	testing.expect_value(t, apply_update_block(&f, 120), Update_Error.None)
	// At registration + TTL both remain; one slot later only the confirmed one.
	testing.expect_value(t, apply_update_block(&f, 150), Update_Error.None)
	testing.expect_value(t, len(f.u.proposals), 2)
	testing.expect_value(t, apply_update_block(&f, 151), Update_Error.None)
	testing.expect(t, len(f.u.proposals) == 1 && f.u.proposals[0].id == b)
	// Its votes went with it.
	add_vote(&f, &f.keys[0], a)
	testing.expect_value(t, apply_update_block(&f, 152), Update_Error.Vote_Proposal_Not_Registered)
	// A confirmed proposal never expires.
	testing.expect_value(t, apply_update_block(&f, 100_000), Update_Error.None)
	testing.expect_value(t, len(f.u.proposals), 1)
	free_all(context.temp_allocator)
}

@(test)
test_versions_and_naturals :: proc(t: ^testing.T) {
	testing.expect(t, version_can_follow({0, 1, 0}, {0, 0, 0}))
	testing.expect(t, version_can_follow({0, 1, 7}, {0, 0, 3}))
	testing.expect(t, version_can_follow({1, 0, 0}, {0, 5, 0}))
	testing.expect(t, !version_can_follow({1, 1, 0}, {0, 5, 0}))
	testing.expect(t, !version_can_follow({0, 0, 1}, {0, 0, 0})) // alt alone
	testing.expect(t, !version_can_follow({0, 0, 0}, {0, 0, 0}))
	testing.expect(t, !version_can_follow({2, 0, 0}, {0, 0, 0}))

	// Bignum magnitudes: 2^64 (9 bytes), 2^65 and 2^65 + 1.
	pool := []u8{1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1}
	p64 := Natural {
		big = {off = 0, len = 9},
	}
	p65 := Natural {
		big = {off = 9, len = 9},
	}
	p65_1 := Natural {
		big = {off = 18, len = 9},
	}
	top := Natural {
		small = max(u64),
	}
	testing.expect_value(t, natural_cmp(&p64, &top, pool), 1)
	testing.expect_value(t, natural_cmp(&p65, &p64, pool), 1)
	testing.expect_value(t, natural_cmp(&p65, &p65, pool), 0)
	testing.expect(t, natural_le_double(&p65, &p64, pool))
	testing.expect(t, !natural_le_double(&p65_1, &p64, pool))
	testing.expect(t, natural_le_double(&p64, &top, pool)) // 2^64 <= 2^65 - 2
	testing.expect(t, natural_le_double(&top, &top, pool))
	testing.expect(t, natural_le_u64(&p64, max(u64), pool))
}

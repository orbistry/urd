package byron

import "core:bytes"
import "core:encoding/hex"
import "core:fmt"
import "core:hash"
import "core:os"
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
			testing.expectf(t, base.Hash32(tx_id(&tables, wire)) == want, "%s: id differs", name)
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

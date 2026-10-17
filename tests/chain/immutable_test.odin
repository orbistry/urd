// Integration tests over real chain data (cardano-node ImmutableDB chunks).
package chain_test

import "core:fmt"
import "core:testing"

import "core:encoding/endian"

import "urd:base"
import "urd:ccrypto"
import "urd:ledger"
import "urd:storage/immutable"

// 300 preview chunks (Alonzo and Babbage), vendored from dingo's test data
// (see testdata/README.md).
PREVIEW_DB :: "testdata/immutable/preview"
// Two complete Babbage chunks from pallas's test data.
PALLAS_DB :: "testdata/immutable/pallas"

@(test)
test_preview_headers_and_body_hashes :: proc(t: ^testing.T) {
	check_db(t, PREVIEW_DB)
}

@(test)
test_pallas_headers_and_body_hashes :: proc(t: ^testing.T) {
	check_db(t, PALLAS_DB)
}

// Decodes every block of an ImmutableDB and checks the header and body hashes
// against the secondary index and the header.
check_db :: proc(t: ^testing.T, dir: string) {
	chunks, err := immutable.list_chunks(dir)
	defer delete(chunks)
	testing.expect_value(t, err, immutable.Error.None)
	testing.expect(t, len(chunks) > 0, "no chunks found in testdata/")

	chunk: immutable.Chunk
	immutable.chunk_init(&chunk)
	defer immutable.chunk_destroy(&chunk)

	blocks := 0
	txs := 0
	per_era: [base.Era]int
	parts: ledger.Block_Parts
	tables: ledger.Block_Tables
	ledger.tables_init(&tables)
	defer ledger.tables_destroy(&tables)
	full: ledger.Block
	for n in chunks {
		lerr := immutable.chunk_load(&chunk, dir, n, verify = true)
		if !testing.expectf(t, lerr == .None, "chunk %d: %v", n, lerr) do return

		for i in 0 ..< len(chunk.entries) {
			entry := &chunk.entries[i]
			raw := immutable.chunk_block(&chunk, i)
			env, eerr := ledger.decode_envelope(raw)
			if !testing.expectf(t, eerr == .None, "chunk %d block %d: envelope %v", n, i, eerr) do return
			per_era[env.era] += 1
			blocks += 1
			if env.era == .Byron {
				continue
			}

			derr := ledger.decode_block_parts(env.block, env.era, &parts)
			if !testing.expectf(t, derr == .None, "chunk %d block %d (%v): %v", n, i, env.era, derr) do return
			h := &parts.header

			// The secondary index records where the header sits in the raw block.
			hdr := immutable.chunk_header(&chunk, i)
			testing.expectf(
				t,
				raw_data(hdr) == raw_data(h.raw) && len(hdr) == len(h.raw),
				"chunk %d block %d: header span mismatch",
				n,
				i,
			)
			testing.expectf(t, h.hash == entry.hash, "chunk %d block %d: header hash mismatch", n, i)
			testing.expectf(
				t,
				h.slot == entry.slot_or_epoch,
				"chunk %d block %d: slot %d != %d",
				n,
				i,
				h.slot,
				entry.slot_or_epoch,
			)
			testing.expectf(t, parts.body_hash == h.body_hash, "chunk %d block %d: body hash mismatch", n, i)
			testing.expectf(
				t,
				u32(parts.body_size) == h.body_size,
				"chunk %d block %d: body size %d != %d",
				n,
				i,
				parts.body_size,
				h.body_size,
			)
			check_header_crypto(t, h, n, i)

			// Full decode: every transaction, and the body hash computed from
			// the decoders' own part boundaries.
			ferr := ledger.decode_block(env.block, env.era, &tables, &full)
			if !testing.expectf(t, ferr == .None, "chunk %d block %d (%v): full decode %v", n, i, env.era, ferr) do return
			testing.expectf(t, full.body_hash == h.body_hash, "chunk %d block %d: decoded body hash mismatch", n, i)
			testing.expectf(
				t,
				u32(full.body_size) == h.body_size,
				"chunk %d block %d: decoded body size mismatch",
				n,
				i,
			)
			txs += len(tables.txs)
			free_all(context.temp_allocator)
		}
	}
	fmt.printfln("%s: decoded %d blocks, %d txs: %v", dir, blocks, txs, per_era)
}

// Preview, preprod and mainnet all use 129600 slots per KES period.
SLOTS_PER_KES_PERIOD :: 129600

// Signature checks that need no chain state: the KES signature over the header
// body, the cold key's signature over the operational certificate, and that
// each VRF output is the hash of its proof.
check_header_crypto :: proc(t: ^testing.T, h: ^ledger.Header, chunk: u32, i: int) {
	kes_period := h.slot / SLOTS_PER_KES_PERIOD
	testing.expectf(t, kes_period >= h.ocert.kes_period, "chunk %d block %d: KES period before ocert start", chunk, i)
	ok := ccrypto.kes_sum6_verify(h.ocert.hot_vkey[:], kes_period - h.ocert.kes_period, h.body, h.kes_signature)
	testing.expectf(t, ok, "chunk %d block %d: bad KES signature", chunk, i)

	// OCertSignable: hot vkey || counter (u64 BE) || start period (u64 BE).
	signable: [48]u8
	copy(signable[:32], h.ocert.hot_vkey[:])
	endian.unchecked_put_u64be(signable[32:], h.ocert.counter)
	endian.unchecked_put_u64be(signable[40:], h.ocert.kes_period)
	ok = ccrypto.ed25519_verify(h.issuer_vkey[:], signable[:], h.ocert.sigma[:])
	testing.expectf(t, ok, "chunk %d block %d: bad ocert signature", chunk, i)

	certs := [2]^ledger.Vrf_Cert{&h.leader_vrf, &h.nonce_vrf}
	for c, k in certs {
		if k == 1 && !ledger.is_tpraos(h.era) do break
		beta, vok := ccrypto.vrf03_proof_to_hash(c.proof[:])
		testing.expectf(
			t,
			vok && string(beta[:]) == string(c.output),
			"chunk %d block %d: VRF output is not the proof hash",
			chunk,
			i,
		)
	}
}

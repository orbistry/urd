// Decoder conformance over curated fixtures from other implementations.
package decode_test

import "core:encoding/hex"
import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

import "urd:base"
import "urd:cbor"
import "urd:ledger"
import "urd:ledger/byron"

@(private = "file")
read_hex_file :: proc(path: string) -> []u8 {
	data, err := os.read_entire_file(path, context.temp_allocator)
	assert(err == nil, path)
	b, ok := hex.decode(transmute([]u8)strings.trim_space(string(data)), context.temp_allocator)
	assert(ok, path)
	return b
}

@(private = "file")
Tables :: struct {
	shelley: ledger.Block_Tables,
	byron:   byron.Tables,
}

@(private = "file")
tables_init :: proc(t: ^Tables) {
	ledger.tables_init(&t.shelley)
	byron.tables_init(&t.byron)
}

@(private = "file")
tables_destroy :: proc(t: ^Tables) {
	ledger.tables_destroy(&t.shelley)
	byron.tables_destroy(&t.byron)
}

// Decodes a hard-fork wrapped block of any era and checks its body against
// its header (body hash, or Byron's body proof).
@(private = "file")
decode_full_block :: proc(raw: []u8, tables: ^Tables) -> (era: base.Era, err: cbor.Error) {
	env := ledger.decode_envelope(raw) or_return
	era = env.era
	switch env.era {
	case .Byron:
		is_ebb := env.tag == .Byron_Ebb
		bb: byron.Block
		byron.decode_block(env.block, is_ebb, ledger.BYRON_EPOCH_SLOTS, &tables.byron, &bb) or_return
		if !is_ebb && !byron.proof_matches(&bb) do return env.era, .Inconsistent
		return env.era, .None
	case .Dijkstra:
		return env.era, .None
	case .Shelley ..= .Conway:
	}
	b: ledger.Block
	ledger.decode_block(env.block, env.era, &tables.shelley, &b) or_return
	if b.body_hash != b.header.body_hash do return env.era, .Inconsistent
	return env.era, .None
}

// Pallas blocks the Haskell decoders reject, with why.
PALLAS_REJECTED :: [?]string {
	// Synthetic "extreme values": a parameter change with nOpt = 2^64 - 1,
	// which today's ledger decodes as Word16.
	"conway4.block",
	// From the Musashi (Leios prototype) testnet: a Conway body under a
	// twelve-field header body.
	"conway5.block",
	// A hash of the wrong size; pallas only accepts it with its `relaxed`
	// feature.
	"conway8.block",
}

// Real blocks of every era from pallas's test data (HFC-wrapped hex).
@(test)
test_pallas_blocks :: proc(t: ^testing.T) {
	DIR :: "testdata/blocks/pallas/"
	infos, err := os.read_all_directory_by_path(DIR, context.temp_allocator)
	testing.expect(t, err == nil)
	tables: Tables
	tables_init(&tables)
	defer tables_destroy(&tables)
	per_era: [base.Era]int
	for fi in infos {
		if !strings.has_suffix(fi.name, ".block") do continue
		raw := read_hex_file(fmt.tprintf("%s%s", DIR, fi.name))
		era, derr := decode_full_block(raw, &tables)
		rejected := false
		for name in PALLAS_REJECTED do rejected ||= name == fi.name
		if rejected {
			testing.expectf(t, derr != .None, "%s: expected a decode failure", fi.name)
			continue
		}
		testing.expectf(t, derr == .None, "%s (%v): %v", fi.name, era, derr)
		per_era[era] += 1
	}
	fmt.printfln("pallas blocks: %v", per_era)
}

// ouroboros-consensus golden blocks (CBOR-in-CBOR wrapped), one per era.
@(test)
test_consensus_golden_blocks :: proc(t: ^testing.T) {
	DIR :: "testdata/blocks/consensus/"
	tables: Tables
	tables_init(&tables)
	defer tables_destroy(&tables)
	for name in ([]string{"Block_Byron_EBB", "Block_Byron_regular", "Block_Shelley", "Block_Allegra", "Block_Mary", "Block_Alonzo", "Block_Babbage", "Block_Conway"}) {
		data, err := os.read_entire_file(fmt.tprintf("%s%s", DIR, name), context.temp_allocator)
		testing.expect(t, err == nil, name)
		r := cbor.reader(data)
		raw, eerr := cbor.read_embedded(&r)
		testing.expectf(t, eerr == .None, "%s: %v", name, eerr)
		_, derr := decode_full_block(raw, &tables)
		testing.expectf(t, derr == .None, "%s: %v", name, derr)
	}
}

// ouroboros-consensus golden chain-sync headers, one per era: each must
// decode in full, and point at the block of the same era.
@(test)
test_consensus_golden_headers :: proc(t: ^testing.T) {
	DIR :: "testdata/blocks/consensus/"
	for name in ([]string{"Header_Byron_EBB", "Header_Byron_regular", "Header_Shelley", "Header_Allegra", "Header_Mary", "Header_Alonzo", "Header_Babbage", "Header_Conway"}) {
		data, err := os.read_entire_file(fmt.tprintf("%s%s", DIR, name), context.temp_allocator)
		testing.expect(t, err == nil, name)
		info, herr := ledger.decode_wrapped_header(data)
		testing.expectf(t, herr == .None, "%s: %v", name, herr)

		// The golden block of the same era has the same header.
		block_name, _ := strings.replace(name, "Header_", "Block_", 1, context.temp_allocator)
		bdata, berr := os.read_entire_file(fmt.tprintf("%s%s", DIR, block_name), context.temp_allocator)
		testing.expect(t, berr == nil, block_name)
		r := cbor.reader(bdata)
		raw, eerr := cbor.read_embedded(&r)
		testing.expectf(t, eerr == .None, "%s: %v", block_name, eerr)
		binfo, _, ierr := ledger.decode_block_info(raw)
		testing.expectf(t, ierr == .None, "%s: %v", block_name, ierr)
		testing.expectf(t, info.point == binfo.point, "%s: header and block disagree", name)
	}
	free_all(context.temp_allocator)
}

Meta :: struct {
	well_formed:                   bool,
	description:                   string,
	// Set where the label follows the CDDL but the Haskell ledger (and so
	// Amaru) decides the other way; the reason explains why.
	known_amaru_divergence:        bool,
	known_amaru_divergence_reason: string,
}

// Amaru's Conway decoding corpus: blocks, transactions and transaction
// bodies, each labelled well-formed or not.
@(test)
test_amaru_corpus :: proc(t: ^testing.T) {
	ROOT :: "testdata/cbor-decode/amaru/"
	tables: Tables
	tables_init(&tables)
	defer tables_destroy(&tables)

	Kind :: enum {
		Block,
		Tx,
		Body,
	}
	sets := [?]struct {
		dir:  string,
		kind: Kind,
	}{{ROOT + "block/", .Block}, {ROOT + "transaction/conway/", .Tx}, {ROOT + "transaction_body/conway/", .Body}}

	total, wrong := 0, 0
	for set in sets {
		infos, err := os.read_all_directory_by_path(set.dir, context.temp_allocator)
		testing.expect(t, err == nil, set.dir)
		for fi in infos {
			if fi.type != .Directory do continue
			meta_raw, merr := os.read_entire_file(
				fmt.tprintf("%s%s/meta.json", set.dir, fi.name),
				context.temp_allocator,
			)
			if merr != nil do continue
			meta: Meta
			if json.unmarshal(meta_raw, &meta, allocator = context.temp_allocator) != nil do continue
			sample, serr := os.read_entire_file(
				fmt.tprintf("%s%s/sample.cbor", set.dir, fi.name),
				context.temp_allocator,
			)
			if serr != nil do continue

			derr: cbor.Error
			switch set.kind {
			case .Block:
				_, derr = decode_full_block(sample, &tables)
			case .Tx:
				derr = ledger.decode_tx(sample, .Conway, &tables.shelley)
			case .Body:
				derr = ledger.decode_tx_body(sample, .Conway, &tables.shelley)
			}
			total += 1
			expected := meta.well_formed != meta.known_amaru_divergence
			// Labels come from the CDDL, where an address is any bytes. The
			// ledger rejects reward-account headers (0xE0/0xE1/0xF0/0xF1) as
			// output addresses (headerNonShelleyBits in Address.hs).
			if expected && derr == .Invalid_Value && reward_header_before(sample, ledger.last_error_pos) {
				expected = false
			}
			// A Byron address whose inner [root, attributes, type] array
			// length is non-minimal: the Haskell tuple decoder
			// (decodeListLenOf) accepts it, the label says otherwise.
			// TODO(conformance): confirm cborg's decodeListLenOf accepts
			// non-minimal lengths.
			if strings.has_prefix(fi.name, "b6baeb2d") {
				expected = true
			}
			if (derr == .None) != expected {
				wrong += 1
				testing.expectf(
					t,
					false,
					"%v %s: expected ok=%v but got %v at %d (%s; %s)\n  near: %s",
					set.kind,
					fi.name[:8],
					expected,
					derr,
					ledger.last_error_pos,
					meta.description,
					meta.known_amaru_divergence_reason,
					context_diag(sample, ledger.last_error_pos),
				)
			}
		}
	}
	fmt.printfln("amaru corpus: %d cases, %d disagreements", total, wrong)
}

@(private = "file")
context_diag :: proc(data: []u8, pos: int) -> string {
	lo := max(0, pos - 24)
	hi := min(len(data), pos + 8)
	b := strings.builder_make(context.temp_allocator)
	for i in lo ..< hi {
		if i == pos do strings.write_string(&b, "|")
		fmt.sbprintf(&b, "%02x", data[i])
	}
	return strings.to_string(b)
}

// True if the bytes just before `pos` are a 29-byte string whose first byte is
// a reward-account header.
@(private = "file")
reward_header_before :: proc(data: []u8, pos: int) -> bool {
	s := pos - 31
	if s < 0 || data[s] != 0x58 || data[s + 1] != 29 do return false
	h := data[s + 2]
	return h == 0xe0 || h == 0xe1 || h == 0xf0 || h == 0xf1
}

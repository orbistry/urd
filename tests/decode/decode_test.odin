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

@(private = "file")
read_hex_file :: proc(path: string) -> []u8 {
	data, err := os.read_entire_file(path, context.temp_allocator)
	assert(err == nil, path)
	b, ok := hex.decode(transmute([]u8)strings.trim_space(string(data)), context.temp_allocator)
	assert(ok, path)
	return b
}

@(private = "file")
decode_full_block :: proc(raw: []u8, tables: ^ledger.Block_Tables) -> (era: base.Era, err: cbor.Error) {
	env := ledger.decode_envelope(raw) or_return
	era = env.era
	if env.era == .Byron || env.era == .Dijkstra do return env.era, .None
	b: ledger.Block
	ledger.decode_block(env.block, env.era, tables, &b) or_return
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
	DIR :: "refs/pallas/test_data/"
	infos, err := os.read_all_directory_by_path(DIR, context.temp_allocator)
	testing.expect(t, err == nil)
	tables: ledger.Block_Tables
	ledger.tables_init(&tables)
	defer ledger.tables_destroy(&tables)
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
	DIR :: "refs/ouroboros-consensus/ouroboros-consensus-cardano/golden/cardano/CardanoNodeToNodeVersion2/"
	tables: ledger.Block_Tables
	ledger.tables_init(&tables)
	defer ledger.tables_destroy(&tables)
	for name in ([]string{"Block_Shelley", "Block_Allegra", "Block_Mary", "Block_Alonzo", "Block_Babbage", "Block_Conway"}) {
		data, err := os.read_entire_file(fmt.tprintf("%s%s", DIR, name), context.temp_allocator)
		testing.expect(t, err == nil, name)
		r := cbor.reader(data)
		raw, eerr := cbor.read_embedded(&r)
		testing.expectf(t, eerr == .None, "%s: %v", name, eerr)
		_, derr := decode_full_block(raw, &tables)
		testing.expectf(t, derr == .None, "%s: %v", name, derr)
	}
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
	ROOT :: "refs/amaru/crates/amaru-kernel/tests/data/cbor.decode/"
	tables: ledger.Block_Tables
	ledger.tables_init(&tables)
	defer ledger.tables_destroy(&tables)

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
				derr = ledger.decode_tx(sample, .Conway, &tables)
			case .Body:
				derr = ledger.decode_tx_body(sample, .Conway, &tables)
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

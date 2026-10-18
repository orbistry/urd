package main

import "core:fmt"
import "core:os"
import "core:time"

import "urd:ledger"
import "urd:ledger/byron"
import "urd:storage/immutable"

// Replays an ImmutableDB's Byron era from genesis through full validation
// (PBFT, the envelope and the ledger rules), stopping at the first block
// past Byron. Reports each epoch and the final state.
replay :: proc(args: []string) -> int {
	if len(args) == 0 {
		fmt.eprint(USAGE)
		return 2
	}
	dir := args[0]
	genesis_path, has_genesis := flag(args, "--genesis")
	if !has_genesis {
		fmt.eprintln("replay: --genesis FILE is required")
		return 2
	}
	requires_magic := false
	for a in args do requires_magic ||= a == "--requires-magic"

	data, rerr := os.read_entire_file(genesis_path, context.allocator)
	if rerr != nil {
		fmt.eprintfln("cannot read %s", genesis_path)
		return 1
	}
	g, gerr := byron.genesis_parse(data)
	if gerr != .None {
		fmt.eprintfln("genesis: %v", gerr)
		return 1
	}
	fmt.printfln("genesis %x, magic %d, k %d", g.hash[:], g.protocol_magic, g.k)
	c: byron.Chain
	if e := byron.chain_init(&c, &g, requires_magic); e != .None {
		fmt.eprintfln("genesis delegation: %v", e)
		return 1
	}
	defer byron.chain_destroy(&c)
	es := byron.epoch_slots(&g)

	numbers, lerr := immutable.list_chunks(dir)
	defer delete(numbers)
	if lerr != .None || len(numbers) == 0 {
		fmt.eprintfln("no chunks in %s", dir)
		return 1
	}
	chunk: immutable.Chunk
	immutable.chunk_init(&chunk)
	defer immutable.chunk_destroy(&chunk)
	t: byron.Tables
	byron.tables_init(&t)
	defer byron.tables_destroy(&t)

	start := time.tick_now()
	blocks, txs := 0, 0
	epoch: u64 = 0
	report :: proc(c: ^byron.Chain, epoch: u64, blocks, txs: int, start: time.Tick) {
		fmt.printfln(
			"epoch %d: %d blocks, %d txs, utxo %d entries / %d lovelace, version %d.%d.%d, %.1fs",
			epoch,
			blocks,
			txs,
			byron.utxo_len(&c.utxo),
			c.utxo.total,
			c.update.adopted_version.major,
			c.update.adopted_version.minor,
			c.update.adopted_version.alt,
			time.duration_seconds(time.tick_since(start)),
		)
	}
	loop: for n in numbers {
		if err := immutable.chunk_load(&chunk, dir, n); err != .None {
			fmt.eprintfln("chunk %d: %v", n, err)
			return 1
		}
		for i in 0 ..< len(chunk.entries) {
			env, eerr := ledger.decode_envelope(immutable.chunk_block(&chunk, i))
			if eerr != .None {
				fmt.eprintfln("chunk %d block %d: envelope %v", n, i, eerr)
				return 1
			}
			if env.era != .Byron do break loop
			b: byron.Block
			if err := byron.decode_block(env.block, env.tag == .Byron_Ebb, es, &t, &b); err != .None {
				fmt.eprintfln("chunk %d block %d: decode %v", n, i, err)
				return 1
			}
			slot := b.ebb.epoch * es if b.is_ebb else u64(b.main.slot)
			if e, known := byron.chain_transition_epoch(&c); known && slot >= e * es {
				break loop
			}
			if slot / es != epoch {
				report(&c, epoch, blocks, txs, start)
				epoch = slot / es
			}
			if err := byron.chain_apply(&c, env.block, &b, &t); err.kind != .None {
				fmt.eprintfln("chunk %d block %d (slot %d): rejected: %v", n, i, slot, err)
				return 1
			}
			blocks += 1
			txs += len(t.txs)
		}
	}
	report(&c, epoch, blocks, txs, start)
	if e, known := byron.chain_transition_epoch(&c); known {
		fmt.printfln("Byron ends: Shelley starts at epoch %d (slot %d)", e, e * es)
	}
	return 0
}

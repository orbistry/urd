package main

import "base:runtime"
import "core:fmt"
import "core:strconv"
import "core:time"

import "urd:ledger"
import "urd:ledger/byron"
import "urd:storage/immutable"

// Wraps an allocator and counts what goes through it.
Counting_Allocator :: struct {
	backing: runtime.Allocator,
	allocs:  int,
	bytes:   int,
}

counting_allocator :: proc(c: ^Counting_Allocator) -> runtime.Allocator {
	return runtime.Allocator{procedure = counting_allocator_proc, data = c}
}

counting_allocator_proc :: proc(
	data: rawptr,
	mode: runtime.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	runtime.Allocator_Error,
) {
	c := (^Counting_Allocator)(data)
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed, .Resize, .Resize_Non_Zeroed:
		c.allocs += 1
		c.bytes += size
	}
	return c.backing.procedure(c.backing.data, mode, size, alignment, old_memory, old_size, loc)
}

// Measures block decoding throughput over an ImmutableDB directory, with
// every chunk loaded in memory first so disk I/O is excluded. After a
// warm-up pass (which grows the reusable tables), the timed passes run with
// counting allocators installed: steady-state decoding should allocate
// nothing. Scratch arena pages committed by the OS are not counted.
bench_decode :: proc(args: []string) -> int {
	if len(args) == 0 {
		fmt.eprint(USAGE)
		return 2
	}
	dir := args[0]
	passes := 3
	if s, ok := flag(args, "--passes"); ok {
		passes = strconv.parse_int(s) or_else passes
	}

	numbers, lerr := immutable.list_chunks(dir)
	defer delete(numbers)
	if lerr != .None || len(numbers) == 0 {
		fmt.eprintfln("no chunks in %s", dir)
		return 1
	}

	// Load every chunk and slice out its blocks.
	chunks := make([]immutable.Chunk, len(numbers))
	defer {
		for &c in chunks do immutable.chunk_destroy(&c)
		delete(chunks)
	}
	blocks := make([dynamic][]u8)
	defer delete(blocks)
	total_bytes := 0
	for n, i in numbers {
		immutable.chunk_init(&chunks[i])
		if err := immutable.chunk_load(&chunks[i], dir, n); err != .None {
			fmt.eprintfln("chunk %d: %v", n, err)
			return 1
		}
		for b in 0 ..< len(chunks[i].entries) {
			raw := immutable.chunk_block(&chunks[i], b)
			append(&blocks, raw)
			total_bytes += len(raw)
		}
	}

	tables: ledger.Block_Tables
	ledger.tables_init(&tables)
	defer ledger.tables_destroy(&tables)

	decode_all :: proc(blocks: [][]u8, tables: ^ledger.Block_Tables) -> (txs: int, ok: bool) {
		b: ledger.Block
		for raw in blocks {
			env, eerr := ledger.decode_envelope(raw)
			if eerr != .None do return txs, false
			if env.era == .Byron {
				header, herr := byron.block_header(env.block)
				if herr != .None do return txs, false
				_, ierr := byron.decode_header_info(header, env.tag == .Byron_Ebb, ledger.BYRON_EPOCH_SLOTS)
				if ierr != .None do return txs, false
				continue
			}
			if ledger.decode_block(env.block, env.era, tables, &b) != .None do return txs, false
			if b.body_hash != b.header.body_hash do return txs, false
			txs += len(tables.txs)
		}
		return txs, true
	}

	txs, ok := decode_all(blocks[:], &tables)
	if !ok {
		fmt.eprintln("decode failed during warm-up")
		return 1
	}

	heap := Counting_Allocator {
		backing = context.allocator,
	}
	temp := Counting_Allocator {
		backing = context.temp_allocator,
	}
	best := max(f64)
	{
		context.allocator = counting_allocator(&heap)
		context.temp_allocator = counting_allocator(&temp)
		for _ in 0 ..< passes {
			start := time.tick_now()
			_, pok := decode_all(blocks[:], &tables)
			secs := time.duration_seconds(time.tick_since(start))
			if !pok {
				fmt.eprintln("decode failed")
				return 1
			}
			best = min(best, secs)
		}
	}

	mb := f64(total_bytes) / (1024 * 1024)
	fmt.printfln("%s: %d blocks, %d txs, %.1f MiB, %d chunks", dir, len(blocks), txs, mb, len(numbers))
	fmt.printfln(
		"best of %d passes: %.3fs  %.0f blocks/s  %.1f MiB/s  %.2f µs/block",
		passes,
		best,
		f64(len(blocks)) / best,
		mb / best,
		best * 1e6 / f64(len(blocks)),
	)
	fmt.printfln(
		"allocations in timed passes: heap %d (%d bytes), temp %d (%d bytes)",
		heap.allocs,
		heap.bytes,
		temp.allocs,
		temp.bytes,
	)
	return 0
}

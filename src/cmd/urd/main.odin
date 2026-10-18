package main

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

import "core:encoding/hex"

import "urd:base"
import "urd:cbor"
import "urd:ledger"
import "urd:network"
import "urd:storage/immutable"

USAGE :: `usage: urd <command> [options]

commands:
  bench-decode DIR [--passes N]
          decoding throughput over an ImmutableDB, and allocations in steady state
  diag    print CBOR (a file, or hex with --hex) in diagnostic notation
  fetch   pull blocks from a peer into an ImmutableDB directory
          --network mainnet|preprod|preview   (default preview)
          --peer HOST:PORT                     (default: the network's public relay)
          --out DIR                            (required)
          --blocks N                           (default 10000)
          --from SLOT.HASH                     (default: genesis)
  replay  DIR --genesis FILE [--requires-magic]
          validate an ImmutableDB's Byron era from its genesis (PBFT, ledger rules)
`

Network :: struct {
	name:       string,
	magic:      u32,
	relay:      string,
	// Slots per ImmutableDB chunk (= Byron epoch length 10k).
	chunk_size: u64,
}

NETWORKS := [?]Network {
	{"mainnet", network.MAINNET_MAGIC, "backbone.cardano.iog.io:3001", 21600},
	{"preprod", network.PREPROD_MAGIC, "preprod-node.play.dev.cardano.org:3001", 21600},
	{"preview", network.PREVIEW_MAGIC, "preview-node.play.dev.cardano.org:3001", 4320},
}

// Blocks closer than this to the peer's tip may still roll back; `fetch`
// stops before them.
SECURITY_PARAM :: 2160

main :: proc() {
	args := os.args[1:]
	if len(args) == 0 {
		fmt.eprint(USAGE)
		os.exit(2)
	}
	switch args[0] {
	case "fetch":
		os.exit(fetch(args[1:]))
	case "bench-decode":
		os.exit(bench_decode(args[1:]))
	case "diag":
		os.exit(diag(args[1:]))
	case "replay":
		os.exit(replay(args[1:]))
	case:
		fmt.eprint(USAGE)
		os.exit(2)
	}
}

@(private)
flag :: proc(args: []string, name: string) -> (string, bool) {
	for i := 0; i + 1 < len(args); i += 1 {
		if args[i] == name do return args[i + 1], true
	}
	return "", false
}

@(private)
parse_point :: proc(s: string) -> (p: base.Point, ok: bool) {
	slot_s, _, hash_s := strings.partition(s, ".")
	slot := strconv.parse_u64(slot_s) or_return
	if len(hash_s) != 64 do return {}, false
	for i in 0 ..< 32 {
		b := strconv.parse_u64_of_base(hash_s[2 * i:][:2], 16) or_return
		p.hash[i] = u8(b)
	}
	p.slot = base.Slot(slot)
	return p, true
}

Fetch_State :: struct {
	writer:   ^immutable.Writer,
	expected: []ledger.Block_Info,
	next:     int,
	err:      string,
	// Hash of the last stored block, to check that every block links to it.
	last:     base.Block_Hash,
	has_last: bool,
}

fetch :: proc(args: []string) -> int {
	net_name, _ := flag(args, "--network")
	if net_name == "" do net_name = "preview"
	cfg: Network
	for n in NETWORKS {
		if n.name == net_name do cfg = n
	}
	if cfg.name == "" {
		fmt.eprintfln("unknown network %q", net_name)
		return 2
	}
	peer, has_peer := flag(args, "--peer")
	if !has_peer do peer = cfg.relay
	out, has_out := flag(args, "--out")
	if !has_out {
		fmt.eprint(USAGE)
		return 2
	}
	limit := 10000
	if s, ok := flag(args, "--blocks"); ok {
		limit = strconv.parse_int(s) or_else limit
	}
	start := base.ORIGIN
	if s, ok := flag(args, "--from"); ok {
		p, pok := parse_point(s)
		if !pok {
			fmt.eprintfln("bad --from %q, want SLOT.HASH", s)
			return 2
		}
		start = p
	}

	client: network.Client
	if err := network.client_connect(&client, peer, cfg.magic); err != .None {
		fmt.eprintfln("connect %s: %v", peer, err)
		return 1
	}
	defer network.client_close(&client)
	fmt.printfln("connected to %s (node-to-node v%d)", peer, client.version)

	found, at, tip, ierr := network.client_find_intersect(&client, {start})
	if ierr != .None || !found {
		fmt.eprintfln("no intersection at %v (%v)", start, ierr)
		return 1
	}
	fmt.printfln(
		"intersection at slot %d; peer tip at slot %d, block %d",
		u64(at.slot),
		u64(tip.point.slot),
		tip.block_no,
	)

	w: immutable.Writer
	if immutable.writer_init(&w, out, cfg.chunk_size) != .None {
		fmt.eprintfln("cannot create %s", out)
		return 1
	}
	defer immutable.writer_close(&w)

	BATCH :: 500
	PIPELINE :: 100
	infos := make([dynamic]ledger.Block_Info, 0, BATCH)
	headers := make([dynamic][]u8, 0, BATCH)
	defer {
		for h in headers do delete(h)
		delete(headers)
		delete(infos)
	}

	fetched := 0
	began := time.tick_now()
	link: base.Block_Hash
	has_link := false
	done := false
	for !done && fetched < limit {
		phase := time.tick_now()
		for h in headers do delete(h)
		clear(&headers)
		clear(&infos)
		for len(infos) < BATCH && fetched + len(infos) < limit {
			reply, err := network.client_next_header(&client, PIPELINE)
			if err != .None {
				fmt.eprintfln("chain-sync: %v", err)
				return 1
			}
			if reply.kind == .Roll_Backward {
				if fetched == 0 && len(infos) == 0 && reply.point == at {
					continue
				}
				fmt.eprintfln("peer rolled back to slot %d; stopping", u64(reply.point.slot))
				done = true
				break
			}
			// Keep our own copy: the reply aliases the mux buffer.
			wrapped := strings.clone(string(reply.header))
			info, derr := ledger.decode_wrapped_header(transmute([]u8)wrapped)
			if derr != .None {
				fmt.eprintfln("bad header: %v", derr)
				return 1
			}
			append(&headers, transmute([]u8)wrapped)
			append(&infos, info)
			if reply.tip.block_no - info.block_no < SECURITY_PARAM {
				done = true
				break
			}
		}
		if len(infos) == 0 do break

		header_secs := time.duration_seconds(time.tick_since(phase))
		phase = time.tick_now()
		state := Fetch_State {
			writer   = &w,
			expected = infos[:],
			last     = link,
			has_last = has_link,
		}
		ok, ferr := network.client_fetch_range(
			&client,
			infos[0].point,
			infos[len(infos) - 1].point,
			store_block,
			&state,
		)
		if ferr != .None || !ok || state.err != "" || state.next != len(infos) {
			fmt.eprintfln("block-fetch: %v %v %s (%d/%d)", ferr, ok, state.err, state.next, len(infos))
			return 1
		}
		fetched += len(infos)
		link, has_link = state.last, state.has_last
		last := infos[len(infos) - 1]
		secs := time.duration_seconds(time.tick_since(began))
		fmt.printfln(
			"%d blocks, slot %d, %v, %.0f blocks/s (headers %.2fs, blocks %.2fs)",
			fetched,
			u64(last.point.slot),
			last.era,
			f64(fetched) / secs,
			header_secs,
			time.duration_seconds(time.tick_since(phase)),
		)
	}
	return 0
}

store_block :: proc(block: []u8, user: rawptr) -> bool {
	s := (^Fetch_State)(user)
	if s.next >= len(s.expected) {
		s.err = "more blocks than requested"
		return false
	}
	info, header_offset, err := ledger.decode_block_info(block)
	if err != .None {
		s.err = fmt.tprintf("undecodable block: %v", err)
		return false
	}
	want := s.expected[s.next]
	if info.point != want.point {
		s.err = fmt.tprintf("block %d is not the announced one", s.next)
		return false
	}
	if s.has_last && (!info.has_prev || info.prev != s.last) {
		s.err = fmt.tprintf("block at slot %d does not link to its predecessor", u64(info.point.slot))
		return false
	}
	s.last, s.has_last = info.point.hash, true
	epoch: u64
	if info.is_ebb {
		epoch = u64(info.point.slot) / s.writer.chunk_size
	}
	werr := immutable.writer_append(
		s.writer,
		block,
		immutable.Append_Info {
			hash = info.point.hash,
			slot = u64(info.point.slot),
			epoch = epoch,
			is_ebb = info.is_ebb,
			header_offset = u16(header_offset),
			header_size = u16(len(info.header)),
		},
	)
	if werr != .None {
		s.err = fmt.tprintf("write: %v", werr)
		return false
	}
	s.next += 1
	return true
}

diag :: proc(args: []string) -> int {
	if len(args) == 0 {
		fmt.eprint(USAGE)
		return 2
	}
	data: []u8
	if args[0] == "--hex" && len(args) > 1 {
		ok: bool
		data, ok = hex.decode(transmute([]u8)strings.trim_space(args[1]))
		if !ok {
			fmt.eprintln("bad hex")
			return 2
		}
	} else {
		raw, err := os.read_entire_file(args[0], context.allocator)
		if err != nil {
			fmt.eprintfln("cannot read %s", args[0])
			return 1
		}
		data = raw
		// Accept files holding hex text too.
		if h, ok := hex.decode(transmute([]u8)strings.trim_space(string(raw))); ok {
			data = h
		}
	}
	fmt.println(cbor.diagnose(data))
	return 0
}

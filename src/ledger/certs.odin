package ledger

import "core:slice"

import "urd:base"
import "urd:cbor"

// Certificates, docs/decoding/txbody.md §6.

Cert_Kind :: enum u8 {
	Stake_Registration        = 0,
	Stake_Deregistration      = 1,
	Stake_Delegation          = 2,
	Pool_Registration         = 3,
	Pool_Retirement           = 4,
	Genesis_Delegation        = 5,
	Mir                       = 6,
	Reg_Deposit               = 7,
	Unreg_Deposit             = 8,
	Vote_Delegation           = 9,
	Stake_Vote_Delegation     = 10,
	Stake_Reg_Delegation      = 11,
	Vote_Reg_Delegation       = 12,
	Stake_Vote_Reg_Delegation = 13,
	Committee_Hot_Auth        = 14,
	Committee_Cold_Resign     = 15,
	Drep_Registration         = 16,
	Drep_Deregistration       = 17,
	Drep_Update               = 18,
}

Drep_Kind :: enum u8 {
	Key_Hash      = 0,
	Script_Hash   = 1,
	Abstain       = 2,
	No_Confidence = 3,
}

Drep :: struct {
	hash: base.Hash28,
	kind: Drep_Kind,
}

// A certificate. Which fields are meaningful depends on `kind`:
//   cred:   the stake, DRep or committee cold credential
//   hot:    the committee hot credential (14)
//   pool:   pool id (2, 4, 10, 11, 13); the genesis key hash (5)
//   drep:   (9, 10, 12, 13)
//   coin:   deposit or refund (7, 8, 11, 12, 13, 16, 17)
//   epoch:  retirement epoch (4)
//   anchor: (15, 16, 18)
//   index:  into pool_params (3), genesis_delegs (5) or mirs (6)
Cert :: struct {
	kind:   Cert_Kind,
	cred:   Credential,
	hot:    Credential,
	pool:   base.Hash28,
	drep:   Drep,
	coin:   u64,
	epoch:  u64,
	anchor: Anchor,
	index:  u32,
}

Pool_Params :: struct {
	operator:       base.Hash28,
	vrf_key_hash:   base.Hash32,
	pledge:         u64,
	cost:           u64,
	margin:         Ratio,
	reward_account: Reward_Account,
	// Into key_hashes, sorted and unique.
	owners:         Range,
	// The relays list as it appears in the certificate.
	relays:         base.Span,
	has_metadata:   bool,
	metadata_url:   base.Span,
	// Any length at decode time; > 32 bytes is a POOL rule failure.
	metadata_hash:  base.Span,
}

Genesis_Delegation :: struct {
	genesis:      base.Hash28,
	delegate:     base.Hash28,
	vrf_key_hash: base.Hash32,
}

Mir_Pot :: enum u8 {
	Reserves = 0,
	Treasury = 1,
}

Mir :: struct {
	pot:          Mir_Pot,
	// Either a transfer to the other pot of `coin`, or per-credential deltas.
	to_other_pot: bool,
	coin:         u64,
	entries:      Range,
}

Mir_Entry :: struct {
	cred:  Credential,
	// DeltaCoin is an unbounded Integer on the wire.
	// TODO(conformance): values outside i128 are rejected here but decode in
	// Haskell; only genesis-delegate-signed MIR certificates could carry them.
	delta: i128,
}

read_drep :: proc "contextless" (d: ^Decoder) -> (r: Drep, err: Error) {
	tag, c := read_sum(d) or_return
	switch tag {
	case 0, 1:
		r.kind = Drep_Kind(tag)
		r.hash = read_hash28(d) or_return
		end_sum(d, c, 1) or_return
	case 2, 3:
		r.kind = Drep_Kind(tag)
		end_sum(d, c, 0) or_return
	case:
		return {}, .Invalid_Value
	}
	return r, .None
}

// Shelley-family TxCert (Shelley through Babbage) or ConwayTxCert.
read_cert :: proc(d: ^Decoder) -> (cert: Cert, err: Error) {
	tag, c := read_sum(d) or_return
	if tag > 18 || (d.era < .Conway && tag > 6) {
		return {}, .Invalid_Value
	}
	cert.kind = Cert_Kind(tag)
	fields := 0
	switch cert.kind {
	case .Stake_Registration, .Stake_Deregistration:
		cert.cred = read_credential(d) or_return
		fields = 1
	case .Stake_Delegation:
		cert.cred = read_credential(d) or_return
		cert.pool = read_hash28(d) or_return
		fields = 2
	case .Pool_Registration:
		cert.index = u32(len(d.t.pool_params))
		pp := read_pool_params(d) or_return
		append(&d.t.pool_params, pp)
		fields = 9
	case .Pool_Retirement:
		cert.pool = read_hash28(d) or_return
		cert.epoch = cbor.read_uint(&d.r) or_return
		fields = 2
	case .Genesis_Delegation:
		if d.era >= .Conway do return {}, .Invalid_Value
		g: Genesis_Delegation
		g.genesis = read_hash28(d) or_return
		g.delegate = read_hash28(d) or_return
		g.vrf_key_hash = read_hash32(d) or_return
		cert.pool = g.genesis
		cert.index = u32(len(d.t.genesis_delegs))
		append(&d.t.genesis_delegs, g)
		fields = 3
	case .Mir:
		if d.era >= .Conway do return {}, .Invalid_Value
		cert.index = u32(len(d.t.mirs))
		m := read_mir(d) or_return
		append(&d.t.mirs, m)
		fields = 1
	case .Reg_Deposit, .Unreg_Deposit:
		cert.cred = read_credential(d) or_return
		cert.coin = read_coin(d) or_return
		fields = 2
	case .Vote_Delegation:
		cert.cred = read_credential(d) or_return
		cert.drep = read_drep(d) or_return
		fields = 2
	case .Stake_Vote_Delegation:
		cert.cred = read_credential(d) or_return
		cert.pool = read_hash28(d) or_return
		cert.drep = read_drep(d) or_return
		fields = 3
	case .Stake_Reg_Delegation:
		cert.cred = read_credential(d) or_return
		cert.pool = read_hash28(d) or_return
		cert.coin = read_coin(d) or_return
		fields = 3
	case .Vote_Reg_Delegation:
		cert.cred = read_credential(d) or_return
		cert.drep = read_drep(d) or_return
		cert.coin = read_coin(d) or_return
		fields = 3
	case .Stake_Vote_Reg_Delegation:
		cert.cred = read_credential(d) or_return
		cert.pool = read_hash28(d) or_return
		cert.drep = read_drep(d) or_return
		cert.coin = read_coin(d) or_return
		fields = 4
	case .Committee_Hot_Auth:
		cert.cred = read_credential(d) or_return
		cert.hot = read_credential(d) or_return
		fields = 2
	case .Committee_Cold_Resign:
		cert.cred = read_credential(d) or_return
		cert.anchor = read_nullable_anchor(d) or_return
		fields = 2
	case .Drep_Registration:
		cert.cred = read_credential(d) or_return
		cert.coin = read_coin(d) or_return
		cert.anchor = read_nullable_anchor(d) or_return
		fields = 3
	case .Drep_Deregistration:
		cert.cred = read_credential(d) or_return
		cert.coin = read_coin(d) or_return
		fields = 2
	case .Drep_Update:
		cert.cred = read_credential(d) or_return
		cert.anchor = read_nullable_anchor(d) or_return
		fields = 2
	}
	end_sum(d, c, fields) or_return
	return cert, .None
}

// decodeStakePoolParamsFlat: nine fields inlined in the certificate array.
@(private = "file")
read_pool_params :: proc(d: ^Decoder) -> (p: Pool_Params, err: Error) {
	p.operator = read_hash28(d) or_return
	p.vrf_key_hash = read_hash32(d) or_return
	p.pledge = read_coin(d) or_return
	p.cost = read_coin(d) or_return
	p.margin = read_interval(d, .Unit) or_return
	p.reward_account = read_reward_account(d) or_return

	p.owners.start = u32(len(d.t.key_hashes))
	owners := read_set(d) or_return
	for cbor.more(&d.r, &owners) {
		append(&d.t.key_hashes, base.Key_Hash(read_hash28(d) or_return))
	}
	n := sort_unique_key_hashes(d, d.t.key_hashes[p.owners.start:]) or_return
	resize(&d.t.key_hashes, int(p.owners.start) + n)
	p.owners.count = u32(n)

	start := d.r.pos
	relays := cbor.read_array(&d.r) or_return
	for cbor.more(&d.r, &relays) {
		read_relay(d) or_return
	}
	p.relays = span_from(d, start)

	if read_null_or(d) {
		p.has_metadata = true
		md := read_rec(d, 2) or_return
		url := read_bounded_text(d, url_limit(d)) or_return
		p.metadata_url = span(d, url)
		h := cbor.read_bytes(&d.r) or_return
		p.metadata_hash = span(d, h)
		cbor.end(&d.r, md) or_return
	}
	return p, .None
}

@(private = "file")
read_relay :: proc "contextless" (d: ^Decoder) -> Error {
	tag, c := read_sum(d) or_return
	switch tag {
	case 0:
		if read_null_or(d) do _ = cbor.read_u16(&d.r) or_return
		if read_null_or(d) do _ = cbor.read_bytes_n(&d.r, 4) or_return
		if read_null_or(d) do _ = cbor.read_bytes_n(&d.r, 16) or_return
		return end_sum(d, c, 3)
	case 1:
		if read_null_or(d) do _ = cbor.read_u16(&d.r) or_return
		_ = read_bounded_text(d, url_limit(d)) or_return
		return end_sum(d, c, 2)
	case 2:
		_ = read_bounded_text(d, url_limit(d)) or_return
		return end_sum(d, c, 1)
	}
	return .Invalid_Value
}

// MIRCert: Rec [pot, target]; the target is a map of credential deltas or a
// coin sent to the other pot.
@(private = "file")
read_mir :: proc(d: ^Decoder) -> (m: Mir, err: Error) {
	c := read_rec(d, 2) or_return
	pot := cbor.read_uint(&d.r) or_return
	if pot > 1 do return {}, .Invalid_Value
	m.pot = Mir_Pot(pot)
	mj := cbor.peek_major(&d.r) or_return
	if mj == .Map {
		m.entries.start = u32(len(d.t.mir_entries))
		mp := cbor.read_map(&d.r) or_return
		for cbor.more(&d.r, &mp) {
			e: Mir_Entry
			e.cred = read_credential(d) or_return
			v := cbor.read_integer(&d.r) or_return
			if v.big != nil do return {}, .Overflow
			e.delta = -1 - i128(v.small) if v.negative else i128(v.small)
			append(&d.t.mir_entries, e)
		}
		// Map.fromList: the last delta of a repeated credential wins.
		entries := d.t.mir_entries[m.entries.start:]
		n := sort_last_wins(entries, proc(a, b: Mir_Entry) -> bool {return credential_less(a.cred, b.cred)})
		resize(&d.t.mir_entries, int(m.entries.start) + n)
		m.entries.count = u32(n)
	} else {
		m.to_other_pot = true
		m.coin = read_coin(d) or_return
	}
	cbor.end(&d.r, c) or_return
	return m, .None
}

// Sorts a set of key hashes in place. Below v9 duplicates are merged; from v9
// they fail. Returns the unique count.
sort_unique_key_hashes :: proc(d: ^Decoder, xs: []base.Key_Hash) -> (n: int, err: Error) {
	slice.sort_by(xs, proc(a, b: base.Key_Hash) -> bool {return hash28_less(base.Hash28(a), base.Hash28(b))})
	return unique_sorted(d, xs)
}

// Removes adjacent duplicates of a sorted slice (below v9) or fails on them
// (from v9). Returns the new length.
unique_sorted :: proc "contextless" (d: ^Decoder, xs: []$T) -> (n: int, err: Error) {
	for i in 0 ..< len(xs) {
		if n > 0 && xs[n - 1] == xs[i] {
			if d.v >= 9 do return 0, .Duplicate_Key
			continue
		}
		xs[n] = xs[i]
		n += 1
	}
	return n, .None
}

// Map.fromList over decoded key-value rows: stable-sorts by key and keeps the
// last row of each key. Returns the new length.
sort_last_wins :: proc(xs: []$T, less: proc(a, b: T) -> bool) -> int {
	slice.stable_sort_by(xs, less)
	n := 0
	for i in 0 ..< len(xs) {
		if i + 1 < len(xs) && !less(xs[i], xs[i + 1]) {
			continue // equal key follows: a later row wins
		}
		xs[n] = xs[i]
		n += 1
	}
	return n
}

// Like `sort_last_wins`, but from v9 a repeated key fails instead.
sort_map_rows :: proc(d: ^Decoder, xs: []$T, less: proc(a, b: T) -> bool) -> (n: int, err: Error) {
	if d.v >= 9 {
		slice.sort_by(xs, less)
		for i in 1 ..< len(xs) {
			if !less(xs[i - 1], xs[i]) do return 0, .Duplicate_Key
		}
		return len(xs), .None
	}
	return sort_last_wins(xs, less), .None
}

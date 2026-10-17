package ledger

import "core:slice"

import "urd:base"
import "urd:cbor"

// Values and multi-assets, docs/decoding/txbody.md §5
// (cardano-ledger mary Cardano/Ledger/Mary/Value.hs).

ASSET_NAME_MAX :: 32

// One multi-asset entry of an output value (quantity in 1..2^64-1) or of a
// mint (non-zero Int64), flattened across the block. Names are at most 32
// bytes, so they are stored inline. Within each value or mint the entries are
// kept in the ledger's map order: by policy, then by name.
Asset :: struct {
	quantity: i128,
	policy:   base.Hash28,
	name:     [ASSET_NAME_MAX]u8,
	name_len: u8,
	// Decode order, used to resolve duplicate keys; meaningless afterwards.
	group:    u32,
	seq:      u32,
}

asset_name :: #force_inline proc "contextless" (a: ^Asset) -> []u8 {
	return a.name[:a.name_len]
}

// `decodeMaryValue`: a Word64 coin, or a RecD pair [coin, multiasset] whose
// quantities are Word64. Before Mary the value is always a plain coin.
read_value :: proc(d: ^Decoder, assets: ^[dynamic]Asset) -> (coin: u64, entries: Range, err: Error) {
	entries.start = u32(len(assets))
	if d.era < .Mary {
		coin = read_coin(d) or_return
		return
	}
	m := cbor.peek_major(&d.r) or_return
	#partial switch m {
	case .Unsigned:
		coin = read_coin(d) or_return
		return
	case .Array:
	case:
		return 0, {}, .Unexpected_Major
	}
	read_recd(d, 2) or_return
	coin = read_coin(d) or_return
	read_multi_asset(d, assets, .Output) or_return
	entries.count = u32(len(assets)) - entries.start
	return
}

Quantity_Kind :: enum u8 {
	// TxOut value: Word64.
	Output,
	// Mint: decodeIntegerBounded64, major 0/1 within Int64, no bignums.
	Mint,
}

// `decodeMultiAsset`: { policy => { asset_name => quantity } }.
//
// Below v9 duplicate keys are last-wins (a repeated policy replaces the whole
// inner map), zero quantities are pruned, and inner maps left empty are
// dropped. From v9 duplicates, zeros and empty inner maps fail; an empty outer
// map decodes. In every era the pruned result must fit the compact form:
// 44 * assets + 28 * policies <= 65535.
read_multi_asset :: proc(d: ^Decoder, out: ^[dynamic]Asset, kind: Quantity_Kind) -> Error {
	start := len(out)
	seq: u32
	group: u32
	outer := cbor.read_map(&d.r) or_return
	for cbor.more(&d.r, &outer) {
		policy := read_hash28(d) or_return
		inner := cbor.read_map(&d.r) or_return
		n := 0
		for cbor.more(&d.r, &inner) {
			name := cbor.read_bytes(&d.r) or_return
			if len(name) > ASSET_NAME_MAX {
				return .Invalid_Value
			}
			q: i128
			switch kind {
			case .Output:
				q = i128(cbor.read_uint(&d.r) or_return)
			case .Mint:
				q = i128(cbor.read_int(&d.r) or_return)
			}
			if q == 0 && d.v >= 9 {
				return .Invalid_Value
			}
			a := Asset {
				quantity = q,
				policy   = policy,
				name_len = u8(len(name)),
				group    = group,
				seq      = seq,
			}
			copy(a.name[:], name)
			append(out, a)
			seq += 1
			n += 1
		}
		if n == 0 && d.v >= 9 {
			return .Empty
		}
		group += 1
	}

	xs := out[start:]
	slice.sort_by(xs, proc(a, b: Asset) -> bool {
		a, b := a, b
		if a.policy != b.policy do return hash28_less(a.policy, b.policy)
		if a.group != b.group do return a.group < b.group
		an, bn := a.name[:a.name_len], b.name[:b.name_len]
		if string(an) != string(bn) do return string(an) < string(bn)
		return a.seq < b.seq
	})

	// Keep, for each policy, only its last group; within it, the last entry
	// of each name. From v9 any such duplicate is an error instead.
	w := 0
	policies := 0
	i := 0
	for i < len(xs) {
		j := i
		for j < len(xs) && xs[j].policy == xs[i].policy do j += 1
		last_group := xs[j - 1].group
		if last_group != xs[i].group && d.v >= 9 {
			return .Duplicate_Key
		}
		kept := 0
		for k in i ..< j {
			if xs[k].group != last_group do continue
			same_next := k + 1 < j && string(asset_name(&xs[k])) == string(asset_name(&xs[k + 1]))
			if same_next {
				if d.v >= 9 do return .Duplicate_Key
				continue
			}
			if xs[k].quantity == 0 do continue // pruned (below v9 only)
			xs[w] = xs[k]
			w += 1
			kept += 1
		}
		if kept > 0 do policies += 1
		i = j
	}
	resize(out, start + w)

	if 44 * w + 28 * policies > 65535 {
		return .Invalid_Value
	}
	return .None
}

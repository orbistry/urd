package ledger

import "core:slice"

import "urd:base"
import "urd:cbor"

// Values and multi-assets, docs/decoding/txbody.md §5
// (cardano-ledger mary Cardano/Ledger/Mary/Value.hs).
//
// The ledger's quantities are Haskell `Integer`s, but the decoders bound
// them: output quantities are Word64 and mint quantities Int64, so each fits
// 64 bits exactly. Arithmetic over them (value preservation) must use i128
// accumulators: a transaction has fewer than 2^32 terms (maxTxSize is a
// Word32), each below 2^64, so every sum stays under 2^96 and i128 matches the
// unbounded Haskell arithmetic.

ASSET_NAME_MAX :: 32

// One multi-asset entry of an output value, flattened across the block. Names
// are at most 32 bytes, so they are stored inline. Within each value the
// entries are in the ledger's map order: by policy, then by name.
Asset :: struct {
	quantity: u64,
	policy:   base.Hash28,
	name:     [ASSET_NAME_MAX]u8,
	name_len: u8,
}

// One minted (positive) or burned (negative) asset; never zero after decoding.
Mint :: struct {
	quantity: i64,
	policy:   base.Hash28,
	name:     [ASSET_NAME_MAX]u8,
	name_len: u8,
}

asset_name :: #force_inline proc "contextless" (a: ^$T) -> []u8 where T == Asset || T == Mint {
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
	read_multi_asset(d, assets) or_return
	entries.count = u32(len(assets)) - entries.start
	return
}

// A decoded entry before duplicate keys are resolved: `group` numbers the
// occurrences of outer (policy) keys in decode order.
@(private = "file")
Pending :: struct($T: typeid) {
	row:   T,
	group: u32,
}

// `decodeMultiAsset`: { policy => { asset_name => quantity } }, appending the
// resolved rows to `out` (`Asset` for output values, `Mint` for the mint
// field, which uses decodeIntegerBounded64: major 0/1 within Int64, no
// bignums).
//
// Below v9 duplicate keys are last-wins (a repeated policy replaces the whole
// inner map), zero quantities are pruned, and inner maps left empty are
// dropped. From v9 duplicates, zeros and empty inner maps fail; an empty outer
// map decodes. In every era the pruned result must fit the compact form:
// 44 * assets + 28 * policies <= 65535.
read_multi_asset :: proc(d: ^Decoder, out: ^[dynamic]$T) -> Error where T == Asset || T == Mint {
	pending := make([dynamic]Pending(T), d.scratch)
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
			row := T {
				policy   = policy,
				name_len = u8(len(name)),
			}
			copy(row.name[:], name)
			when T == Asset {
				row.quantity = cbor.read_uint(&d.r) or_return
			} else {
				row.quantity = cbor.read_int(&d.r) or_return
			}
			if row.quantity == 0 && d.v >= 9 {
				return .Invalid_Value
			}
			append(&pending, Pending(T){row = row, group = group})
			n += 1
		}
		if n == 0 && d.v >= 9 {
			return .Empty
		}
		group += 1
	}

	// Stable: entries with equal keys keep their decode order, so the last of
	// a run is the last decoded.
	slice.stable_sort_by(pending[:], proc(a, b: Pending(T)) -> bool {
		a, b := a, b
		if a.row.policy != b.row.policy do return hash28_less(a.row.policy, b.row.policy)
		if a.group != b.group do return a.group < b.group
		return string(asset_name(&a.row)) < string(asset_name(&b.row))
	})

	// Keep, for each policy, only its last group; within it, the last entry
	// of each name. From v9 any such duplicate is an error instead.
	start := len(out)
	policies := 0
	xs := pending[:]
	i := 0
	for i < len(xs) {
		j := i
		for j < len(xs) && xs[j].row.policy == xs[i].row.policy do j += 1
		last_group := xs[j - 1].group
		if last_group != xs[i].group && d.v >= 9 {
			return .Duplicate_Key
		}
		kept := 0
		for k in i ..< j {
			if xs[k].group != last_group do continue
			if k + 1 < j && string(asset_name(&xs[k].row)) == string(asset_name(&xs[k + 1].row)) {
				if d.v >= 9 do return .Duplicate_Key
				continue
			}
			if xs[k].row.quantity == 0 do continue // pruned (below v9 only)
			append(out, xs[k].row)
			kept += 1
		}
		if kept > 0 do policies += 1
		i = j
	}

	if 44 * (len(out) - start) + 28 * policies > 65535 {
		return .Invalid_Value
	}
	return .None
}

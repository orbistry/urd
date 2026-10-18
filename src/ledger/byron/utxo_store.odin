package byron

import "urd:base"

// The Byron UTxO, held in memory until the on-disk table engine exists
// (ARCHITECTURE.md, ledger state on disk). Rules never touch it directly:
// a block is validated against the entries its inputs resolve to, and the
// resulting diff is applied afterwards (`utxo_apply`).
//
// Entries are 16 bytes; address bytes live in one arena, compacted when more
// than half of it is dead.

Utxo_Entry :: struct {
	lovelace: u64,
	addr_off: u32,
	addr_len: u32,
}

Utxo :: struct {
	entries: map[base.Tx_In]Utxo_Entry,
	addrs:   [dynamic]u8,
	// Bytes of `addrs` no entry refers to any more.
	dead:    int,
	// Sum of every entry's lovelace.
	total:   u64,
}

utxo_init :: proc(u: ^Utxo, allocator := context.allocator) {
	u.entries = make(map[base.Tx_In]Utxo_Entry, allocator)
	u.addrs = make([dynamic]u8, allocator)
}

utxo_destroy :: proc(u: ^Utxo) {
	delete(u.entries)
	delete(u.addrs)
}

utxo_len :: #force_inline proc(u: ^Utxo) -> int {
	return len(u.entries)
}

utxo_get :: #force_inline proc(u: ^Utxo, txin: base.Tx_In) -> (e: Utxo_Entry, ok: bool) {
	return u.entries[txin]
}

utxo_address :: #force_inline proc "contextless" (u: ^Utxo, e: Utxo_Entry) -> []u8 {
	return u.addrs[e.addr_off:][:e.addr_len]
}

// Inserts a new entry; the input must not be present.
utxo_insert :: proc(u: ^Utxo, txin: base.Tx_In, address: []u8, lovelace: u64) {
	e := Utxo_Entry {
		lovelace = lovelace,
		addr_off = u32(len(u.addrs)),
		addr_len = u32(len(address)),
	}
	append(&u.addrs, ..address)
	_, value, just_inserted, _ := map_entry(&u.entries, txin)
	assert(just_inserted, "utxo: input already present")
	value^ = e
	u.total += lovelace
}

// Removes an entry and returns it; the input must be present.
utxo_remove :: proc(u: ^Utxo, txin: base.Tx_In) -> Utxo_Entry {
	e, ok := u.entries[txin]
	assert(ok, "utxo: input not present")
	delete_key(&u.entries, txin)
	u.dead += int(e.addr_len)
	u.total -= e.lovelace
	return e
}

// Rewrites the address arena without dead bytes once they are the majority,
// keeping the amortised cost per removal constant.
utxo_maybe_compact :: proc(u: ^Utxo) {
	if u.dead < 1 << 20 || u.dead * 2 < len(u.addrs) {
		return
	}
	fresh := make([dynamic]u8, 0, len(u.addrs) - u.dead, u.addrs.allocator)
	for txin, e in u.entries {
		off := u32(len(fresh))
		append(&fresh, ..u.addrs[e.addr_off:][:e.addr_len])
		// Not `for _, &e in u.entries`: Odin dev-2026-10 does not write
		// through it when the key holds an array, as Tx_In does.
		(&u.entries[txin]).addr_off = off
	}
	delete(u.addrs)
	u.addrs = fresh
	u.dead = 0
}

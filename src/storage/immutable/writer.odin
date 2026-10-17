package immutable

import "core:encoding/endian"
import "core:hash"
import "core:os"

import "urd:base"

// Appends blocks to an ImmutableDB directory in cardano-node's format.
// Blocks must arrive in chain order.
Writer :: struct {
	dir:        string,
	// Regular slots per chunk (10k: 21600 on mainnet and preprod, 4320 on
	// preview).
	chunk_size: u64,
	chunk:      u32,
	is_open:    bool,
	chunk_file: ^os.File,
	chunk_len:  u64,
	// Secondary-index offset of each relative slot so far, plus the end
	// offset: `len(primary) == last filled relative slot + 2`.
	primary:    [dynamic]u32,
	secondary:  [dynamic]u8,
}

Append_Info :: struct {
	hash:          base.Block_Hash,
	// Slot of the block. An EBB carries the slot of its epoch's first slot.
	slot:          u64,
	// For an EBB, the epoch it opens.
	epoch:         u64,
	is_ebb:        bool,
	header_offset: u16,
	header_size:   u16,
}

writer_init :: proc(w: ^Writer, dir: string, chunk_size: u64, allocator := context.allocator) -> Error {
	if !os.exists(dir) {
		if os.make_directory_all(dir) != nil {
			return .Io
		}
	}
	w.dir = dir
	w.chunk_size = chunk_size
	w.primary = make([dynamic]u32, allocator)
	w.secondary = make([dynamic]u8, allocator)
	return .None
}

// Closes the current chunk. The last chunk is left unfinalised (its primary
// index stops at the last filled slot), as cardano-node leaves it.
writer_close :: proc(w: ^Writer) -> Error {
	err := Error.None
	if w.is_open {
		err = close_chunk(w, finalise = false)
	}
	delete(w.primary)
	delete(w.secondary)
	return err
}

writer_append :: proc(w: ^Writer, block: []u8, info: Append_Info) -> Error {
	chunk := u32(info.slot / w.chunk_size)
	if !w.is_open || chunk != w.chunk {
		if w.is_open {
			if chunk < w.chunk do return .Bad_Offset
			close_chunk(w, finalise = true) or_return
		}
		open_chunk(w, chunk) or_return
	}

	rel := 0 if info.is_ebb else int(info.slot % w.chunk_size) + 1
	if len(w.primary) == 0 {
		append(&w.primary, 0)
	}
	if rel < len(w.primary) - 1 {
		// Relative slots only move forward.
		return .Bad_Offset
	}
	for len(w.primary) - 1 < rel {
		append(&w.primary, w.primary[len(w.primary) - 1])
	}

	entry: [SECONDARY_ENTRY_SIZE]u8
	endian.unchecked_put_u64be(entry[0:], w.chunk_len)
	endian.unchecked_put_u16be(entry[8:], info.header_offset)
	endian.unchecked_put_u16be(entry[10:], info.header_size)
	endian.unchecked_put_u32be(entry[12:], hash.crc32(block))
	h := info.hash
	copy(entry[16:48], h[:])
	endian.unchecked_put_u64be(entry[48:], info.epoch if info.is_ebb else info.slot)
	append(&w.secondary, ..entry[:])
	append(&w.primary, u32(len(w.secondary)))

	n, err := os.write(w.chunk_file, block)
	if err != nil || n != len(block) {
		return .Io
	}
	w.chunk_len += u64(len(block))
	return .None
}

@(private)
open_chunk :: proc(w: ^Writer, chunk: u32) -> Error {
	path_buf: [4096]u8
	f, err := os.open(chunk_path(path_buf[:], w.dir, chunk, "chunk"), {.Write, .Create, .Trunc})
	if err != nil {
		return .Io
	}
	w.chunk_file = f
	w.chunk = chunk
	w.chunk_len = 0
	w.is_open = true
	clear(&w.primary)
	clear(&w.secondary)
	return .None
}

@(private)
close_chunk :: proc(w: ^Writer, finalise: bool) -> Error {
	path_buf: [4096]u8
	os.close(w.chunk_file)
	w.is_open = false

	if finalise {
		// One offset per relative slot (EBB slot + chunk_size regular slots),
		// plus the end offset.
		if len(w.primary) == 0 {
			append(&w.primary, 0)
		}
		for u64(len(w.primary)) < w.chunk_size + 2 {
			append(&w.primary, w.primary[len(w.primary) - 1])
		}
	}
	primary := make([]u8, 1 + 4 * len(w.primary), context.temp_allocator)
	primary[0] = PRIMARY_VERSION
	for off, i in w.primary {
		endian.unchecked_put_u32be(primary[1 + 4 * i:], off)
	}
	if os.write_entire_file(chunk_path(path_buf[:], w.dir, w.chunk, "primary"), primary) != nil {
		return .Io
	}
	if os.write_entire_file(chunk_path(path_buf[:], w.dir, w.chunk, "secondary"), w.secondary[:]) != nil {
		return .Io
	}
	return .None
}

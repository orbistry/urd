// Package immutable reads and writes cardano-node's ImmutableDB format.
//
// The database is a directory of numbered chunks. Each chunk has three files:
//
//	NNNNN.chunk      the blocks, concatenated CBOR (hard-fork wrapped)
//	NNNNN.primary    version byte, then one big-endian u32 per relative slot:
//	                 the offset of that slot's entry in the secondary index
//	NNNNN.secondary  one 56-byte entry per block (see `Entry`)
//
// Relative slot 0 of every chunk is reserved for a Byron epoch boundary
// block; regular slot s lives at relative slot (s mod chunk_size) + 1.
// See ouroboros-consensus Storage/ImmutableDB/Chunks/Layout.hs and
// Impl/Index/{Primary,Secondary}.hs.
package immutable

import "core:encoding/endian"
import "core:fmt"
import "core:hash"
import "core:os"
import "core:slice"

import "urd:base"

PRIMARY_VERSION :: 1
SECONDARY_ENTRY_SIZE :: 56

Error :: enum u8 {
	None,
	Io,
	Bad_Primary,
	Bad_Secondary,
	Bad_Offset,
	Checksum,
}

// One secondary-index entry, i.e. one block.
Entry :: struct {
	block_offset:  u64,
	crc:           u32,
	header_offset: u16,
	header_size:   u16,
	hash:          base.Block_Hash,
	// Slot of a regular block, or epoch number of an EBB.
	slot_or_epoch: u64,
	is_ebb:        bool,
}

// A loaded chunk. Buffers are reused across `chunk_load` calls.
Chunk :: struct {
	number:    u32,
	data:      [dynamic]u8,
	primary:   [dynamic]u8,
	secondary: [dynamic]u8,
	entries:   [dynamic]Entry,
}

chunk_init :: proc(c: ^Chunk, allocator := context.allocator) {
	c.data = make([dynamic]u8, allocator)
	c.primary = make([dynamic]u8, allocator)
	c.secondary = make([dynamic]u8, allocator)
	c.entries = make([dynamic]Entry, allocator)
}

chunk_destroy :: proc(c: ^Chunk) {
	delete(c.data)
	delete(c.primary)
	delete(c.secondary)
	delete(c.entries)
}

// Raw (hard-fork wrapped) bytes of the i-th block of the chunk.
chunk_block :: proc(c: ^Chunk, i: int) -> []u8 {
	start := c.entries[i].block_offset
	end := u64(len(c.data)) if i + 1 == len(c.entries) else c.entries[i + 1].block_offset
	return c.data[start:end]
}

// Header bytes of the i-th block, as recorded by the secondary index.
chunk_header :: proc(c: ^Chunk, i: int) -> []u8 {
	e := &c.entries[i]
	return c.data[e.block_offset + u64(e.header_offset):][:e.header_size]
}

chunk_path :: proc(buf: []u8, dir: string, number: u32, ext: string) -> string {
	return fmt.bprintf(buf, "%s/%05d.%s", dir, number, ext)
}

@(private)
read_into :: proc(buf: ^[dynamic]u8, path: string) -> Error {
	f, oerr := os.open(path)
	if oerr != nil {
		return .Io
	}
	defer os.close(f)
	size, serr := os.file_size(f)
	if serr != nil {
		return .Io
	}
	resize(buf, int(size))
	n, rerr := os.read_full(f, buf[:])
	if rerr != nil || n != int(size) {
		return .Io
	}
	return .None
}

// Loads chunk `number` from `dir` and parses its indices. With `verify`, the
// CRC32 of every block is checked against the secondary index.
chunk_load :: proc(c: ^Chunk, dir: string, number: u32, verify := false) -> Error {
	path_buf: [4096]u8
	c.number = number
	read_into(&c.data, chunk_path(path_buf[:], dir, number, "chunk")) or_return
	read_into(&c.primary, chunk_path(path_buf[:], dir, number, "primary")) or_return
	read_into(&c.secondary, chunk_path(path_buf[:], dir, number, "secondary")) or_return

	if len(c.primary) < 1 + 4 || c.primary[0] != PRIMARY_VERSION || (len(c.primary) - 1) % 4 != 0 {
		return .Bad_Primary
	}
	if len(c.secondary) % SECONDARY_ENTRY_SIZE != 0 {
		return .Bad_Secondary
	}

	// Relative slot 0 is the EBB slot. It is filled iff the second offset
	// moved past the first.
	offsets := c.primary[1:]
	ebb_filled :=
		len(offsets) >= 8 && endian.unchecked_get_u32be(offsets[4:]) > endian.unchecked_get_u32be(offsets[0:])

	n := len(c.secondary) / SECONDARY_ENTRY_SIZE
	resize(&c.entries, n)
	for i in 0 ..< n {
		b := c.secondary[i * SECONDARY_ENTRY_SIZE:]
		e := &c.entries[i]
		e.block_offset = endian.unchecked_get_u64be(b[0:])
		e.header_offset = endian.unchecked_get_u16be(b[8:])
		e.header_size = endian.unchecked_get_u16be(b[10:])
		e.crc = endian.unchecked_get_u32be(b[12:])
		copy(e.hash[:], b[16:48])
		e.slot_or_epoch = endian.unchecked_get_u64be(b[48:])
		e.is_ebb = i == 0 && ebb_filled
		if e.block_offset > u64(len(c.data)) || (i > 0 && e.block_offset <= c.entries[i - 1].block_offset) {
			return .Bad_Offset
		}
		if u64(e.header_offset) + u64(e.header_size) > u64(len(c.data)) - e.block_offset {
			return .Bad_Offset
		}
	}

	if verify {
		for i in 0 ..< n {
			if hash.crc32(chunk_block(c, i)) != c.entries[i].crc {
				return .Checksum
			}
		}
	}
	return .None
}

// Numbers of the chunks present in `dir`, ascending.
list_chunks :: proc(dir: string, allocator := context.allocator) -> (numbers: [dynamic]u32, err: Error) {
	infos, rerr := os.read_all_directory_by_path(dir, context.temp_allocator)
	if rerr != nil {
		return nil, .Io
	}
	numbers = make([dynamic]u32, allocator)
	for fi in infos {
		name := fi.name
		if len(name) != len("00000.chunk") || name[5:] != ".chunk" {
			continue
		}
		v: u32
		ok := true
		for ch in name[:5] {
			if ch < '0' || ch > '9' {
				ok = false
				break
			}
			v = v * 10 + u32(ch - '0')
		}
		if ok {
			append(&numbers, v)
		}
	}
	// Directory order is unspecified.
	slice.sort(numbers[:])
	return numbers, .None
}

// Package crypto holds the hash functions and signature schemes used by the
// ledger and consensus.
package ccrypto

import blake2 "core:crypto/_blake2"

import "urd:base"

@(private)
blake2b_init :: #force_inline proc "contextless" (ctx: ^blake2.Blake2b_Context, size: u8) {
	cfg := blake2.Blake2_Config {
		size = size,
	}
	blake2.init(ctx, &cfg)
}

// Blake2b with a 256-bit digest: block, header, tx, datum and script data
// hashes.
blake2b_256 :: proc "contextless" (data: []u8) -> (h: base.Hash32) {
	ctx: blake2.Blake2b_Context
	blake2b_init(&ctx, 32)
	blake2.update(&ctx, data)
	blake2.final(&ctx, h[:])
	return
}

// Blake2b with a 224-bit digest: key hashes, script hashes, pool ids.
blake2b_224 :: proc "contextless" (data: []u8) -> (h: base.Hash28) {
	ctx: blake2.Blake2b_Context
	blake2b_init(&ctx, 28)
	blake2.update(&ctx, data)
	blake2.final(&ctx, h[:])
	return
}

// Incremental Blake2b-256 for data that is not contiguous.
Blake2b_256 :: struct {
	ctx: blake2.Blake2b_Context,
}

blake2b_256_init :: proc "contextless" (s: ^Blake2b_256) {
	blake2b_init(&s.ctx, 32)
}

blake2b_256_update :: proc "contextless" (s: ^Blake2b_256, data: []u8) {
	blake2.update(&s.ctx, data)
}

blake2b_256_final :: proc "contextless" (s: ^Blake2b_256) -> (h: base.Hash32) {
	blake2.final(&s.ctx, h[:])
	return
}

// Incremental Blake2b-224.
Blake2b_224 :: struct {
	ctx: blake2.Blake2b_Context,
}

blake2b_224_init :: proc "contextless" (s: ^Blake2b_224) {
	blake2b_init(&s.ctx, 28)
}

blake2b_224_update :: proc "contextless" (s: ^Blake2b_224, data: []u8) {
	blake2.update(&s.ctx, data)
}

blake2b_224_final :: proc "contextless" (s: ^Blake2b_224) -> (h: base.Hash28) {
	blake2.final(&s.ctx, h[:])
	return
}

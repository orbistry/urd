package ccrypto

import grp "core:crypto/_edwards25519"
import "core:crypto/sha2"

ED25519_PUBLIC_KEY_SIZE :: 32
ED25519_SIGNATURE_SIZE :: 64

// Ed25519 signature verification with libsodium's semantics
// (crypto_sign_ed25519_verify_detached, built without ED25519_COMPAT), which
// is what cardano-node uses for every Shelley-era signature: vkey witnesses,
// bootstrap witnesses, operational certificates, KES leaves, and the Plutus
// `verifyEd25519Signature` builtin.
//
// The rules, in libsodium's order:
//   1. S must be canonical (S < L).
//   2. R must not be one of the small-order encodings.
//   3. A must be canonical (y < p) and not of small order.
//   4. A must decode to a curve point.
//   5. Cofactorless check: encode([S]B - [k]A) must equal R byte for byte,
//      where k = SHA-512(R || A || M) mod L.
//
// Odin's core:crypto/ed25519 is deliberately different (cofactored equation,
// small-order R accepted), so it must not be used where consensus depends on
// the result.
ed25519_verify :: proc(public_key, msg, signature: []u8) -> bool {
	if len(public_key) != ED25519_PUBLIC_KEY_SIZE || len(signature) != ED25519_SIGNATURE_SIZE {
		return false
	}
	r_bytes := signature[:32]
	s_bytes := signature[32:]

	s: grp.Scalar = ---
	if !grp.sc_set_bytes(&s, s_bytes) {
		return false
	}
	if has_small_order(r_bytes) {
		return false
	}
	if !is_canonical_point(public_key) || has_small_order(public_key) {
		return false
	}
	a: grp.Group_Element = ---
	if !grp.ge_set_bytes(&a, public_key) {
		return false
	}
	grp.ge_negate(&a, &a)

	digest: [64]u8
	ctx: sha2.Context_512
	sha2.init_512(&ctx)
	sha2.update(&ctx, r_bytes)
	sha2.update(&ctx, public_key)
	sha2.update(&ctx, msg)
	sha2.final(&ctx, digest[:])
	k: grp.Scalar = ---
	grp.sc_set_bytes_wide(&k, &digest)

	// R' = [k](-A) + [S]B
	check: grp.Group_Element = ---
	grp.ge_double_scalarmult_basepoint_vartime(&check, &k, &a, &s)
	encoded: [32]u8
	grp.ge_bytes(&check, encoded[:])
	return constant_time_eq(encoded[:], r_bytes)
}

// libsodium's ge25519_is_canonical: the y coordinate (sign bit ignored) is
// below p = 2^255 - 19.
is_canonical_point :: proc "contextless" (s: []u8) -> bool {
	c := u32((s[31] & 0x7f) ~ 0x7f)
	for i := 30; i > 0; i -= 1 {
		c |= u32(s[i] ~ 0xff)
	}
	c = (c - 1) >> 8
	d := (0xed - 1 - u32(s[0])) >> 8
	return 1 - (c & d & 1) == 1
}

// libsodium's ge25519_has_small_order: compares against the encodings of the
// small-order points, including non-canonical ones, ignoring the sign bit.
has_small_order :: proc "contextless" (s: []u8) -> bool {
	@(static, rodata)
	blocklist := [7][32]u8 {
		// 0 (order 4)
		{},
		// 1 (order 1)
		{0 = 0x01},
		// 2707385501144840649318225287225658788936804267575313519463743609750303402022 (order 8)
		{
			0x26,
			0xe8,
			0x95,
			0x8f,
			0xc2,
			0xb2,
			0x27,
			0xb0,
			0x45,
			0xc3,
			0xf4,
			0x89,
			0xf2,
			0xef,
			0x98,
			0xf0,
			0xd5,
			0xdf,
			0xac,
			0x05,
			0xd3,
			0xc6,
			0x33,
			0x39,
			0xb1,
			0x38,
			0x02,
			0x88,
			0x6d,
			0x53,
			0xfc,
			0x05,
		},
		// 55188659117513257062467267217118295137698188065244968500265048394206261417927 (order 8)
		{
			0xc7,
			0x17,
			0x6a,
			0x70,
			0x3d,
			0x4d,
			0xd8,
			0x4f,
			0xba,
			0x3c,
			0x0b,
			0x76,
			0x0d,
			0x10,
			0x67,
			0x0f,
			0x2a,
			0x20,
			0x53,
			0xfa,
			0x2c,
			0x39,
			0xcc,
			0xc6,
			0x4e,
			0xc7,
			0xfd,
			0x77,
			0x92,
			0xac,
			0x03,
			0x7a,
		},
		// p - 1 (order 2)
		{
			0xec,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0x7f,
		},
		// p (= 0, order 4)
		{
			0xed,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0x7f,
		},
		// p + 1 (= 1, order 1)
		{
			0xee,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0xff,
			0x7f,
		},
	}
	c: [7]u32
	for j in 0 ..< 31 {
		for i in 0 ..< 7 {
			c[i] |= u32(s[j] ~ blocklist[i][j])
		}
	}
	for i in 0 ..< 7 {
		c[i] |= u32((s[31] & 0x7f) ~ blocklist[i][31])
	}
	k: u32
	for i in 0 ..< 7 {
		k |= c[i] - 1
	}
	return (k >> 8) & 1 == 1
}

@(private)
constant_time_eq :: proc "contextless" (a, b: []u8) -> bool {
	if len(a) != len(b) {
		return false
	}
	d: u8
	for i in 0 ..< len(a) {
		d |= a[i] ~ b[i]
	}
	return d == 0
}

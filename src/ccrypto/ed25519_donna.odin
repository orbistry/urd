package ccrypto

import grp "core:crypto/_edwards25519"
import field "core:crypto/_fiat/field_curve25519"
import "core:crypto/sha2"

// Ed25519 signature verification with ed25519-donna's semantics
// (`ed25519_sign_open` in crypton's cbits/ed25519/ed25519.c), which is what
// cardano-node uses for every Byron-era signature: cardano-crypto's
// `Cardano.Crypto.Wallet.verify` (extended keys: block signatures, delegation
// certificates, update proposals and votes, vkey witnesses) and crypton's
// `Crypto.PubKey.Ed25519.verify` (redeem witnesses) both end there.
//
// Donna is permissive where libsodium is strict:
//   1. S only needs its top three bits clear (S < 2^253); it is then reduced
//      mod L, so S in [L, 2^253) verifies like S - L.
//   2. A is decoded leniently (`ge25519_unpack_negative_vartime`): y is taken
//      modulo p, so non-canonical encodings (y >= p) are accepted, and the sign
//      bit is ignored when x = 0. Small-order and mixed-order keys are
//      accepted.
//   3. R is not checked on its own.
// The equation is the same cofactorless one: encode([S]B - [k]A) must equal R
// byte for byte, where k = SHA-512(R || A || M) mod L over the bytes as given.
ed25519_verify_donna :: proc(public_key, msg, signature: []u8) -> bool {
	parts := [1][]u8{msg}
	return ed25519_verify_donna_parts(public_key, signature, parts[:])
}

// `ed25519_verify_donna` over the concatenation of `msg_parts`, without
// building the message.
ed25519_verify_donna_parts :: proc(public_key, signature: []u8, msg_parts: [][]u8) -> bool {
	if len(public_key) != ED25519_PUBLIC_KEY_SIZE || len(signature) != ED25519_SIGNATURE_SIZE {
		return false
	}
	r_bytes := signature[:32]
	s_bytes := signature[32:]

	if s_bytes[31] & 0xe0 != 0 {
		return false
	}
	// expand256_modm: S zero-extended and reduced mod L.
	wide: [64]u8
	copy(wide[:32], s_bytes)
	s: grp.Scalar = ---
	grp.sc_set_bytes_wide(&s, &wide)

	a: grp.Group_Element = ---
	if !ge_set_bytes_donna(&a, public_key) {
		return false
	}
	grp.ge_negate(&a, &a)

	digest: [64]u8
	ctx: sha2.Context_512
	sha2.init_512(&ctx)
	sha2.update(&ctx, r_bytes)
	sha2.update(&ctx, public_key)
	for part in msg_parts {
		sha2.update(&ctx, part)
	}
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

// Point decoding as donna does it: y from the low 255 bits (arithmetic is mod
// p, so y >= p acts as y - p), x from the curve equation, and x negated when
// its parity differs from the sign bit (a no-op for x = 0). No canonicity
// check, unlike `grp.ge_set_bytes`.
@(private)
ge_set_bytes_donna :: proc "contextless" (ge: ^grp.Group_Element, b: []u8) -> bool {
	field.fe_from_bytes(&ge.y, (^[32]u8)(raw_data(b)))
	field.fe_one(&ge.z)

	// x^2 = (y^2 - 1) / (d * y^2 + 1)
	num, den: field.Tight_Field_Element = ---, ---
	field.fe_carry_square(&num, field.fe_relax_cast(&ge.y))
	field.fe_carry_mul(&den, field.fe_relax_cast(&num), field.fe_relax_cast(&grp.FE_D))
	field.fe_carry_sub(&num, &num, &ge.z)
	field.fe_carry_add(&den, &den, &ge.z)
	if field.fe_carry_sqrt_ratio_m1(&ge.x, field.fe_relax_cast(&num), field.fe_relax_cast(&den)) == 0 {
		return false
	}
	// The root is the non-negative one; flip it to the encoded parity.
	field.fe_cond_negate(&ge.x, &ge.x, int(b[31] >> 7))
	field.fe_carry_mul(&ge.t, field.fe_relax_cast(&ge.x), field.fe_relax_cast(&ge.y))
	return true
}

package ccrypto

import grp "core:crypto/_edwards25519"
import field "core:crypto/_fiat/field_curve25519"
import "core:crypto/sha2"

// ECVRF-ED25519-SHA512-Elligator2, IETF draft-03, as implemented by the libsodium
// fork that cardano-node links (cardano-base/cardano-crypto-praos/cbits/vrf03).
// This is the VRF of every TPraos and Praos header so far.

VRF_PUBLIC_KEY_SIZE :: 32
VRF03_PROOF_SIZE :: 80
VRF_OUTPUT_SIZE :: 64

@(private = "file")
SUITE :: 0x04

// Verifies `proof` for `alpha` under `public_key` and returns the VRF output
// (beta). Mirrors crypto_vrf_ietfdraft03_verify.
vrf03_verify :: proc(public_key, proof, alpha: []u8) -> (beta: [VRF_OUTPUT_SIZE]u8, ok: bool) {
	if len(public_key) != VRF_PUBLIC_KEY_SIZE || len(proof) != VRF03_PROOF_SIZE {
		return
	}
	if has_small_order(public_key) || !is_canonical_point(public_key) {
		return
	}
	y: grp.Group_Element = ---
	if !grp.ge_set_bytes(&y, public_key) {
		return
	}
	gamma: grp.Group_Element = ---
	if !decode_gamma(&gamma, proof) {
		return
	}

	// c = proof[32:48] (zero-extended), s = proof[48:80] (must be < L).
	c_bytes: [32]u8
	copy(c_bytes[:16], proof[32:48])
	c, s: grp.Scalar = ---, ---
	if !grp.sc_set_bytes(&c, c_bytes[:]) || !grp.sc_set_bytes(&s, proof[48:80]) {
		return
	}

	// H = hash_to_curve(Y, alpha), libsodium style: the sign bit of the hash is
	// cleared before Elligator2, so the point's x is always made non-negative.
	r_string: [64]u8
	ctx: sha2.Context_512
	sha2.init_512(&ctx)
	sha2.update(&ctx, {SUITE, 0x01})
	sha2.update(&ctx, public_key)
	sha2.update(&ctx, alpha)
	sha2.final(&ctx, r_string[:])
	r_string[31] &= 0x7f
	h: grp.Group_Element = ---
	h_string: [32]u8
	from_uniform(&h, h_string[:], r_string[:32])

	// U = [s]B - [c]Y, V = [s]H - [c]Gamma
	cn: grp.Scalar = ---
	grp.sc_negate(&cn, &c)
	u, v, t: grp.Group_Element = ---, ---, ---
	grp.ge_double_scalarmult_basepoint_vartime(&u, &cn, &y, &s)
	grp.ge_scalarmult_vartime(&v, &h, &s)
	grp.ge_scalarmult_vartime(&t, &gamma, &cn)
	grp.ge_add(&v, &v, &t)
	u_string, v_string: [32]u8
	grp.ge_bytes(&u, u_string[:])
	grp.ge_bytes(&v, v_string[:])

	hram: [64]u8
	sha2.init_512(&ctx)
	sha2.update(&ctx, {SUITE, 0x02})
	sha2.update(&ctx, h_string[:])
	sha2.update(&ctx, proof[:32])
	sha2.update(&ctx, u_string[:])
	sha2.update(&ctx, v_string[:])
	sha2.final(&ctx, hram[:])
	if !constant_time_eq(hram[:16], proof[32:48]) {
		return
	}
	return proof_to_hash(&gamma), true
}

// VRF output of a proof, without verifying it (crypto_vrf_ietfdraft03_proof_to_hash).
vrf03_proof_to_hash :: proc(proof: []u8) -> (beta: [VRF_OUTPUT_SIZE]u8, ok: bool) {
	if len(proof) != VRF03_PROOF_SIZE {
		return
	}
	gamma: grp.Group_Element = ---
	if !decode_gamma(&gamma, proof) {
		return
	}
	s: grp.Scalar = ---
	if !grp.sc_set_bytes(&s, proof[48:80]) {
		return
	}
	return proof_to_hash(&gamma), true
}

// Gamma must be a canonical encoding of a curve point. libsodium also accepts
// the "negative zero" encodings of the two points with x = 0, which Odin's
// decoder rejects; no proof carrying such a Gamma can verify, so the results
// agree.
@(private = "file")
decode_gamma :: proc "contextless" (gamma: ^grp.Group_Element, proof: []u8) -> bool {
	return is_canonical_point(proof[:32]) && grp.ge_set_bytes(gamma, proof[:32])
}

// beta = SHA-512(SUITE || 0x03 || encode(8 * Gamma))
@(private = "file")
proof_to_hash :: proc(gamma: ^grp.Group_Element) -> (beta: [VRF_OUTPUT_SIZE]u8) {
	g := gamma^
	clear_cofactor(&g)
	g_string: [32]u8
	grp.ge_bytes(&g, g_string[:])
	ctx: sha2.Context_512
	sha2.init_512(&ctx)
	sha2.update(&ctx, {SUITE, 0x03})
	sha2.update(&ctx, g_string[:])
	sha2.final(&ctx, beta[:])
	return
}

@(private = "file")
clear_cofactor :: proc "contextless" (p: ^grp.Group_Element) {
	grp.ge_double(p, p)
	grp.ge_double(p, p)
	grp.ge_double(p, p)
}

// ---------------------------------------------------------------------------
// Elligator2 (libsodium's ge25519_from_uniform)

@(private = "file")
Fe :: field.Tight_Field_Element

@(private = "file")
fe_mul :: #force_inline proc "contextless" (out, a, b: ^Fe) {
	field.fe_carry_mul(out, field.fe_relax_cast(a), field.fe_relax_cast(b))
}

@(private = "file")
fe_sq :: #force_inline proc "contextless" (out, a: ^Fe) {
	field.fe_carry_square(out, field.fe_relax_cast(a))
}

@(private = "file")
fe_inv :: #force_inline proc "contextless" (out, a: ^Fe) {
	field.fe_carry_inv(out, field.fe_relax_cast(a))
}

@(private = "file")
fe_small :: proc "contextless" (out: ^Fe, v: u32) {
	b: [32]u8
	b[0], b[1], b[2], b[3] = u8(v), u8(v >> 8), u8(v >> 16), u8(v >> 24)
	field.fe_from_bytes(out, &b)
}

// sqrt(u) for a known square; returns false if u is not a square.
@(private = "file")
fe_sqrt :: proc "contextless" (out, u: ^Fe) -> bool {
	one: Fe
	field.fe_one(&one)
	return field.fe_carry_sqrt_ratio_m1(out, field.fe_relax_cast(u), field.fe_relax_cast(&one)) == 1
}

// Montgomery curve25519 coefficient A.
@(private = "file")
CURVE25519_A :: 486662

// Maps 32 uniform bytes to a point of the prime-order subgroup, writing the
// point and its encoding. The top bit of `r` selects the sign of x; callers
// in the VRF clear it first.
@(private = "file")
from_uniform :: proc "contextless" (p: ^grp.Group_Element, encoded: []u8, r: []u8) {
	s: [32]u8
	copy(s[:], r)
	x_sign := int(s[31] >> 7)
	s[31] &= 0x7f
	r_fe: Fe
	field.fe_from_bytes(&r_fe, &s)

	a: Fe
	fe_small(&a, CURVE25519_A)
	one: Fe
	field.fe_one(&one)

	// x1 = -A / (1 + 2r^2)
	rr2, x, x2, x3, gx: Fe
	fe_sq(&rr2, &r_fe)
	field.fe_carry_add(&rr2, &rr2, &rr2)
	field.fe_carry_add(&rr2, &rr2, &one)
	fe_inv(&rr2, &rr2)
	fe_mul(&x, &a, &rr2)
	field.fe_carry_opp(&x, &x)

	// gx1 = x1^3 + A x1^2 + x1; if it is not a square, x = -x1 - A.
	fe_sq(&x2, &x)
	fe_mul(&x3, &x, &x2)
	fe_mul(&x2, &x2, &a)
	field.fe_carry_add(&gx, &x3, &x)
	field.fe_carry_add(&gx, &gx, &x2)
	tmp: Fe
	notsquare := 1 - field.fe_carry_sqrt_ratio_m1(&tmp, field.fe_relax_cast(&gx), field.fe_relax_cast(&one))
	negx: Fe
	field.fe_carry_opp(&negx, &x)
	field.fe_cond_assign(&x, &negx, notsquare)
	zero: Fe
	field.fe_zero(&zero)
	sub_a := zero
	field.fe_cond_assign(&sub_a, &a, notsquare)
	field.fe_carry_sub(&x, &x, &sub_a)

	// y = sqrt(x^3 + A x^2 + x). The choice of root does not matter: only |x_ed|
	// survives the sign normalisation below.
	y: Fe
	fe_sq(&x2, &x)
	fe_mul(&x3, &x, &x2)
	fe_mul(&x2, &x2, &a)
	field.fe_carry_add(&gx, &x3, &x)
	field.fe_carry_add(&gx, &gx, &x2)
	ok := fe_sqrt(&y, &gx)
	assert_contextless(ok, "elligator2: x is always on the curve")

	// Montgomery to Edwards: x_ed = sqrt(-A-2) x / y, y_ed = (x - 1) / (x + 1),
	// with y_ed = 1 when (x + 1) y = 0 (libsodium inverts zero to zero).
	x_plus_one, x_minus_one, inv, xed, yed: Fe
	field.fe_carry_add(&x_plus_one, &x, &one)
	field.fe_carry_sub(&x_minus_one, &x, &one)
	fe_mul(&inv, &x_plus_one, &y)
	fe_inv(&inv, &inv)
	fe_mul(&xed, &x, &SQRT_AM2)
	fe_mul(&xed, &xed, &inv)
	fe_mul(&xed, &xed, &x_plus_one)
	fe_mul(&yed, &inv, &y)
	fe_mul(&yed, &yed, &x_minus_one)
	inv_is_zero := field.fe_equal(&inv, &zero)
	field.fe_cond_assign(&yed, &one, inv_is_zero)

	field.fe_cond_negate(&xed, &xed, field.fe_is_negative(&xed) ~ x_sign)

	p.x = xed
	p.y = yed
	field.fe_one(&p.z)
	fe_mul(&p.t, &xed, &yed)
	clear_cofactor(p)
	grp.ge_bytes(p, encoded)
}

// sqrt(-A - 2) = sqrt(-486664). Either root works (see `from_uniform`).
@(private = "file")
SQRT_AM2: Fe

@(private = "file", init)
init_sqrt_am2 :: proc "contextless" () {
	v: Fe
	fe_small(&v, CURVE25519_A + 2)
	field.fe_carry_opp(&v, &v)
	ok := fe_sqrt(&SQRT_AM2, &v)
	assert_contextless(ok)
}

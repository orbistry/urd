// Package consensus implements the Ouroboros protocols: the hard-fork era
// history, PBFT, TPraos and Praos header validation, nonces, leader checks and
// chain selection.
package consensus

import "base:intrinsics"

// Signed fixed-width integer used for the E34 fixed-point arithmetic of the
// leader check. Sign-magnitude, little-endian 64-bit limbs.
//
// The width covers every value the consensus code produces: the largest is
// the leader check's 1/(1 - p), at most 2^512 * 10^34 < 2^626, and products
// are taken before dividing by 10^34. Overflow is a programming error and
// panics rather than wrapping.
WIDE_LIMBS :: 32

Wide :: struct {
	limbs: [WIDE_LIMBS]u64,
	// Number of significant limbs; 0 for zero.
	len:   int,
	neg:   bool,
}

wide_from_u64 :: proc "contextless" (v: u64) -> (w: Wide) {
	if v != 0 {
		w.limbs[0] = v
		w.len = 1
	}
	return
}

wide_from_i64 :: proc "contextless" (v: i64) -> (w: Wide) {
	if v < 0 {
		w = wide_from_u64(u64(-(v + 1)) + 1)
		w.neg = true
		return
	}
	return wide_from_u64(u64(v))
}

// From big-endian magnitude bytes (e.g. a VRF output).
wide_from_bytes_be :: proc "contextless" (b: []u8) -> (w: Wide) {
	assert_contextless(len(b) <= 8 * WIDE_LIMBS)
	for i in 0 ..< len(b) {
		bit := len(b) - 1 - i
		w.limbs[bit / 8] |= u64(b[i]) << u64(8 * (bit % 8))
	}
	w.len = WIDE_LIMBS
	normalize(&w)
	return
}

// 2^k
wide_pow2 :: proc "contextless" (k: int) -> (w: Wide) {
	assert_contextless(k < 64 * WIDE_LIMBS)
	w.limbs[k / 64] = u64(1) << u64(k % 64)
	w.len = k / 64 + 1
	return
}

@(private)
normalize :: #force_inline proc "contextless" (w: ^Wide) {
	for w.len > 0 && w.limbs[w.len - 1] == 0 {
		w.len -= 1
	}
	if w.len == 0 {
		w.neg = false
	}
}

wide_is_zero :: #force_inline proc "contextless" (a: Wide) -> bool {
	return a.len == 0
}

wide_neg :: proc "contextless" (a: Wide) -> Wide {
	r := a
	if r.len != 0 {
		r.neg = !r.neg
	}
	return r
}

wide_abs :: proc "contextless" (a: Wide) -> Wide {
	r := a
	r.neg = false
	return r
}

@(private)
cmp_mag :: proc "contextless" (a, b: ^Wide) -> int {
	if a.len != b.len {
		return 1 if a.len > b.len else -1
	}
	for i := a.len - 1; i >= 0; i -= 1 {
		if a.limbs[i] != b.limbs[i] {
			return 1 if a.limbs[i] > b.limbs[i] else -1
		}
	}
	return 0
}

wide_cmp :: proc "contextless" (a, b: Wide) -> int {
	a, b := a, b
	if a.neg != b.neg {
		return -1 if a.neg else 1
	}
	c := cmp_mag(&a, &b)
	return -c if a.neg else c
}

// |a| + |b|
@(private)
add_mag :: proc "contextless" (a, b: ^Wide) -> (r: Wide) {
	n := max(a.len, b.len)
	carry: u64
	for i in 0 ..< n {
		s, c1 := intrinsics.overflow_add(a.limbs[i], b.limbs[i])
		s2, c2 := intrinsics.overflow_add(s, carry)
		r.limbs[i] = s2
		carry = u64(c1) + u64(c2)
	}
	if carry != 0 {
		assert_contextless(n < WIDE_LIMBS, "wide: overflow")
		r.limbs[n] = carry
		n += 1
	}
	r.len = n
	return
}

// |a| - |b|, requires |a| >= |b|
@(private)
sub_mag :: proc "contextless" (a, b: ^Wide) -> (r: Wide) {
	borrow: u64
	for i in 0 ..< a.len {
		d, b1 := intrinsics.overflow_sub(a.limbs[i], b.limbs[i])
		d2, b2 := intrinsics.overflow_sub(d, borrow)
		r.limbs[i] = d2
		borrow = u64(b1) + u64(b2)
	}
	r.len = a.len
	normalize(&r)
	return
}

wide_add :: proc "contextless" (a, b: Wide) -> (r: Wide) {
	a, b := a, b
	if a.neg == b.neg {
		r = add_mag(&a, &b)
		r.neg = a.neg
		normalize(&r)
		return
	}
	if cmp_mag(&a, &b) >= 0 {
		r = sub_mag(&a, &b)
		r.neg = a.neg
	} else {
		r = sub_mag(&b, &a)
		r.neg = b.neg
	}
	normalize(&r)
	return
}

wide_sub :: proc "contextless" (a, b: Wide) -> Wide {
	return wide_add(a, wide_neg(b))
}

wide_mul :: proc "contextless" (a, b: Wide) -> (r: Wide) {
	if a.len == 0 || b.len == 0 {
		return
	}
	assert_contextless(a.len + b.len <= WIDE_LIMBS, "wide: overflow")
	for i in 0 ..< a.len {
		carry: u64
		ai := u128(a.limbs[i])
		for j in 0 ..< b.len {
			t := ai * u128(b.limbs[j]) + u128(r.limbs[i + j]) + u128(carry)
			r.limbs[i + j] = u64(t)
			carry = u64(t >> 64)
		}
		r.limbs[i + b.len] = carry
	}
	r.len = a.len + b.len
	r.neg = a.neg != b.neg
	normalize(&r)
	return
}

// Truncating division of magnitudes (Knuth, TAOCP vol. 2, 4.3.1, algorithm D).
@(private)
divmod_mag :: proc "contextless" (a, b: ^Wide) -> (q, r: Wide) {
	assert_contextless(b.len != 0, "wide: division by zero")
	if cmp_mag(a, b) < 0 {
		r = a^
		r.neg = false
		return
	}
	if b.len == 1 {
		d := u128(b.limbs[0])
		rem: u128
		for i := a.len - 1; i >= 0; i -= 1 {
			cur := rem << 64 | u128(a.limbs[i])
			q.limbs[i] = u64(cur / d)
			rem = cur % d
		}
		q.len = a.len
		normalize(&q)
		r = wide_from_u64(u64(rem))
		return
	}

	// Normalise so the divisor's top limb has its high bit set.
	s := u64(intrinsics.count_leading_zeros(b.limbs[b.len - 1]))
	n := b.len
	m := a.len - n
	v: [WIDE_LIMBS]u64
	u: [WIDE_LIMBS + 1]u64
	for i := n - 1; i > 0; i -= 1 {
		v[i] = b.limbs[i] << s | (b.limbs[i - 1] >> (64 - s) if s != 0 else 0)
	}
	v[0] = b.limbs[0] << s
	u[a.len] = a.limbs[a.len - 1] >> (64 - s) if s != 0 else 0
	for i := a.len - 1; i > 0; i -= 1 {
		u[i] = a.limbs[i] << s | (a.limbs[i - 1] >> (64 - s) if s != 0 else 0)
	}
	u[0] = a.limbs[0] << s

	B :: u128(1) << 64
	for j := m; j >= 0; j -= 1 {
		num := u128(u[j + n]) << 64 | u128(u[j + n - 1])
		qhat := num / u128(v[n - 1])
		rhat := num % u128(v[n - 1])
		for qhat >= B || qhat * u128(v[n - 2]) > (rhat << 64 | u128(u[j + n - 2])) {
			qhat -= 1
			rhat += u128(v[n - 1])
			if rhat >= B do break
		}
		// u[j..j+n] -= qhat * v
		borrow: i128
		carry: u128
		for i in 0 ..< n {
			p := qhat * u128(v[i]) + carry
			carry = p >> 64
			t := i128(u[i + j]) - i128(u64(p)) + borrow
			u[i + j] = u64(t)
			borrow = t >> 64
		}
		t := i128(u[j + n]) - i128(carry) + borrow
		u[j + n] = u64(t)
		if t < 0 {
			// qhat was one too large: add v back.
			qhat -= 1
			c: u128
			for i in 0 ..< n {
				s2 := u128(u[i + j]) + u128(v[i]) + c
				u[i + j] = u64(s2)
				c = s2 >> 64
			}
			u[j + n] += u64(c)
		}
		q.limbs[j] = u64(qhat)
	}
	q.len = m + 1
	normalize(&q)

	for i in 0 ..< n {
		r.limbs[i] = u[i] >> s | (u[i + 1] << (64 - s) if s != 0 else 0)
	}
	r.len = n
	normalize(&r)
	return
}

// Floor division (Haskell's `div`): rounds toward negative infinity.
wide_div_floor :: proc "contextless" (a, b: Wide) -> Wide {
	a, b := a, b
	q, r := divmod_mag(&a, &b)
	if a.neg != b.neg {
		if r.len != 0 {
			one := wide_from_u64(1)
			q = add_mag(&q, &one)
		}
		q.neg = true
		normalize(&q)
	}
	return q
}

// Parses a decimal integer with an optional leading '-'.
wide_from_string :: proc "contextless" (s: string) -> (w: Wide, ok: bool) {
	s := s
	neg := false
	if len(s) > 0 && s[0] == '-' {
		neg = true
		s = s[1:]
	}
	if len(s) == 0 do return {}, false
	ten := wide_from_u64(10)
	for ch in transmute([]u8)s {
		if ch < '0' || ch > '9' do return {}, false
		d := wide_from_u64(u64(ch - '0'))
		w = wide_add(wide_mul(w, ten), d)
	}
	if neg do w = wide_neg(w)
	return w, true
}

// Decimal rendering into `buf`; returns the written slice.
wide_to_string :: proc "contextless" (a: Wide, buf: []u8) -> string {
	digits: [WIDE_LIMBS * 20]u8
	n := 0
	cur := wide_abs(a)
	ten19 := wide_from_u64(10_000_000_000_000_000_000)
	for cur.len != 0 {
		q, r := divmod_mag(&cur, &ten19)
		chunk := r.limbs[0]
		for k := 0; k < 19; k += 1 {
			digits[n] = u8('0' + chunk % 10)
			chunk /= 10
			n += 1
			if q.len == 0 && chunk == 0 do break
		}
		cur = q
	}
	if n == 0 {
		digits[0] = '0'
		n = 1
	}
	out := 0
	if a.neg {
		buf[0] = '-'
		out = 1
	}
	for i := n - 1; i >= 0; i -= 1 {
		buf[out] = digits[i]
		out += 1
	}
	return string(buf[:out])
}

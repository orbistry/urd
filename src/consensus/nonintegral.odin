package consensus

// Exact port of cardano-ledger's non-integral arithmetic
// (libs/non-integral/src/Cardano/Ledger/NonIntegral.hs) instantiated at
// `FixedPoint = Data.Fixed E34`: a value v is stored as the integer v * 10^34,
// and every multiplication and division rounds toward negative infinity
// (Haskell's `div`), exactly as `Data.Fixed` does.
//
// Consensus depends on bit-exact agreement: the leader check is
// `taylorExpCmp 3 (1 / (1 - p)) (-sigma * ln (1 - f))`.

Fixed :: Wide

@(private = "file")
RES :: 100_000_000_000_000_000 * 100_000_000_000_000_000 // 10^34

fixed_res :: proc "contextless" () -> Wide {
	@(static, rodata)
	limbs := [2]u64{u64(u128(RES) & 0xffff_ffff_ffff_ffff), u64(u128(RES) >> 64)}
	w: Wide
	w.limbs[0], w.limbs[1] = limbs[0], limbs[1]
	w.len = 2
	return w
}

fixed_from_int :: proc "contextless" (n: Wide) -> Fixed {
	return wide_mul(n, fixed_res())
}

fixed_from_i64 :: proc "contextless" (n: i64) -> Fixed {
	return fixed_from_int(wide_from_i64(n))
}

// `fromRational (n % d)`: floor(n * 10^34 / d).
fixed_from_ratio :: proc "contextless" (n, d: Wide) -> Fixed {
	return wide_div_floor(wide_mul(n, fixed_res()), d)
}

fixed_mul :: proc "contextless" (a, b: Fixed) -> Fixed {
	return wide_div_floor(wide_mul(a, b), fixed_res())
}

fixed_div :: proc "contextless" (a, b: Fixed) -> Fixed {
	return wide_div_floor(wide_mul(a, fixed_res()), b)
}

fixed_add :: wide_add
fixed_sub :: wide_sub
fixed_cmp :: wide_cmp

fixed_one :: proc "contextless" () -> Fixed {
	return fixed_res()
}

// `ceiling` of a fixed-point value, as an integer.
fixed_ceiling :: proc "contextless" (x: Fixed) -> Wide {
	return wide_neg(wide_div_floor(wide_neg(x), fixed_res()))
}

// eps = 1 / 10^24
@(private = "file")
eps :: proc "contextless" () -> Fixed {
	return wide_from_u64(10_000_000_000)
}

// ipow' x n for n >= 0 (repeated squaring, as in the Haskell recursion).
@(private = "file")
ipow_nonneg :: proc "contextless" (x: Fixed, n: u64) -> Fixed {
	if n == 0 {
		return fixed_one()
	}
	if n % 2 == 0 {
		y := ipow_nonneg(x, n / 2)
		return fixed_mul(y, y)
	}
	return fixed_mul(x, ipow_nonneg(x, n - 1))
}

@(private = "file")
ipow :: proc "contextless" (x: Fixed, n: i64) -> Fixed {
	if n < 0 {
		return fixed_div(fixed_one(), ipow_nonneg(x, u64(-n)))
	}
	return ipow_nonneg(x, u64(n))
}

// taylorExp maxN n x lastX acc divisor, started as taylorExp 1000 1 x 1 1 1.
@(private = "file")
taylor_exp :: proc "contextless" (x: Fixed) -> Fixed {
	one := fixed_one()
	last_x := one
	acc := one
	divisor := one
	for n := 1; n != 1000; n += 1 {
		next_x := fixed_div(fixed_mul(last_x, x), divisor)
		if wide_cmp(wide_abs(next_x), eps()) < 0 {
			return acc
		}
		last_x = next_x
		acc = fixed_add(acc, next_x)
		divisor = fixed_add(divisor, one)
	}
	return acc
}

// exp' x. The Haskell version divides by zero at x = 0 (scaleExp 0 yields
// 0 / 0); nothing on the consensus path calls it there. We return 1.
fixed_exp :: proc "contextless" (x: Fixed) -> Fixed {
	if x.len == 0 {
		return fixed_one()
	}
	if x.neg {
		return fixed_div(fixed_one(), fixed_exp(wide_neg(x)))
	}
	n := fixed_ceiling(x)
	assert_contextless(n.len <= 1, "exp: exponent out of range")
	x_ := fixed_div(x, fixed_from_int(n))
	return ipow(taylor_exp(x_), i64(n.limbs[0]))
}

// e = exp' 1, computed once.
@(private = "file")
EXP1: Fixed

@(private = "file", init)
init_exp1 :: proc "contextless" () {
	EXP1 = fixed_exp(fixed_one())
}

// bound / contract / findE: the integer n with e^n <= x < e^(n+1), found by
// squaring out a bracket and bisecting it.
@(private = "file")
find_e :: proc "contextless" (e, x: Fixed) -> i64 {
	lo := fixed_div(fixed_one(), e)
	hi := e
	l, u: i64 = -1, 1
	for !(wide_cmp(lo, x) <= 0 && wide_cmp(x, hi) <= 0) {
		lo = fixed_mul(lo, lo)
		hi = fixed_mul(hi, hi)
		l *= 2
		u *= 2
	}
	for l + 1 != u {
		mid := l + floor_div_i64(u - l, 2)
		if wide_cmp(x, ipow(e, mid)) < 0 {
			u = mid
		} else {
			l = mid
		}
	}
	return l
}

@(private = "file")
floor_div_i64 :: #force_inline proc "contextless" (a, b: i64) -> i64 {
	q := a / b
	if (a % b != 0) && ((a < 0) != (b < 0)) {
		q -= 1
	}
	return q
}

// lncf maxN x: continued fraction for ln(1 + x).
@(private = "file")
lncf :: proc "contextless" (max_n: int, x: Fixed) -> Fixed {
	one := fixed_one()
	a_nm2, b_nm2 := one, Fixed{}
	a_nm1, b_nm1 := Fixed{}, one
	last: Fixed
	has_last := false
	// as = x : map (* x) [1, 1, 4, 4, 9, 9, ...];  bs = [1, 2, 3, ...]
	sq: i64 = 1
	sq_count := 0
	b_n := one
	for n := 0; ; n += 1 {
		a_n: Fixed
		if n == 0 {
			a_n = x
		} else {
			a_n = fixed_mul(fixed_from_i64(sq * sq), x)
			sq_count += 1
			if sq_count == 2 {
				sq_count = 0
				sq += 1
			}
		}
		a_cur := fixed_add(fixed_mul(b_n, a_nm1), fixed_mul(a_n, a_nm2))
		b_cur := fixed_add(fixed_mul(b_n, b_nm1), fixed_mul(a_n, b_nm2))
		xn := fixed_div(a_cur, b_cur)
		if max_n == n {
			return xn
		}
		if has_last && wide_cmp(wide_abs(fixed_sub(last, xn)), eps()) < 0 {
			return xn
		}
		last, has_last = xn, true
		a_nm2, b_nm2 = a_nm1, b_nm1
		a_nm1, b_nm1 = a_cur, b_cur
		b_n = fixed_add(b_n, one)
	}
}

// ln' x for x > 0.
fixed_ln :: proc "contextless" (x: Fixed) -> Fixed {
	assert_contextless(!x.neg && x.len != 0, "ln: not in domain")
	n := find_e(EXP1, x)
	y := ipow(EXP1, n)
	x_ := fixed_sub(fixed_div(x, y), fixed_one())
	return fixed_add(fixed_from_i64(n), lncf(1000, x_))
}

// a *** b
fixed_pow :: proc "contextless" (a, b: Fixed) -> Fixed {
	switch {
	case b.len == 0:
		return fixed_one()
	case a.len == 0:
		return {}
	case wide_cmp(a, fixed_one()) == 0:
		return fixed_one()
	}
	return fixed_exp(fixed_mul(b, fixed_ln(a)))
}

Compare_Result :: enum u8 {
	Above,
	Below,
	Max_Reached,
}

// taylorExpCmp boundX cmp x: decides whether cmp is above or below e^x using
// a Taylor expansion with a Lagrange error bound. Also returns the
// approximation and the iteration count, as the Haskell CompareResult does.
taylor_exp_cmp :: proc "contextless" (bound_x, cmp, x: Fixed) -> (res: Compare_Result, approx: Fixed, iterations: int) {
	MAX_N :: 1000
	one := fixed_one()
	err := x
	acc := one
	divisor := one
	for n := 0; ; n += 1 {
		if n == MAX_N {
			return .Max_Reached, acc, n
		}
		divisor_next := fixed_add(divisor, one)
		next_x := err
		err_next := fixed_div(fixed_mul(err, x), divisor_next)
		acc_next := fixed_add(acc, next_x)
		error_term := wide_abs(fixed_mul(err_next, bound_x))
		if wide_cmp(cmp, fixed_add(acc_next, error_term)) >= 0 {
			return .Above, acc_next, n + 1
		}
		if wide_cmp(cmp, fixed_sub(acc_next, error_term)) < 0 {
			return .Below, acc_next, n + 1
		}
		err, acc, divisor = err_next, acc_next, divisor_next
	}
}

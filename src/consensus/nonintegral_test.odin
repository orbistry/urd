package consensus

import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

PALLAS_MATH :: "refs/pallas/pallas-math/tests/data/"
GOLDEN :: "refs/cardano-ledger/libs/non-integral/reference/"

@(private = "file")
lines_of :: proc(path: string, allocator := context.temp_allocator) -> []string {
	data, err := os.read_entire_file(path, allocator)
	assert(err == nil, path)
	return strings.split_lines(strings.trim_right(string(data), "\n"), allocator)
}

@(private = "file")
num :: proc(s: string) -> Wide {
	w, ok := wide_from_string(s)
	if !ok do fmt.eprintfln("bad number %q", s)
	assert(ok)
	return w
}

// A decimal with exactly 34 fractional digits, as printed by the oracles.
@(private = "file")
dec :: proc(s: string) -> Fixed {
	whole, _, frac := strings.partition(s, ".")
	assert(len(frac) == 34, s)
	return num(strings.concatenate({whole, frac}, context.temp_allocator))
}

@(private = "file")
str :: proc(w: Wide) -> string {
	buf := make([]u8, 700, context.temp_allocator)
	return wide_to_string(w, buf)
}

@(test)
test_wide_roundtrip_and_division :: proc(t: ^testing.T) {
	for s in ([]string{"0", "1", "-1", "18446744073709551616", "-340282366920938463463374607431768211457", "123456789012345678901234567890123456789012345678901234567890"}) {
		testing.expect_value(t, str(num(s)), s)
	}
	// Floor division signs.
	testing.expect_value(t, str(wide_div_floor(num("7"), num("-2"))), "-4")
	testing.expect_value(t, str(wide_div_floor(num("-7"), num("2"))), "-4")
	testing.expect_value(t, str(wide_div_floor(num("-7"), num("-2"))), "3")
	testing.expect_value(t, str(wide_div_floor(num("-8"), num("2"))), "-4")
	// Multi-limb Knuth division.
	a := num(
		"1157920892373161954235709850086879078532699846656405640394575840079131296399360000000000000000000000000000000000",
	)
	b := num("115792089237316195423570985008687907853269984665640564039457584007913129639935")
	testing.expect_value(t, str(wide_div_floor(a, b)), "10000000000000000000000000000000000")
	testing.expect_value(t, str(wide_div_floor(wide_mul(b, b), b)), str(b))
}

@(test)
test_node_primitives :: proc(t: ^testing.T) {
	for line in lines_of(PALLAS_MATH + "node-primitives.tsv") {
		f := strings.split(line, "\t", context.temp_allocator)
		got: Fixed
		switch f[0] {
		case "multiply":
			got = fixed_mul(num(f[1]), num(f[2]))
		case "divide":
			got = fixed_div(num(f[1]), num(f[2]))
		case "ratio":
			got = fixed_div(fixed_from_int(num(f[1])), fixed_from_int(num(f[2])))
		}
		testing.expectf(t, wide_cmp(got, num(f[3])) == 0, "%s: got %s", line, str(got))
	}
}

@(private = "file")
ordering_name :: proc(r: Compare_Result) -> string {
	switch r {
	case .Above:
		return "ABOVE"
	case .Below:
		return "BELOW"
	case .Max_Reached:
		return "MAX_REACHED"
	}
	return ""
}

@(test)
test_node_comparisons :: proc(t: ^testing.T) {
	for line in lines_of(PALLAS_MATH + "node-comparisons.tsv") {
		f := strings.split(line, "\t", context.temp_allocator)
		// x = 10^6 runs the series to 1000 terms of size x^n/n!, which needs
		// ~11k-bit integers. Consensus never gets near it: x = -sigma ln(1 - f)
		// with sigma <= 1.
		if wide_cmp(wide_abs(num(f[1])), fixed_from_i64(1000)) > 0 do continue
		res, _, iters := taylor_exp_cmp(fixed_from_i64(3), num(f[0]), num(f[1]))
		got := fmt.tprintf("%s %d", ordering_name(res), iters)
		testing.expectf(t, got == fmt.tprintf("%s %s", f[2], f[3]), "%s: got %s", line, got)
	}
}

@(test)
test_node_extra_arithmetic :: proc(t: ^testing.T) {
	one := fixed_one()
	c := fixed_sub(one, fixed_div(one, fixed_from_i64(10)))
	ln_c := fixed_ln(c)
	rows := 0
	for line in lines_of(PALLAS_MATH + "node-extra-arithmetic.tsv") {
		f := strings.split(line, "\t", context.temp_allocator)
		if len(f) == 5 do continue // 1 / (1 - a) at a = 1: the oracle divides by zero.
		x, a, b := num(f[0]), num(f[1]), num(f[2])
		testing.expectf(t, wide_cmp(fixed_exp(x), dec(f[3])) == 0, "exp %s", line)
		testing.expectf(t, wide_cmp(wide_neg(fixed_ln(a)), dec(f[4])) == 0, "ln %s", line)
		testing.expectf(t, wide_cmp(fixed_sub(one, fixed_pow(c, b)), dec(f[5])) == 0, "pow %s", line)
		q := fixed_div(one, fixed_sub(one, a))
		res, _, iters := taylor_exp_cmp(fixed_from_i64(3), q, wide_neg(fixed_mul(b, ln_c)))
		got := fmt.tprintf("%s %d", ordering_name(res), iters)
		testing.expectf(t, got == fmt.tprintf("%s %s", f[6], f[7]), "cmp %s: got %s", line, got)
		rows += 1
	}
	testing.expect_value(t, rows, 112)
}

@(test)
test_node_leader_vectors :: proc(t: ^testing.T) {
	rows := 0
	for line in lines_of(PALLAS_MATH + "node-vectors.tsv") {
		f := strings.split(line, "\t", context.temp_allocator)
		max := wide_pow2(256 if f[0] == "32" else 512)
		v := num(f[1])
		pool, total := num(f[2]), num(f[3])
		fn, fd := num(f[4]), num(f[5])
		coeff := active_slot_coeff(fn.limbs[0], fd.limbs[0])
		want := f[6] == "true"

		sigma := fixed_from_ratio(pool, total)
		testing.expectf(t, wide_cmp(sigma, num(f[7])) == 0, "sigma %s", line)
		if f[8] != "none" {
			testing.expectf(t, wide_cmp(coeff.log, num(f[8])) == 0, "ln(1-f) %s: got %s", line, str(coeff.log))
		}
		testing.expectf(t, wide_cmp(leader_recip_q(v, max), num(f[9])) == 0, "q %s", line)
		if f[10] != "none" {
			x := wide_neg(fixed_mul(sigma, coeff.log))
			testing.expectf(t, wide_cmp(x, num(f[10])) == 0, "x %s: got %s", line, str(x))
		}
		got := check_leader_value(v, max, pool.limbs[0], total.limbs[0], &coeff)
		testing.expectf(t, got == want, "leader %s: got %v", line, got)
		rows += 1
	}
	testing.expect_value(t, rows, 648)
}

// 100k (x, a, b) triples: exp' x, -ln' a, 1 - (1 - f) *** b with f = 1/10,
// and the Taylor comparison of 1/(1 - a) against e^(-b ln(1 - f)).
@(test)
test_golden :: proc(t: ^testing.T) {
	in_data, _ := os.read_entire_file(GOLDEN + "golden_tests.txt", context.allocator)
	out_data, _ := os.read_entire_file(GOLDEN + "golden_tests_result.txt", context.allocator)
	inputs := strings.split_lines(strings.trim_right(string(in_data), "\n"))
	results := strings.split_lines(strings.trim_right(string(out_data), "\n"))
	defer {
		delete(inputs)
		delete(results)
		delete(in_data)
		delete(out_data)
	}
	testing.expect_value(t, len(inputs), len(results))
	one := fixed_one()
	c := fixed_sub(one, fixed_div(one, fixed_from_i64(10)))
	ln_c := fixed_ln(c)
	failures := 0
	for i in 0 ..< len(inputs) {
		in_f := strings.fields(inputs[i], context.temp_allocator)
		out := strings.fields(results[i], context.temp_allocator)
		x, a, b := num(in_f[0]), num(in_f[1]), num(in_f[2])
		ok := wide_cmp(fixed_exp(x), dec(out[0])) == 0
		ok &&= wide_cmp(wide_neg(fixed_ln(a)), dec(out[1])) == 0
		ok &&= wide_cmp(fixed_sub(one, fixed_pow(c, b)), dec(out[2])) == 0
		q := fixed_div(one, fixed_sub(one, a))
		res, approx, iters := taylor_exp_cmp(fixed_from_i64(3), q, wide_neg(fixed_mul(b, ln_c)))
		ok &&= wide_cmp(approx, dec(out[3])) == 0
		ok &&= (res == .Above) == (out[4] == "GT")
		ok &&= fmt.tprintf("%d", iters) == out[5]
		if !ok {
			failures += 1
			if failures <= 5 do testing.expectf(t, false, "golden line %d: %s", i + 1, inputs[i])
		}
		free_all(context.temp_allocator)
	}
	testing.expect_value(t, failures, 0)
}

package consensus

// Active slot coefficient f, with ln(1 - f) precomputed as the ledger does
// (mkActiveSlotCoeff in cardano-ledger's BaseTypes.hs).
Active_Slot_Coeff :: struct {
	num, den: u64,
	// ln'(1 - f) in E34. Unused when f = 1.
	log:      Fixed,
	// f = 1: every slot leads (ln 0 is undefined; a testing convenience).
	always:   bool,
}

// `unActiveSlotLog = floor (fpPrecision * ln' (1 - fromRational f))` and
// `activeSlotLog f = fromIntegral unActiveSlotLog / fpPrecision`. The floor
// and division cancel in E34, leaving ln'(1 - fromRational f) itself.
active_slot_coeff :: proc "contextless" (num, den: u64) -> (f: Active_Slot_Coeff) {
	f.num, f.den = num, den
	if num == den {
		f.always = true
		return
	}
	frac := fixed_from_ratio(wide_from_u64(num), wide_from_u64(den))
	f.log = fixed_ln(fixed_sub(fixed_one(), frac))
	return
}

// The leader check (checkLeaderNatValue): a pool with relative stake
// sigma = pool_stake / total_stake leads the slot iff
//
//	taylorExpCmp 3 (1 / (1 - p)) (-sigma * ln (1 - f)) == BELOW
//
// where p = cert_nat / cert_nat_max. `cert_nat_max` is 2^512 for TPraos (the
// raw 64-byte leader VRF output) and 2^256 for Praos (the hashed leader value).
check_leader_value :: proc "contextless" (
	cert_nat, cert_nat_max: Wide,
	pool_stake, total_stake: u64,
	f: ^Active_Slot_Coeff,
) -> bool {
	if f.always {
		return true
	}
	sigma := fixed_from_ratio(wide_from_u64(pool_stake), wide_from_u64(total_stake))
	recip_q := leader_recip_q(cert_nat, cert_nat_max)
	x := wide_neg(fixed_mul(sigma, f.log))
	res, _, _ := taylor_exp_cmp(fixed_from_i64(3), recip_q, x)
	return res == .Below
}

// fromRational (certNatMax % (certNatMax - certNat)). Real VRF values are
// always below the maximum; the endpoint is given the quotient M * 10^34 so
// that test oracles that probe it can be compared.
leader_recip_q :: proc "contextless" (cert_nat, cert_nat_max: Wide) -> Fixed {
	diff := wide_sub(cert_nat_max, cert_nat)
	if diff.len == 0 || diff.neg {
		return fixed_from_int(cert_nat_max)
	}
	return fixed_from_ratio(cert_nat_max, diff)
}

package ccrypto

import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

PLUTUS_BUILTINS :: "refs/plutus/plutus-conformance/test-cases/uplc/evaluation/builtin/semantics/"

// Byte-string literals of a conformance-test program, in order.
@(private)
uplc_bytestrings :: proc(src: string, allocator := context.temp_allocator) -> [dynamic][]u8 {
	out := make([dynamic][]u8, allocator)
	s := src
	for {
		i := strings.index(s, "(con bytestring #")
		if i < 0 do break
		s = s[i + len("(con bytestring #"):]
		j := 0
		for j < len(s) && strings.index_byte("0123456789abcdefABCDEF", s[j]) >= 0 do j += 1
		b, ok := hex.decode(transmute([]u8)s[:j], allocator)
		assert(ok)
		append(&out, b)
		s = s[j:]
	}
	return out
}

@(private)
read_case :: proc(dir, name: string) -> (program: string, expected: string) {
	path := fmt.tprintf("%s%s/%s/%s.uplc", PLUTUS_BUILTINS, dir, name, name)
	p, err := os.read_entire_file(path, context.temp_allocator)
	assert(err == nil, path)
	e, err2 := os.read_entire_file(fmt.tprintf("%s.expected", path), context.temp_allocator)
	assert(err2 == nil, path)
	return string(p), string(e)
}

@(test)
test_ed25519_plutus_conformance :: proc(t: ^testing.T) {
	infos, err := os.read_all_directory_by_path(PLUTUS_BUILTINS + "verifyEd25519Signature", context.temp_allocator)
	testing.expect(t, err == nil, "missing plutus refs")
	n := 0
	for fi in infos {
		prog, expected := read_case("verifyEd25519Signature", fi.name)
		args := uplc_bytestrings(prog)
		testing.expect_value(t, len(args), 3)
		got := ed25519_verify(args[0], args[1], args[2])
		switch {
		case strings.contains(expected, "True"):
			testing.expectf(t, got, "%s: expected True", fi.name)
		case strings.contains(expected, "False"), strings.contains(expected, "evaluation failure"):
			// Wrong-length inputs make the builtin fail; the primitive just
			// rejects them.
			testing.expectf(t, !got, "%s: expected rejection", fi.name)
		case:
			testing.expectf(t, false, "%s: unexpected expectation %q", fi.name, expected)
		}
		n += 1
	}
	testing.expect(t, n >= 35)
}

@(test)
test_small_order_and_canonical :: proc(t: ^testing.T) {
	identity := [32]u8{0 = 1}
	testing.expect(t, has_small_order(identity[:]))
	identity[31] = 0x80 // sign bit is ignored
	testing.expect(t, has_small_order(identity[:]))

	// p and p + 1 are non-canonical y values; p - 1 = 2^255 - 20 is canonical.
	p: [32]u8
	p[0] = 0xed
	for i in 1 ..< 31 do p[i] = 0xff
	p[31] = 0x7f
	testing.expect(t, !is_canonical_point(p[:]))
	p[0] = 0xec
	testing.expect(t, is_canonical_point(p[:]))
	p[0] = 0xff
	testing.expect(t, !is_canonical_point(p[:]))

	// The base point is canonical and of large order.
	base_point := [32]u8{0 = 0x58}
	for i in 1 ..< 32 do base_point[i] = 0x66
	testing.expect(t, is_canonical_point(base_point[:]))
	testing.expect(t, !has_small_order(base_point[:]))

	// A valid RFC 8032 signature (test 1) with S replaced by S + L must fail.
	pk, _ := hex.decode(transmute([]u8)string("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"), context.temp_allocator)
	sig, _ := hex.decode(transmute([]u8)string("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"), context.temp_allocator)
	testing.expect(t, ed25519_verify(pk, nil, sig))
	L := [32]u8{0 = 0xed, 1 = 0xd3, 2 = 0xf5, 3 = 0x5c, 4 = 0x1a, 5 = 0x63, 6 = 0x12, 7 = 0x58, 8 = 0xd6, 9 = 0x9c, 10 = 0xf7, 11 = 0xa2, 12 = 0xde, 13 = 0xf9, 14 = 0xde, 15 = 0x14, 31 = 0x10}
	carry: u16
	for i in 0 ..< 32 {
		v := u16(sig[32 + i]) + u16(L[i]) + carry
		sig[32 + i] = u8(v)
		carry = v >> 8
	}
	testing.expect(t, !ed25519_verify(pk, nil, sig))
}

@(private)
read_kv_vector :: proc(path: string) -> map[string][]u8 {
	data, err := os.read_entire_file(path, context.temp_allocator)
	assert(err == nil, path)
	out := make(map[string][]u8, context.temp_allocator)
	for line in strings.split_lines(string(data), context.temp_allocator) {
		k, _, v := strings.partition(line, ": ")
		if k == "" do continue
		if v == "empty" {
			out[k] = {}
			continue
		}
		b, ok := hex.decode(transmute([]u8)v, context.temp_allocator)
		if ok do out[k] = b
	}
	return out
}

@(test)
test_vrf03_vectors :: proc(t: ^testing.T) {
	DIR :: "refs/cardano-base/cardano-crypto-praos/test_vectors/"
	names := []string{"standard_10", "standard_11", "standard_12", "generated_1", "generated_2", "generated_3", "generated_4"}
	for name in names {
		v := read_kv_vector(fmt.tprintf("%svrf_ver03_%s", DIR, name))
		beta, ok := vrf03_verify(v["pk"], v["pi"], v["alpha"])
		testing.expectf(t, ok, "%s: proof rejected", name)
		testing.expectf(t, string(beta[:]) == string(v["beta"]), "%s: beta mismatch", name)

		beta2, ok2 := vrf03_proof_to_hash(v["pi"])
		testing.expect(t, ok2 && beta2 == beta)

		// Any flipped bit in the proof or message must be rejected.
		pi := make([]u8, len(v["pi"]), context.temp_allocator)
		for i in 0 ..< len(pi) {
			copy(pi, v["pi"])
			pi[i] ~= 0x01
			_, bad := vrf03_verify(v["pk"], pi, v["alpha"])
			testing.expectf(t, !bad, "%s: accepted proof with byte %d flipped", name, i)
		}
		alpha := make([]u8, len(v["alpha"]) + 1, context.temp_allocator)
		copy(alpha, v["alpha"])
		_, bad := vrf03_verify(v["pk"], v["pi"], alpha)
		testing.expectf(t, !bad, "%s: accepted a different message", name)
	}
}

@(test)
test_kes_sum6_haskell_interop :: proc(t: ^testing.T) {
	DIR :: "refs/pallas/pallas-crypto/src/kes/data/"
	key, kerr := os.read_entire_file(DIR + "key6.bin", context.temp_allocator)
	testing.expect(t, kerr == nil && len(key) == 608)
	// The raw Sum6 signing key ends with the top-level (vk0, vk1) pair.
	vk := blake2b_256(key[len(key) - 64:])
	msg := transmute([]u8)string("test message")

	sig0, _ := os.read_entire_file(DIR + "key6Sig.bin", context.temp_allocator)
	sig5, _ := os.read_entire_file(DIR + "key6Sig5.bin", context.temp_allocator)
	testing.expect(t, kes_sum6_verify(vk[:], 0, msg, sig0))
	testing.expect(t, kes_sum6_verify(vk[:], 5, msg, sig5))

	// Wrong period, wrong message, corrupted signature.
	testing.expect(t, !kes_sum6_verify(vk[:], 1, msg, sig0))
	testing.expect(t, !kes_sum6_verify(vk[:], 4, msg, sig5))
	testing.expect(t, !kes_sum6_verify(vk[:], 0, transmute([]u8)string("test messagf"), sig0))
	for i in ([]int{0, 63, 64, 200, 447}) {
		sig0[i] ~= 1
		testing.expectf(t, !kes_sum6_verify(vk[:], 0, msg, sig0), "byte %d", i)
		sig0[i] ~= 1
	}
}

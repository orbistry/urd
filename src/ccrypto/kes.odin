package ccrypto

// Sum6KES over Ed25519 with Blake2b-256 (cardano-crypto-class
// Cardano/Crypto/KES/Sum.hs), the KES scheme of every Shelley-era header.
//
// A Sum_d signature is the Sum_(d-1) signature followed by the two child
// verification keys (vk0, vk1); the parent key is Blake2b-256(vk0 || vk1).
// The leaf is a plain Ed25519 signature.

KES_DEPTH :: 6
KES_PERIODS :: 1 << KES_DEPTH
KES_VKEY_SIZE :: 32
KES_SIGNATURE_SIZE :: ED25519_SIGNATURE_SIZE + KES_DEPTH * 2 * KES_VKEY_SIZE

// Verifies a Sum6KES signature of `msg` at `period` under `vkey`.
//
// Like the Haskell implementation, the period is not range-checked here (the
// leaf's `t == 0` is only an assertion there): periods past the last one keep
// descending into the right subtree. Header validation bounds the period
// before calling this.
kes_sum6_verify :: proc(vkey: []u8, period: u64, msg, signature: []u8) -> bool {
	if len(vkey) != KES_VKEY_SIZE || len(signature) != KES_SIGNATURE_SIZE {
		return false
	}
	current: [KES_VKEY_SIZE]u8
	copy(current[:], vkey)
	t := period
	size := KES_SIGNATURE_SIZE
	for d := KES_DEPTH; d > 0; d -= 1 {
		pair := signature[size - 2 * KES_VKEY_SIZE:size]
		if blake2b_256(pair) != current {
			return false
		}
		half := u64(1) << u64(d - 1)
		if t < half {
			copy(current[:], pair[:KES_VKEY_SIZE])
		} else {
			copy(current[:], pair[KES_VKEY_SIZE:])
			t -= half
		}
		size -= 2 * KES_VKEY_SIZE
	}
	return ed25519_verify(current[:], msg, signature[:ED25519_SIGNATURE_SIZE])
}

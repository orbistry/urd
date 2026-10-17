package ledger

import "urd:base"
import "urd:cbor"
import "urd:ccrypto"

// Highest major protocol version this node can decode: cardano-ledger's
// `MaxVersion` (libs/cardano-ledger-binary/src/Cardano/Ledger/Binary/Version.hs).
// Decoding a `Version` above it fails, so a header announcing a higher major
// version is undecodable.
MAX_PROTOCOL_VERSION :: 13

VKEY_SIZE :: 32
SIGNATURE_SIZE :: 64
VRF_VKEY_SIZE :: 32
VRF_PROOF_SIZE :: 80
// Sum6KES over Ed25519 with Blake2b-256: one Ed25519 signature plus a pair of
// verification keys per level.
KES_SIGNATURE_SIZE :: 64 + 6 * 2 * 32

// A certified VRF output, `[output, proof]`.
Vrf_Cert :: struct {
	// Any length below protocol version 12; honest blocks use 64 bytes.
	output: []u8,
	proof:  [VRF_PROOF_SIZE]u8,
}

Op_Cert :: struct {
	hot_vkey:   [VKEY_SIZE]u8,
	counter:    u64,
	kes_period: u64,
	sigma:      [SIGNATURE_SIZE]u8,
}

// Header of a Shelley-family block. Shelley to Alonzo use TPraos, which
// carries two VRF certificates (nonce and leader); Babbage onwards use Praos,
// which carries one (`leader_vrf`) from which both values are derived.
Header :: struct {
	// `[header_body, kes_signature]` as it appears in the block.
	raw:           []u8,
	// The KES-signed header body.
	body:          []u8,
	kes_signature: []u8,
	hash:          base.Block_Hash,
	era:           base.Era,
	block_no:      u64,
	slot:          u64,
	prev:          base.Block_Hash,
	// False only for the first block after genesis (prev = null).
	has_prev:      bool,
	issuer_vkey:   [VKEY_SIZE]u8,
	vrf_vkey:      [VRF_VKEY_SIZE]u8,
	leader_vrf:    Vrf_Cert,
	nonce_vrf:     Vrf_Cert,
	body_size:     u32,
	body_hash:     base.Hash32,
	ocert:         Op_Cert,
	pv_major:      u32,
	// `Natural` on the wire; saturates at max(u64), which no honest block
	// comes near.
	pv_minor:      u64,
}

is_tpraos :: #force_inline proc "contextless" (era: base.Era) -> bool {
	return era >= .Shelley && era <= .Alonzo
}

@(private)
read_fixed :: #force_inline proc "contextless" (r: ^cbor.Reader, dst: []u8) -> cbor.Error {
	b := cbor.read_bytes_n(r, len(dst)) or_return
	copy(dst, b)
	return .None
}

// `CertifiedVRF` below version 12: a definite array of exactly two
// (`enforceSize`), output bytes of any length, proof of fixed size.
@(private)
read_vrf_cert :: proc "contextless" (r: ^cbor.Reader, v: ^Vrf_Cert) -> cbor.Error {
	cbor.expect_array_definite(r, 2) or_return
	v.output = cbor.read_bytes(r) or_return
	return read_fixed(r, v.proof[:])
}

@(private)
read_ocert_fields :: proc "contextless" (r: ^cbor.Reader, o: ^Op_Cert) -> cbor.Error {
	read_fixed(r, o.hot_vkey[:]) or_return
	o.counter = cbor.read_uint(r) or_return
	o.kes_period = cbor.read_uint(r) or_return
	return read_fixed(r, o.sigma[:])
}

@(private)
read_protver_fields :: proc "contextless" (r: ^cbor.Reader, h: ^Header) -> cbor.Error {
	major := cbor.read_u32(r) or_return
	if major > MAX_PROTOCOL_VERSION {
		return .Invalid_Value
	}
	h.pv_major = major
	h.pv_minor, _ = cbor.read_natural(r) or_return
	return .None
}

@(private)
read_prev_hash :: proc "contextless" (r: ^cbor.Reader, h: ^Header) -> cbor.Error {
	if cbor.is_null(r) {
		r.pos += 1
		h.has_prev = false
		return .None
	}
	h.prev = base.Block_Hash(cbor.read_hash32(r) or_return)
	h.has_prev = true
	return .None
}

// Decodes a Shelley-family header from `r`, which must be positioned at the
// `[header_body, signature]` array.
decode_header :: proc "contextless" (r: ^cbor.Reader, era: base.Era, h: ^Header) -> cbor.Error {
	h.era = era
	start := r.pos

	outer := cbor.read_array_len(r, 2) or_return
	body_start := r.pos
	if is_tpraos(era) {
		decode_tpraos_body(r, h) or_return
	} else {
		decode_praos_body(r, h) or_return
	}
	h.body = r.data[body_start:r.pos]
	h.kes_signature = cbor.read_bytes_n(r, KES_SIGNATURE_SIZE) or_return
	cbor.end(r, outer) or_return

	h.raw = r.data[start:r.pos]
	h.hash = base.Block_Hash(ccrypto.blake2b_256(h.raw))
	return .None
}

// BHBody (cardano-protocol TPraos/BlockHeader.hs): a record of 15, with the
// operational certificate and protocol version inlined as groups.
@(private)
decode_tpraos_body :: proc "contextless" (r: ^cbor.Reader, h: ^Header) -> cbor.Error {
	c := cbor.read_array_len(r, 15) or_return
	h.block_no = cbor.read_uint(r) or_return
	h.slot = cbor.read_uint(r) or_return
	read_prev_hash(r, h) or_return
	read_fixed(r, h.issuer_vkey[:]) or_return
	read_fixed(r, h.vrf_vkey[:]) or_return
	read_vrf_cert(r, &h.nonce_vrf) or_return
	read_vrf_cert(r, &h.leader_vrf) or_return
	h.body_size = cbor.read_u32(r) or_return
	h.body_hash = cbor.read_hash32(r) or_return
	read_ocert_fields(r, &h.ocert) or_return
	read_protver_fields(r, h) or_return
	return cbor.end(r, c)
}

// HeaderBody (cardano-protocol Praos/BlockHeader.hs): a record of 10, with
// the operational certificate and protocol version as nested records.
@(private)
decode_praos_body :: proc "contextless" (r: ^cbor.Reader, h: ^Header) -> cbor.Error {
	c := cbor.read_array_len(r, 10) or_return
	h.block_no = cbor.read_uint(r) or_return
	h.slot = cbor.read_uint(r) or_return
	read_prev_hash(r, h) or_return
	read_fixed(r, h.issuer_vkey[:]) or_return
	read_fixed(r, h.vrf_vkey[:]) or_return
	read_vrf_cert(r, &h.leader_vrf) or_return
	h.body_size = cbor.read_u32(r) or_return
	h.body_hash = cbor.read_hash32(r) or_return

	oc := cbor.read_array_len(r, 4) or_return
	read_ocert_fields(r, &h.ocert) or_return
	cbor.end(r, oc) or_return

	pv := cbor.read_array_len(r, 2) or_return
	read_protver_fields(r, h) or_return
	cbor.end(r, pv) or_return

	return cbor.end(r, c)
}

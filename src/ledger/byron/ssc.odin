package byron

import "urd:cbor"

// Shared seed computation payloads and proofs (byron/Ssc.hs), docs B.3.7.
// Their content is dropped, but their structure is checked exactly as the
// droppers do.

// `dropSscPayload`: [tag, ...] with tag 0 (commitments), 1 (openings),
// 2 (shares), each followed by VSS certificates, or 3 (certificates only).
drop_ssc_payload :: proc "contextless" (r: ^cbor.Reader) -> Error {
	n := read_array_definite(r) or_return
	tag := cbor.read_u8(r) or_return
	switch tag {
	case 0:
		if n != 3 do return .Length_Mismatch
		drop_set(r, drop_signed_commitment) or_return
	case 1:
		if n != 3 do return .Length_Mismatch
		drop_map(r, drop_bytes) or_return
	case 2:
		if n != 3 do return .Length_Mismatch
		drop_map(r, drop_inner_shares) or_return
	case 3:
		if n != 2 do return .Length_Mismatch
	case:
		return .Invalid_Value
	}
	return drop_set(r, drop_vss_certificate)
}

// `dropSscProof`: [tag, bytes, bytes] for tags 0..2, [3, bytes].
drop_ssc_proof :: proc "contextless" (r: ^cbor.Reader) -> Error {
	n := read_array_definite(r) or_return
	tag := cbor.read_u8(r) or_return
	switch tag {
	case 0, 1, 2:
		if n != 3 do return .Length_Mismatch
		_ = cbor.read_bytes(r) or_return
	case 3:
		if n != 2 do return .Length_Mismatch
	case:
		return .Invalid_Value
	}
	_ = cbor.read_bytes(r) or_return
	return .None
}

@(private = "file")
Dropper :: #type proc "contextless" (r: ^cbor.Reader) -> Error

@(private = "file")
drop_bytes :: proc "contextless" (r: ^cbor.Reader) -> Error {
	_ = cbor.read_bytes(r) or_return
	return .None
}

// `dropList dropBytes`: an indefinite list of byte strings.
@(private = "file")
drop_bytes_list :: proc "contextless" (r: ^cbor.Reader) -> Error {
	c := read_list(r) or_return
	for cbor.more(r, &c) {
		_ = cbor.read_bytes(r) or_return
	}
	return .None
}

// `dropSet`: a tag of any value (not checked against 258), then a definite
// list.
@(private = "file")
drop_set :: proc "contextless" (r: ^cbor.Reader, elem: Dropper) -> Error {
	_ = cbor.read_tag(r) or_return
	n := read_array_definite(r) or_return
	for _ in 0 ..< n {
		elem(r) or_return
	}
	return .None
}

// `dropMap dropBytes value`: a definite map with byte-string keys, with no
// order or duplicate check.
@(private = "file")
drop_map :: proc "contextless" (r: ^cbor.Reader, value: Dropper) -> Error {
	n := read_map_definite(r) or_return
	for _ in 0 ..< n {
		_ = cbor.read_bytes(r) or_return
		value(r) or_return
	}
	return .None
}

// `dropTriple dropBytes dropCommitment dropBytes`.
@(private = "file")
drop_signed_commitment :: proc "contextless" (r: ^cbor.Reader) -> Error {
	enforce_size(r, 3) or_return
	_ = cbor.read_bytes(r) or_return

	// Commitment: [{bytes => [* bytes]}, secret proof].
	enforce_size(r, 2) or_return
	drop_map(r, drop_bytes_list) or_return
	// SecretProof: [bytes, bytes, bytes, [* bytes]].
	enforce_size(r, 4) or_return
	for _ in 0 ..< 3 {
		_ = cbor.read_bytes(r) or_return
	}
	drop_bytes_list(r) or_return

	_ = cbor.read_bytes(r) or_return
	return .None
}

// Inner shares map: {bytes => [* bytes]}.
@(private = "file")
drop_inner_shares :: proc "contextless" (r: ^cbor.Reader) -> Error {
	return drop_map(r, drop_bytes_list)
}

// VssCertificate: [bytes, Word64, bytes, bytes].
@(private = "file")
drop_vss_certificate :: proc "contextless" (r: ^cbor.Reader) -> Error {
	enforce_size(r, 4) or_return
	_ = cbor.read_bytes(r) or_return
	_ = cbor.read_uint(r) or_return
	_ = cbor.read_bytes(r) or_return
	_ = cbor.read_bytes(r) or_return
	return .None
}

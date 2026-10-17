package byron

import "urd:base"
import "urd:cbor"

// Heavyweight delegation certificates (byron/Delegation/Certificate.hs,
// Payload.hs), docs B.3.9.

// `ACertificate`: [epoch, issuer, delegate, signature]. Spans are relative to
// the decoding base: the block for payload certificates, the header for the
// one in a block signature.
Delegation_Cert :: struct {
	// The certificate as received; its hash is the `CertificateId`.
	raw:       base.Span,
	// The epoch item as received; the certificate signature covers it.
	epoch_raw: base.Span,
	epoch:     u64,
	issuer:    Vkey,
	delegate:  Vkey,
	sig:       Signature,
}

@(private)
read_delegation_cert :: proc "contextless" (d: ^Decoder) -> (c: Delegation_Cert, err: Error) {
	r := &d.r
	start := r.pos
	enforce_size(r, 4) or_return
	epoch_start := r.pos
	c.epoch = cbor.read_uint(r) or_return
	c.epoch_raw = span_from(d, epoch_start)
	c.issuer = read_vkey(r) or_return
	c.delegate = read_vkey(r) or_return
	c.sig = read_signature(r) or_return
	c.raw = span_from(d, start)
	return c, .None
}

// The delegation payload: an indefinite list of certificates.
@(private)
read_delegation_payload :: proc(d: ^Decoder) -> Error {
	c := read_list(&d.r) or_return
	for cbor.more(&d.r, &c) {
		cert := read_delegation_cert(d) or_return
		append(&d.t.certs, cert)
	}
	return .None
}

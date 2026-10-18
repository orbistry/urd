package byron

import "urd:base"
import "urd:cbor"
import "urd:ccrypto"

// Byron signatures (byron-crypto Signing/Tag.hs, Signing/Signature.hs). Every
// signed message starts with a sign tag: one byte, then the protocol magic as
// a CBOR Word32. Block signatures use their own tag, which also carries the
// key of the delegation certificate's issuer. All are verified with
// ed25519-donna on the first 32 bytes of the key (`CC.verify` on an XPub).

Sign_Tag :: enum u8 {
	Tx          = 0x01,
	Redeem_Tx   = 0x02,
	Proposal    = 0x04,
	Vote        = 0x06,
	// Used only inside the block tag: "01" ‖ issuer ‖ 0x09 ‖ magic.
	Block       = 0x09,
	Certificate = 0x0a,
}

// tag ‖ magic, written into `buf`.
@(private)
sign_tag :: proc "contextless" (buf: ^[6]u8, tag: Sign_Tag, magic: u32) -> []u8 {
	buf[0] = u8(tag)
	n := cbor.put_head(buf[1:], .Unsigned, u64(magic))
	return buf[:1 + n]
}

// The block signature (`SignBlock genesisKey`), by the certificate's delegate,
// over 0x85 ‖ prev ‖ proof ‖ slot ‖ difficulty ‖ extra as received
// (byron/Block/Header.hs recoverSignedBytes). The tag carries the header's
// own genesis key field, not the certificate's issuer (they differ only in a
// header no honest node forges); PBFT verifies it this way
// (ouroboros-consensus Byron/Ledger/PBFT.hs). `header` is the header's bytes.
verify_block_signature :: proc(h: ^Header, header: []u8, magic: u32) -> bool {
	tag: [6]u8
	prefix := [1]u8{0x85}
	parts := [?][]u8 {
		transmute([]u8)string("01"),
		h.issuer[:],
		sign_tag(&tag, .Block, magic),
		prefix[:],
		base.span_bytes(header, h.prev_raw),
		base.span_bytes(header, h.proof_raw),
		base.span_bytes(header, h.slot_raw),
		base.span_bytes(header, h.difficulty_raw),
		base.span_bytes(header, h.extra_raw),
	}
	return ccrypto.ed25519_verify_donna_parts(h.cert.delegate[:32], h.signature[:], parts[:])
}

// A heavyweight delegation certificate (`isValid`), by its issuer, over the
// CBOR byte string "00" ‖ delegate ‖ epoch as received. `base_bytes` is what
// the certificate's spans are relative to.
verify_certificate :: proc(c: ^Delegation_Cert, base_bytes: []u8, magic: u32) -> bool {
	return verify_delegation(&c.issuer, &c.delegate, base.span_bytes(base_bytes, c.epoch_raw), &c.sig, magic)
}

// A genesis delegation certificate: as `verify_certificate`, with the epoch
// re-encoded (the genesis file holds it as a JSON number).
verify_genesis_delegation :: proc(d: ^Genesis_Delegation, magic: u32) -> bool {
	epoch: [9]u8
	n := cbor.put_head(epoch[:], .Unsigned, d.epoch)
	return verify_delegation(&d.issuer, &d.delegate, epoch[:n], &d.sig, magic)
}

@(private = "file")
verify_delegation :: proc(issuer, delegate: ^Vkey, epoch: []u8, sig: ^Signature, magic: u32) -> bool {
	tag: [6]u8
	head: [9]u8
	n := cbor.put_head(head[:], .Bytes, u64(2 + len(delegate) + len(epoch)))
	parts := [?][]u8{sign_tag(&tag, .Certificate, magic), head[:n], transmute([]u8)string("00"), delegate[:], epoch}
	return ccrypto.ed25519_verify_donna_parts(issuer[:32], sig[:], parts[:])
}

// A transaction witness, over `TxSigData`: the CBOR byte string of the
// Blake2b-256 of the transaction as received (`recoverSigData`).
verify_tx_witness :: proc(w: ^Witness, tx_hash: base.Hash32, magic: u32) -> bool {
	tag: [6]u8
	head := [2]u8{0x58, 0x20}
	hash := tx_hash
	parts := [?][]u8{sign_tag(&tag, .Tx if w.kind == .Ver_Key else .Redeem_Tx, magic), head[:], hash[:]}
	return ccrypto.ed25519_verify_donna_parts(w.key[:32], w.sig[:], parts[:])
}

// An update proposal, by its proposer, over 0x85 ‖ fields 1 to 5 as received
// (byron/Update/Proposal.hs recoverProposalSignedBytes).
verify_proposal :: proc(p: ^Proposal, block: []u8, magic: u32) -> bool {
	tag: [6]u8
	prefix := [1]u8{0x85}
	parts := [?][]u8{sign_tag(&tag, .Proposal, magic), prefix[:], base.span_bytes(block, p.body)}
	return ccrypto.ed25519_verify_donna_parts(p.from[:32], p.sig[:], parts[:])
}

// A vote, by its voter, over 0x82 ‖ proposal id as received ‖ 0xf5 (the
// decision is always True) (byron/Update/Vote.hs recoverSignedBytes).
verify_vote :: proc(v: ^Vote, block: []u8, magic: u32) -> bool {
	tag: [6]u8
	prefix := [1]u8{0x82}
	suffix := [1]u8{0xf5}
	parts := [?][]u8{sign_tag(&tag, .Vote, magic), prefix[:], base.span_bytes(block, v.proposal_id_raw), suffix[:]}
	return ccrypto.ed25519_verify_donna_parts(v.voter[:32], v.sig[:], parts[:])
}

// A Byron key hash (`hashKey`, the `KeyHash` of genesis keys and delegates):
// Blake2b-224 of SHA3-256 of the key's CBOR byte string.
vkey_hash :: proc(vk: ^Vkey) -> base.Key_Hash {
	head := [2]u8{0x58, 0x40}
	parts := [2][]u8{head[:], vk[:]}
	digest := sha3_256_parts(parts[:])
	return base.Key_Hash(ccrypto.blake2b_224(digest[:]))
}

package network

import "urd:base"
import "urd:cbor"

// Network magics of the public networks.
MAINNET_MAGIC :: 764824073
PREPROD_MAGIC :: 1
PREVIEW_MAGIC :: 2

// Tip of a chain as reported by chain-sync: `[point, block_no]`.
Tip :: struct {
	point:    base.Point,
	block_no: u64,
}

// ---------------------------------------------------------------------------
// Points and tips

write_point :: proc(w: ^cbor.Writer, p: base.Point) {
	if base.point_is_origin(p) {
		cbor.write_array(w, 0)
		return
	}
	cbor.write_array(w, 2)
	cbor.write_uint(w, u64(p.slot))
	h := p.hash
	cbor.write_bytes(w, h[:])
}

read_point :: proc(r: ^cbor.Reader) -> (p: base.Point, err: cbor.Error) {
	c := cbor.read_array(r) or_return
	if !c.indefinite && c.n == 0 {
		return base.ORIGIN, .None
	}
	if c.indefinite || c.n != 2 {
		return {}, .Length_Mismatch
	}
	p.slot = base.Slot(cbor.read_uint(r) or_return)
	p.hash = base.Block_Hash(cbor.read_hash32(r) or_return)
	return p, .None
}

read_tip :: proc(r: ^cbor.Reader) -> (t: Tip, err: cbor.Error) {
	cbor.expect_array_definite(r, 2) or_return
	t.point = read_point(r) or_return
	t.block_no = cbor.read_uint(r) or_return
	return t, .None
}

// Reads the `[tag, ...]` head of a mini-protocol message.
read_msg_tag :: proc(r: ^cbor.Reader) -> (tag: u64, n: int, err: cbor.Error) {
	c := cbor.read_array(r) or_return
	if c.indefinite {
		return 0, 0, .Unexpected_Indefinite
	}
	if c.n == 0 {
		return 0, 0, .Length_Mismatch
	}
	tag = cbor.read_uint(r) or_return
	return tag, c.n, .None
}

// ---------------------------------------------------------------------------
// Handshake (node-to-node, versions 14 to 16)

N2N_VERSION_MIN :: 14
N2N_VERSION_MAX :: 16

N2N_Version_Data :: struct {
	network_magic:  u32,
	initiator_only: bool,
	peer_sharing:   bool,
	query:          bool,
	// Version 16 onwards.
	peras:          bool,
}

write_n2n_version_data :: proc(w: ^cbor.Writer, version: u64, d: N2N_Version_Data) {
	cbor.write_array(w, 5 if version >= 16 else 4)
	cbor.write_uint(w, u64(d.network_magic))
	cbor.write_bool(w, d.initiator_only)
	cbor.write_uint(w, 1 if d.peer_sharing else 0)
	cbor.write_bool(w, d.query)
	if version >= 16 {
		cbor.write_bool(w, d.peras)
	}
}

read_n2n_version_data :: proc(r: ^cbor.Reader, version: u64) -> (d: N2N_Version_Data, err: cbor.Error) {
	cbor.expect_array_definite(r, 5 if version >= 16 else 4) or_return
	d.network_magic = cbor.read_u32(r) or_return
	d.initiator_only = cbor.read_bool(r) or_return
	ps := cbor.read_uint(r) or_return
	if ps > 1 {
		return {}, .Invalid_Value
	}
	d.peer_sharing = ps == 1
	d.query = cbor.read_bool(r) or_return
	if version >= 16 {
		d.peras = cbor.read_bool(r) or_return
	}
	return d, .None
}

// MsgProposeVersions offering every supported node-to-node version.
write_propose_versions :: proc(w: ^cbor.Writer, d: N2N_Version_Data) {
	cbor.write_array(w, 2)
	cbor.write_uint(w, 0)
	cbor.write_map(w, N2N_VERSION_MAX - N2N_VERSION_MIN + 1)
	for v in u64(N2N_VERSION_MIN) ..= N2N_VERSION_MAX {
		cbor.write_uint(w, v)
		write_n2n_version_data(w, v, d)
	}
}

Handshake_Result :: enum u8 {
	Accepted,
	Refused,
	Query_Reply,
}

// Decodes the responder's reply to MsgProposeVersions.
read_handshake_reply :: proc(
	msg: []u8,
) -> (
	result: Handshake_Result,
	version: u64,
	data: N2N_Version_Data,
	err: cbor.Error,
) {
	r := cbor.reader(msg)
	tag, n := read_msg_tag(&r) or_return
	switch tag {
	case 1:
		if n != 3 do return {}, 0, {}, .Length_Mismatch
		version = cbor.read_uint(&r) or_return
		data = read_n2n_version_data(&r, version) or_return
		cbor.expect_end(&r) or_return
		return .Accepted, version, data, .None
	case 2:
		return .Refused, 0, {}, .None
	case 3:
		return .Query_Reply, 0, {}, .None
	}
	return {}, 0, {}, .Invalid_Value
}

// ---------------------------------------------------------------------------
// Chain-sync

Chain_Sync_Msg :: enum u8 {
	Request_Next        = 0,
	Await_Reply         = 1,
	Roll_Forward        = 2,
	Roll_Backward       = 3,
	Find_Intersect      = 4,
	Intersect_Found     = 5,
	Intersect_Not_Found = 6,
	Done                = 7,
}

write_request_next :: proc(w: ^cbor.Writer) {
	cbor.write_array(w, 1)
	cbor.write_uint(w, u64(Chain_Sync_Msg.Request_Next))
}

write_find_intersect :: proc(w: ^cbor.Writer, points: []base.Point) {
	cbor.write_array(w, 2)
	cbor.write_uint(w, u64(Chain_Sync_Msg.Find_Intersect))
	cbor.write_array(w, len(points))
	for p in points {
		write_point(w, p)
	}
}

write_chain_sync_done :: proc(w: ^cbor.Writer) {
	cbor.write_array(w, 1)
	cbor.write_uint(w, u64(Chain_Sync_Msg.Done))
}

// A decoded chain-sync message from the server. `header` is the raw
// hard-fork wrapped header (node-to-node) of a roll-forward.
Chain_Sync_Reply :: struct {
	kind:   Chain_Sync_Msg,
	header: []u8,
	point:  base.Point,
	tip:    Tip,
}

read_chain_sync_reply :: proc(msg: []u8) -> (m: Chain_Sync_Reply, err: cbor.Error) {
	r := cbor.reader(msg)
	tag, n := read_msg_tag(&r) or_return
	if tag > u64(Chain_Sync_Msg.Done) {
		return {}, .Invalid_Value
	}
	m.kind = Chain_Sync_Msg(tag)
	#partial switch m.kind {
	case .Await_Reply:
		if n != 1 do return {}, .Length_Mismatch
	case .Roll_Forward:
		if n != 3 do return {}, .Length_Mismatch
		m.header = cbor.span(&r) or_return
		m.tip = read_tip(&r) or_return
	case .Roll_Backward, .Intersect_Found:
		if n != 3 do return {}, .Length_Mismatch
		m.point = read_point(&r) or_return
		m.tip = read_tip(&r) or_return
	case .Intersect_Not_Found:
		if n != 2 do return {}, .Length_Mismatch
		m.tip = read_tip(&r) or_return
	case:
		return {}, .Invalid_Value
	}
	cbor.expect_end(&r) or_return
	return m, .None
}

// ---------------------------------------------------------------------------
// Block-fetch

Block_Fetch_Msg :: enum u8 {
	Request_Range = 0,
	Client_Done   = 1,
	Start_Batch   = 2,
	No_Blocks     = 3,
	Block         = 4,
	Batch_Done    = 5,
}

write_request_range :: proc(w: ^cbor.Writer, from, to: base.Point) {
	cbor.write_array(w, 3)
	cbor.write_uint(w, u64(Block_Fetch_Msg.Request_Range))
	write_point(w, from)
	write_point(w, to)
}

write_block_fetch_done :: proc(w: ^cbor.Writer) {
	cbor.write_array(w, 1)
	cbor.write_uint(w, u64(Block_Fetch_Msg.Client_Done))
}

// Decodes a block-fetch server message. For MsgBlock, `block` is the
// hard-fork wrapped block, unwrapped from its CBOR-in-CBOR tag.
read_block_fetch_reply :: proc(msg: []u8) -> (kind: Block_Fetch_Msg, block: []u8, err: cbor.Error) {
	r := cbor.reader(msg)
	tag, n := read_msg_tag(&r) or_return
	switch tag {
	case 2, 3, 5:
		if n != 1 do return {}, nil, .Length_Mismatch
	case 4:
		if n != 2 do return {}, nil, .Length_Mismatch
		block = cbor.read_embedded(&r) or_return
	case:
		return {}, nil, .Invalid_Value
	}
	cbor.expect_end(&r) or_return
	return Block_Fetch_Msg(tag), block, .None
}

// ---------------------------------------------------------------------------
// Keep-alive

// Encoded size bound of MsgKeepAlive: array head, tag, Word16 cookie.
KEEP_ALIVE_MAX_SIZE :: 1 + 1 + 3

// MsgKeepAlive `[0, cookie]` into a caller buffer of KEEP_ALIVE_MAX_SIZE.
encode_keep_alive :: proc "contextless" (buf: []u8, cookie: u16) -> []u8 {
	buf[0] = 0x82
	buf[1] = 0x00
	n := cbor.put_head(buf[2:], .Unsigned, u64(cookie))
	return buf[:2 + n]
}

read_keep_alive_response :: proc(msg: []u8) -> (cookie: u16, err: cbor.Error) {
	r := cbor.reader(msg)
	tag, n := read_msg_tag(&r) or_return
	if tag != 1 || n != 2 {
		return 0, .Invalid_Value
	}
	cookie = cbor.read_u16(&r) or_return
	cbor.expect_end(&r) or_return
	return cookie, .None
}

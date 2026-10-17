// Package network implements the Ouroboros multiplexer and mini-protocols.
//
// The multiplexer frames each mini-protocol's byte stream into segments
// (SDUs) of at most 65535 bytes behind an 8-byte header. Segments carry no
// message boundaries: a mini-protocol message is one CBOR item, so the
// receiver accumulates each channel's bytes and cuts complete items out of
// the front.
//
// Everything here is I/O-free: callers feed received bytes in with
// `mux_ingest` and take framed bytes to send from `Mux.tx`. Both a blocking
// client and the event-loop node drive the same code.
package network

import "core:encoding/endian"
import "core:time"

import "urd:cbor"

Protocol :: enum u16 {
	Handshake           = 0,
	Chain_Sync          = 2,
	Block_Fetch         = 3,
	Tx_Submission       = 4,
	Local_Chain_Sync    = 5,
	Local_Tx_Submission = 6,
	Local_State_Query   = 7,
	Keep_Alive          = 8,
	Local_Tx_Monitor    = 9,
	Peer_Sharing        = 10,
}

MAX_PROTOCOL_ID :: 10

SDU_HEADER_SIZE :: 8
MAX_SDU_PAYLOAD :: 0xffff
// Payload size of the segments we send; cardano-node uses 12288 on sockets.
EGRESS_SDU_SIZE :: 12288

// Which side of a mini-protocol a segment belongs to. On the wire, the mode
// bit is set on segments sent by the responder.
Side :: enum u8 {
	Initiator,
	Responder,
}

Sdu_Header :: struct {
	timestamp: u32,
	protocol:  u16,
	from:      Side,
	length:    u16,
}

Mux_Error :: enum u8 {
	None,
	Unknown_Protocol,
	// A channel buffered more bytes than its protocol state allows.
	Ingress_Overflow,
	// A channel's bytes are not well-formed CBOR.
	Bad_Message,
}

// Ingress bytes of one (protocol, side) pair.
Channel :: struct {
	buf: [dynamic]u8,
	// Start of the unconsumed bytes in `buf`.
	pos: int,
	// Upper bound on buffered, unconsumed bytes (protocol-dependent).
	limit: int,
}

Mux :: struct {
	// Bytes received from the bearer that do not yet form a whole segment.
	rx:       [dynamic]u8,
	// Indexed by protocol id, then by the side that sent the bytes.
	channels: [MAX_PROTOCOL_ID + 1][Side]Channel,
	// Framed bytes waiting to be written to the bearer.
	tx:       [dynamic]u8,
	tx_pos:   int,
	// Our role on this connection; sets the mode bit on what we send.
	role:     Side,
	start:    time.Tick,
}

DEFAULT_CHANNEL_LIMIT :: 4 * 1024 * 1024

mux_init :: proc(m: ^Mux, role: Side, allocator := context.allocator) {
	m.rx = make([dynamic]u8, 0, 2 * (SDU_HEADER_SIZE + MAX_SDU_PAYLOAD), allocator)
	m.tx = make([dynamic]u8, 0, 64 * 1024, allocator)
	for &sides in m.channels {
		for &ch in sides {
			ch.buf = make([dynamic]u8, allocator)
			ch.limit = DEFAULT_CHANNEL_LIMIT
		}
	}
	m.role = role
	m.start = time.tick_now()
}

mux_destroy :: proc(m: ^Mux) {
	delete(m.rx)
	delete(m.tx)
	for &sides in m.channels {
		for &ch in sides {
			delete(ch.buf)
		}
	}
}

encode_sdu_header :: proc "contextless" (dst: []u8, h: Sdu_Header) {
	endian.unchecked_put_u32be(dst[0:], h.timestamp)
	id := h.protocol & 0x7fff
	if h.from == .Responder {
		id |= 0x8000
	}
	endian.unchecked_put_u16be(dst[4:], id)
	endian.unchecked_put_u16be(dst[6:], h.length)
}

decode_sdu_header :: proc "contextless" (src: []u8) -> (h: Sdu_Header) {
	h.timestamp = endian.unchecked_get_u32be(src[0:])
	id := endian.unchecked_get_u16be(src[4:])
	h.protocol = id & 0x7fff
	h.from = .Responder if id & 0x8000 != 0 else .Initiator
	h.length = endian.unchecked_get_u16be(src[6:])
	return
}

@(private)
timestamp :: proc(m: ^Mux) -> u32 {
	return u32(time.duration_microseconds(time.tick_since(m.start)))
}

// Frames `msg` for `protocol` and appends it to the transmit buffer.
mux_send :: proc(m: ^Mux, protocol: Protocol, msg: []u8) {
	ts := timestamp(m)
	rest := msg
	for {
		n := min(len(rest), EGRESS_SDU_SIZE)
		hdr: [SDU_HEADER_SIZE]u8
		encode_sdu_header(hdr[:], Sdu_Header{timestamp = ts, protocol = u16(protocol), from = m.role, length = u16(n)})
		append(&m.tx, ..hdr[:])
		append(&m.tx, ..rest[:n])
		rest = rest[n:]
		if len(rest) == 0 do break
	}
}

// Bytes of `tx` not yet written. Call `mux_sent` with how many were written.
mux_pending :: proc(m: ^Mux) -> []u8 {
	return m.tx[m.tx_pos:]
}

mux_sent :: proc(m: ^Mux, n: int) {
	m.tx_pos += n
	if m.tx_pos == len(m.tx) {
		clear(&m.tx)
		m.tx_pos = 0
	}
}

// Feeds bytes read from the bearer: complete segments are moved into their
// channels, a trailing partial segment is kept for the next call.
mux_ingest :: proc(m: ^Mux, data: []u8) -> Mux_Error {
	append(&m.rx, ..data)
	pos := 0
	for len(m.rx) - pos >= SDU_HEADER_SIZE {
		h := decode_sdu_header(m.rx[pos:])
		total := SDU_HEADER_SIZE + int(h.length)
		if len(m.rx) - pos < total {
			break
		}
		if h.protocol > MAX_PROTOCOL_ID {
			return .Unknown_Protocol
		}
		ch := &m.channels[h.protocol][h.from]
		if len(ch.buf) - ch.pos + int(h.length) > ch.limit {
			return .Ingress_Overflow
		}
		append(&ch.buf, ..m.rx[pos + SDU_HEADER_SIZE:][:h.length])
		pos += total
	}
	if pos > 0 {
		remove_range(&m.rx, 0, pos)
	}
	return .None
}

// Takes the next complete message that `from` sent on `protocol`, if one has
// fully arrived. The slice aliases the channel buffer and stays valid until
// the next `mux_ingest` or `mux_recv` on that channel.
mux_recv :: proc(m: ^Mux, protocol: Protocol, from: Side) -> (msg: []u8, ok: bool, err: Mux_Error) {
	ch := &m.channels[u16(protocol)][from]
	if ch.pos > 0 && ch.pos == len(ch.buf) {
		clear(&ch.buf)
		ch.pos = 0
	} else if ch.pos > len(ch.buf) / 2 {
		remove_range(&ch.buf, 0, ch.pos)
		ch.pos = 0
	}
	if ch.pos == len(ch.buf) {
		return nil, false, .None
	}
	r := cbor.reader(ch.buf[ch.pos:])
	item, cerr := cbor.span(&r)
	#partial switch cerr {
	case .None:
		ch.pos += len(item)
		return item, true, .None
	case .Eof:
		return nil, false, .None
	}
	return nil, false, .Bad_Message
}

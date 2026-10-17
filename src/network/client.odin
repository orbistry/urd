package network

import "core:net"
import "core:time"

import "urd:base"
import "urd:cbor"

// A blocking node-to-node client over one TCP connection. Used by tools and
// tests to pull headers and blocks from a peer; the node itself drives the
// same mux and codecs from an event loop.
Client :: struct {
	socket:             net.TCP_Socket,
	mux:                Mux,
	w:                  cbor.Writer,
	rx_buf:             []u8,
	version:            u64,
	// Chain-sync requests sent but not yet answered by a roll forward/back.
	in_flight:          int,
	// Keep-alive: the responder drops a client that stays silent on this
	// protocol for 97 s (timeLimitsKeepAlive).
	keep_alive_at:      time.Tick,
	keep_alive_cookie:  u16,
	keep_alive_pending: bool,
}

KEEP_ALIVE_INTERVAL :: 10 * time.Second

Client_Error :: enum u8 {
	None,
	Connect,
	Send,
	Recv,
	Closed,
	Mux,
	Decode,
	Handshake_Refused,
	Unexpected_Message,
}

client_connect :: proc(c: ^Client, peer: string, network_magic: u32, allocator := context.allocator) -> Client_Error {
	sock, err := net.dial_tcp(peer)
	if err != nil {
		return .Connect
	}
	c.socket = sock
	mux_init(&c.mux, .Initiator, allocator)
	c.w = cbor.writer(allocator)
	c.rx_buf = make([]u8, 256 * 1024, allocator)

	cbor.writer_reset(&c.w)
	write_propose_versions(&c.w, N2N_Version_Data{network_magic = network_magic, initiator_only = true})
	client_send(c, .Handshake) or_return
	msg := client_recv(c, .Handshake) or_return
	result, version, _, derr := read_handshake_reply(msg)
	if derr != .None {
		return .Decode
	}
	if result != .Accepted {
		return .Handshake_Refused
	}
	c.version = version
	c.keep_alive_at = time.tick_now()
	return .None
}

// Sends MsgKeepAlive when the interval has passed and the previous one was
// answered. Called from every blocking wait.
client_keep_alive :: proc(c: ^Client) -> Client_Error {
	if c.keep_alive_pending {
		msg, ok, merr := mux_recv(&c.mux, .Keep_Alive, .Responder)
		if merr != .None do return .Mux
		if !ok do return .None
		cookie, derr := read_keep_alive_response(msg)
		if derr != .None || cookie != c.keep_alive_cookie {
			return .Unexpected_Message
		}
		c.keep_alive_pending = false
	}
	if time.tick_since(c.keep_alive_at) < KEEP_ALIVE_INTERVAL {
		return .None
	}
	c.keep_alive_cookie += 1
	ka: cbor.Writer = cbor.writer(context.temp_allocator, 16)
	write_keep_alive(&ka, c.keep_alive_cookie)
	mux_send(&c.mux, .Keep_Alive, cbor.writer_bytes(&ka))
	c.keep_alive_pending = true
	c.keep_alive_at = time.tick_now()
	return .None
}

client_close :: proc(c: ^Client) {
	net.close(c.socket)
	mux_destroy(&c.mux)
	cbor.writer_destroy(&c.w)
	delete(c.rx_buf)
}

// Frames the writer's contents for `protocol` and writes everything pending.
client_send :: proc(c: ^Client, protocol: Protocol) -> Client_Error {
	mux_send(&c.mux, protocol, cbor.writer_bytes(&c.w))
	for {
		pending := mux_pending(&c.mux)
		if len(pending) == 0 do return .None
		n, err := net.send_tcp(c.socket, pending)
		if err != nil || n <= 0 {
			return .Send
		}
		mux_sent(&c.mux, n)
	}
}

// Blocks until the responder's next message on `protocol` has arrived.
client_recv :: proc(c: ^Client, protocol: Protocol) -> (msg: []u8, err: Client_Error) {
	for {
		m, ok, merr := mux_recv(&c.mux, protocol, .Responder)
		if merr != .None {
			return nil, .Mux
		}
		if ok {
			return m, .None
		}
		client_keep_alive(c) or_return
		if len(mux_pending(&c.mux)) > 0 {
			sn, serr := net.send_tcp(c.socket, mux_pending(&c.mux))
			if serr != nil || sn <= 0 do return nil, .Send
			mux_sent(&c.mux, sn)
		}
		n, rerr := net.recv_tcp(c.socket, c.rx_buf)
		if rerr != nil {
			return nil, .Recv
		}
		if n == 0 {
			return nil, .Closed
		}
		if mux_ingest(&c.mux, c.rx_buf[:n]) != .None {
			return nil, .Mux
		}
	}
}

// Finds the most recent of `points` that the peer also has.
client_find_intersect :: proc(
	c: ^Client,
	points: []base.Point,
) -> (
	found: bool,
	point: base.Point,
	tip: Tip,
	err: Client_Error,
) {
	cbor.writer_reset(&c.w)
	write_find_intersect(&c.w, points)
	client_send(c, .Chain_Sync) or_return
	msg := client_recv(c, .Chain_Sync) or_return
	reply, derr := read_chain_sync_reply(msg)
	if derr != .None {
		return false, {}, {}, .Decode
	}
	#partial switch reply.kind {
	case .Intersect_Found:
		return true, reply.point, reply.tip, .None
	case .Intersect_Not_Found:
		return false, {}, reply.tip, .None
	}
	return false, {}, {}, .Unexpected_Message
}

// Keeps `depth` MsgRequestNext in flight and returns the next roll forward or
// roll backward. MsgAwaitReply is skipped (the following message answers the
// same request). The returned header aliases the mux buffer.
client_next_header :: proc(c: ^Client, depth: int) -> (reply: Chain_Sync_Reply, err: Client_Error) {
	if c.in_flight < depth {
		cbor.writer_reset(&c.w)
		for _ in c.in_flight ..< depth {
			write_request_next(&c.w)
		}
		client_send(c, .Chain_Sync) or_return
		c.in_flight = depth
	}
	for {
		msg := client_recv(c, .Chain_Sync) or_return
		r, derr := read_chain_sync_reply(msg)
		if derr != .None {
			return {}, .Decode
		}
		#partial switch r.kind {
		case .Await_Reply:
			continue
		case .Roll_Forward, .Roll_Backward:
			c.in_flight -= 1
			return r, .None
		}
		return {}, .Unexpected_Message
	}
}

// Requests the blocks between `from` and `to` (inclusive) and calls `on_block`
// with each hard-fork wrapped block until it returns false; the rest of the
// batch is still drained. Returns false if the peer has no blocks for the
// range.
client_fetch_range :: proc(
	c: ^Client,
	from, to: base.Point,
	on_block: proc(block: []u8, user: rawptr) -> bool,
	user: rawptr,
) -> (
	found: bool,
	err: Client_Error,
) {
	cbor.writer_reset(&c.w)
	write_request_range(&c.w, from, to)
	client_send(c, .Block_Fetch) or_return
	msg := client_recv(c, .Block_Fetch) or_return
	kind, _, derr := read_block_fetch_reply(msg)
	if derr != .None {
		return false, .Decode
	}
	#partial switch kind {
	case .No_Blocks:
		return false, .None
	case .Start_Batch:
	case:
		return false, .Unexpected_Message
	}
	wanted := true
	for {
		m := client_recv(c, .Block_Fetch) or_return
		k, block, berr := read_block_fetch_reply(m)
		if berr != .None {
			return false, .Decode
		}
		#partial switch k {
		case .Block:
			if wanted {
				wanted = on_block(block, user)
			}
		case .Batch_Done:
			return true, .None
		case:
			return false, .Unexpected_Message
		}
	}
}

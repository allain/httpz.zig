const H2Connection = @This();
const std = @import("std");
const mem = std.mem;
const Io = std.Io;

const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Headers = @import("../Headers.zig");
const Connection = @import("Connection.zig");
const Date = @import("Date.zig");

const h2 = @import("../h2/root.zig");
const frame = h2.frame;
const hpack = h2.hpack;
const FrameType = frame.FrameType;
const FrameHeader = frame.FrameHeader;
const Flags = frame.Flags;
const Stream = h2.Stream;
const StreamRegistry = h2.StreamRegistry;
const FlowControl = h2.FlowControl;
const Settings = h2.Settings;
const ErrorCode = h2.ErrorCode;

const Handler = Connection.Handler;

/// Serve an HTTP/2 connection.
///
/// This is called after TLS negotiation selects "h2" via ALPN, or
/// when prior knowledge (h2c) is detected on a cleartext connection.
///
/// The caller provides the reader/writer that sit on top of TLS
/// (or raw TCP for h2c).
pub fn serve(reader: *Io.Reader, writer: *Io.Writer, handler: Handler, io: Io) void {
    serveImpl(reader, writer, handler, io) catch {};
}

fn serveImpl(reader: *Io.Reader, writer: *Io.Writer, handler: Handler, io: Io) !void {
    // --- Connection Preface (RFC 9113 §3.4) ---
    // Client must send the 24-byte preface, then a SETTINGS frame.
    // We validate the preface, then send our own SETTINGS + ACK.

    var preface_buf: [frame.connection_preface.len]u8 = undefined;
    reader.readSliceAll(&preface_buf) catch return;
    if (!mem.eql(u8, &preface_buf, frame.connection_preface)) {
        // Invalid preface — close without GOAWAY per RFC 9113 §3.4
        return;
    }

    // Send our server preface: SETTINGS frame
    var our_settings: Settings = .{};
    our_settings.max_concurrent_streams = 100;
    const settings_list = [_]frame.Setting{
        .{ .id = .max_concurrent_streams, .value = 100 },
    };
    try frame.writeSettings(writer, &settings_list);
    try writer.flush();

    // Read the client's SETTINGS frame (must be first frame after preface)
    var peer_settings: Settings = .{};
    {
        const f = readFrameFromReader(reader) catch return;
        if (f.header.frame_type != .settings or f.header.flags.has(Flags.ack)) {
            try sendGoaway(writer, 0, .protocol_error);
            return;
        }
        if (f.header.stream_id != 0) {
            try sendGoaway(writer, 0, .protocol_error);
            return;
        }
        _ = peer_settings.applyAll(f.payload) catch {
            try sendGoaway(writer, 0, .protocol_error);
            return;
        };
    }
    // ACK the client's SETTINGS
    try frame.writeSettingsAck(writer);
    try writer.flush();

    // --- Connection state ---
    var registry: StreamRegistry = .{ .is_server = true, .max_concurrent_streams = our_settings.max_concurrent_streams };
    var flow: FlowControl.FlowController = .{};

    // HPACK decoder state
    var hpack_dec_buf: [4096]u8 = undefined;
    var hpack_dec_entries: [128]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&hpack_dec_buf, &hpack_dec_entries);
    decoder.dynamic_table.setMaxSize(peer_settings.header_table_size);

    // HPACK encoder state
    var hpack_enc_buf: [4096]u8 = undefined;
    var hpack_enc_entries: [128]hpack.DynamicTable.Entry = undefined;
    var encoder = hpack.Encoder.init(&hpack_enc_buf, &hpack_enc_entries);

    // Header block assembly buffer (for CONTINUATION frames)
    var header_block_buf: [16384]u8 = undefined;
    var header_block_len: usize = 0;
    var header_block_stream_id: u31 = 0;
    var header_block_end_stream: bool = false;

    // Track last stream ID for GOAWAY
    var last_client_stream_id: u31 = 0;

    // --- Frame loop ---
    while (true) {
        const f = readFrameFromReader(reader) catch |err| switch (err) {
            error.EndOfStream => return,
            else => {
                sendGoaway(writer, last_client_stream_id, .protocol_error) catch {};
                return;
            },
        };

        // If we're assembling a header block, only CONTINUATION on the same
        // stream is allowed (RFC 9113 §4.3)
        if (header_block_len > 0) {
            if (f.header.frame_type != .continuation or f.header.stream_id != header_block_stream_id) {
                try sendGoaway(writer, last_client_stream_id, .protocol_error);
                return;
            }
        }

        switch (f.header.frame_type) {
            .settings => {
                if (f.header.stream_id != 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
                if (f.header.flags.has(Flags.ack)) {
                    // ACK of our settings — nothing to do
                    continue;
                }
                const old_window = peer_settings.applyAll(f.payload) catch {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                };
                // Adjust stream windows if initial_window_size changed
                if (peer_settings.initial_window_size != old_window) {
                    const delta: i32 = @as(i32, @intCast(peer_settings.initial_window_size)) - @as(i32, @intCast(old_window));
                    for (registry.streams[0..registry.len]) |*s| {
                        if (s.isActive()) {
                            s.send_window +|= delta;
                        }
                    }
                }
                decoder.dynamic_table.setMaxSize(peer_settings.header_table_size);
                try frame.writeSettingsAck(writer);
                try writer.flush();
            },

            .ping => {
                if (f.header.stream_id != 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
                if (f.payload.len != 8) {
                    try sendGoaway(writer, last_client_stream_id, .frame_size_error);
                    return;
                }
                if (!f.header.flags.has(Flags.ack)) {
                    try frame.writePing(writer, f.payload[0..8], true);
                    try writer.flush();
                }
            },

            .goaway => {
                // Peer is shutting down — stop processing
                return;
            },

            .window_update => {
                if (f.payload.len != 4) {
                    try sendGoaway(writer, last_client_stream_id, .frame_size_error);
                    return;
                }
                const increment = frame.parseWindowUpdate(f.payload) catch {
                    if (f.header.stream_id == 0) {
                        try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    } else {
                        try frame.writeRstStream(writer, f.header.stream_id, .protocol_error);
                        try writer.flush();
                    }
                    return;
                };
                if (f.header.stream_id == 0) {
                    flow.recvWindowUpdate(increment) catch {
                        try sendGoaway(writer, last_client_stream_id, .flow_control_error);
                        return;
                    };
                } else {
                    if (registry.get(f.header.stream_id)) |s| {
                        const new: i64 = @as(i64, s.send_window) + @as(i64, increment);
                        if (new > std.math.maxInt(i32)) {
                            try frame.writeRstStream(writer, f.header.stream_id, .flow_control_error);
                            try writer.flush();
                            continue;
                        }
                        s.send_window = @intCast(new);
                    }
                }
            },

            .headers => {
                if (f.header.stream_id == 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }

                // Parse past padding and priority fields to get the header block fragment
                var payload = f.payload;
                var pad_len: usize = 0;
                if (f.header.flags.has(Flags.padded)) {
                    if (payload.len < 1) {
                        try sendGoaway(writer, last_client_stream_id, .protocol_error);
                        return;
                    }
                    pad_len = payload[0];
                    payload = payload[1..];
                }
                if (f.header.flags.has(Flags.priority_flag)) {
                    if (payload.len < 5) {
                        try sendGoaway(writer, last_client_stream_id, .protocol_error);
                        return;
                    }
                    payload = payload[5..]; // skip dependency(4) + weight(1)
                }
                if (pad_len > payload.len) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
                const fragment = payload[0 .. payload.len - pad_len];

                if (f.header.flags.has(Flags.end_headers)) {
                    // Complete header block in a single HEADERS frame
                    last_client_stream_id = f.header.stream_id;
                    processRequest(
                        &registry,
                        &decoder,
                        &encoder,
                        &flow,
                        &peer_settings,
                        fragment,
                        f.header.stream_id,
                        f.header.flags.has(Flags.end_stream),
                        writer,
                        handler,
                        io,
                    );
                } else {
                    // Start of multi-frame header block — buffer it
                    if (fragment.len > header_block_buf.len) {
                        try sendGoaway(writer, last_client_stream_id, .internal_error);
                        return;
                    }
                    @memcpy(header_block_buf[0..fragment.len], fragment);
                    header_block_len = fragment.len;
                    header_block_stream_id = f.header.stream_id;
                    header_block_end_stream = f.header.flags.has(Flags.end_stream);
                }
            },

            .continuation => {
                // Must be assembling a header block
                if (header_block_len == 0 or f.header.stream_id != header_block_stream_id) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
                if (header_block_len + f.payload.len > header_block_buf.len) {
                    try sendGoaway(writer, last_client_stream_id, .internal_error);
                    return;
                }
                @memcpy(header_block_buf[header_block_len..][0..f.payload.len], f.payload);
                header_block_len += f.payload.len;

                if (f.header.flags.has(Flags.end_headers)) {
                    last_client_stream_id = header_block_stream_id;
                    processRequest(
                        &registry,
                        &decoder,
                        &encoder,
                        &flow,
                        &peer_settings,
                        header_block_buf[0..header_block_len],
                        header_block_stream_id,
                        header_block_end_stream,
                        writer,
                        handler,
                        io,
                    );
                    header_block_len = 0;
                    header_block_stream_id = 0;
                }
            },

            .data => {
                if (f.header.stream_id == 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }

                // Flow control: account for received data
                var data_len: usize = f.payload.len;
                if (f.header.flags.has(Flags.padded) and data_len > 0) {
                    data_len -= 1; // pad length byte
                    data_len -= f.payload[0]; // padding
                }
                if (data_len > 0) {
                    const should_update = flow.recordRecv(@intCast(f.payload.len)) catch {
                        try sendGoaway(writer, last_client_stream_id, .flow_control_error);
                        return;
                    };
                    if (should_update) {
                        const inc = flow.pendingWindowUpdate() catch {
                            try sendGoaway(writer, last_client_stream_id, .internal_error);
                            return;
                        };
                        if (inc > 0) {
                            try frame.writeWindowUpdate(writer, 0, inc);
                            try frame.writeWindowUpdate(writer, f.header.stream_id, inc);
                            try writer.flush();
                        }
                    }
                }

                // Update stream state
                if (registry.get(f.header.stream_id)) |s| {
                    s.recv(f.header.frame_type, f.header.flags) catch {
                        try frame.writeRstStream(writer, f.header.stream_id, .stream_closed);
                        try writer.flush();
                    };
                }
                // TODO: buffer request body data and deliver to handler
            },

            .rst_stream => {
                if (f.header.stream_id == 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
                if (registry.get(f.header.stream_id)) |s| {
                    s.recv(.rst_stream, Flags.none) catch {};
                }
            },

            .priority => {
                // Deprecated in RFC 9113 but must be tolerated
                if (f.header.stream_id == 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
            },

            .push_promise => {
                // Clients must not send PUSH_PROMISE
                try sendGoaway(writer, last_client_stream_id, .protocol_error);
                return;
            },

            _ => {
                // Unknown frame types MUST be ignored (RFC 9113 §4.1)
            },
        }

        // Periodic GC of closed streams
        if (registry.len > 64) {
            registry.gc();
        }
    }
}

/// Process a complete request (headers decoded from HPACK) and send the response.
fn processRequest(
    registry: *StreamRegistry,
    decoder: *hpack.Decoder,
    encoder: *hpack.Encoder,
    flow: *FlowControl.FlowController,
    peer_settings: *const Settings,
    header_block: []const u8,
    stream_id: u31,
    end_stream: bool,
    writer: *Io.Writer,
    handler: Handler,
    io: Io,
) void {
    processRequestImpl(registry, decoder, encoder, flow, peer_settings, header_block, stream_id, end_stream, writer, handler, io) catch {
        // Send RST_STREAM on error
        frame.writeRstStream(writer, stream_id, .internal_error) catch {};
        writer.flush() catch {};
    };
}

fn processRequestImpl(
    registry: *StreamRegistry,
    decoder: *hpack.Decoder,
    encoder: *hpack.Encoder,
    flow: *FlowControl.FlowController,
    peer_settings: *const Settings,
    header_block: []const u8,
    stream_id: u31,
    end_stream: bool,
    writer: *Io.Writer,
    handler: Handler,
    io: Io,
) !void {
    // Create/get stream
    const stream = registry.getOrCreate(stream_id) catch |err| switch (err) {
        error.RefusedStream => {
            try frame.writeRstStream(writer, stream_id, .refused_stream);
            try writer.flush();
            return;
        },
        else => {
            try frame.writeRstStream(writer, stream_id, .protocol_error);
            try writer.flush();
            return;
        },
    };

    // Transition stream state for HEADERS recv
    const flags_value: u8 = Flags.end_headers | if (end_stream) Flags.end_stream else 0;
    stream.recv(.headers, .{ .value = flags_value }) catch {
        try frame.writeRstStream(writer, stream_id, .protocol_error);
        try writer.flush();
        return;
    };

    // Decode HPACK headers
    var decoded_headers: [hpack.max_decoded_headers]hpack.HeaderField = undefined;
    const header_count = decoder.decode(header_block, &decoded_headers) catch {
        // HPACK decompression failure is a connection error
        try sendGoaway(writer, stream_id, .compression_error);
        return;
    };
    const headers = decoded_headers[0..header_count];

    // Extract pseudo-headers (RFC 9113 §8.3.1)
    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;

    for (headers) |h| {
        if (h.name.len > 0 and h.name[0] == ':') {
            if (mem.eql(u8, h.name, ":method")) {
                method = h.value;
            } else if (mem.eql(u8, h.name, ":path")) {
                path = h.value;
            } else if (mem.eql(u8, h.name, ":scheme")) {
                scheme = h.value;
            } else if (mem.eql(u8, h.name, ":authority")) {
                authority = h.value;
            }
        }
    }

    // Validate required pseudo-headers
    if (method == null or path == null or scheme == null) {
        try frame.writeRstStream(writer, stream_id, .protocol_error);
        try writer.flush();
        return;
    }

    // Build a synthetic HTTP/1.1 request line + headers for the existing handler
    var request_buf: [8192]u8 = undefined;
    var pos: usize = 0;

    // Request line: "GET /path HTTP/1.1\r\n"
    const m = method.?;
    const p = path.?;
    @memcpy(request_buf[pos..][0..m.len], m);
    pos += m.len;
    request_buf[pos] = ' ';
    pos += 1;
    @memcpy(request_buf[pos..][0..p.len], p);
    pos += p.len;
    @memcpy(request_buf[pos..][0..11], " HTTP/1.1\r\n");
    pos += 11;

    // Host header from :authority
    if (authority) |auth| {
        @memcpy(request_buf[pos..][0..6], "Host: ");
        pos += 6;
        @memcpy(request_buf[pos..][0..auth.len], auth);
        pos += auth.len;
        @memcpy(request_buf[pos..][0..2], "\r\n");
        pos += 2;
    }

    // Regular headers (skip pseudo-headers)
    for (headers) |h| {
        if (h.name.len > 0 and h.name[0] == ':') continue;
        // Skip prohibited headers (RFC 9113 §8.2.2)
        if (Headers.eqlIgnoreCase(h.name, "connection")) continue;
        if (Headers.eqlIgnoreCase(h.name, "keep-alive")) continue;
        if (Headers.eqlIgnoreCase(h.name, "transfer-encoding")) continue;
        if (Headers.eqlIgnoreCase(h.name, "upgrade")) continue;

        if (pos + h.name.len + h.value.len + 4 > request_buf.len) break;
        @memcpy(request_buf[pos..][0..h.name.len], h.name);
        pos += h.name.len;
        @memcpy(request_buf[pos..][0..2], ": ");
        pos += 2;
        @memcpy(request_buf[pos..][0..h.value.len], h.value);
        pos += h.value.len;
        @memcpy(request_buf[pos..][0..2], "\r\n");
        pos += 2;
    }

    // End of headers
    @memcpy(request_buf[pos..][0..2], "\r\n");
    pos += 2;

    // Parse the synthetic request
    const request = Request.parse(request_buf[0..pos]) catch {
        try frame.writeRstStream(writer, stream_id, .protocol_error);
        try writer.flush();
        return;
    };

    // Call the handler
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const timestamp = Date.now(io);
    var response = Connection.processRequest(allocator, io, timestamp, &request, handler);
    defer response.deinit(allocator);

    // --- Encode and send the HTTP/2 response ---

    // Encode response headers via HPACK
    var resp_header_buf: [8192]u8 = undefined;
    var hpos: usize = 0;

    // :status pseudo-header
    var status_str: [3]u8 = undefined;
    _ = std.fmt.bufPrint(&status_str, "{d}", .{response.status.toInt()}) catch unreachable;
    hpos += try encoder.encodeHeader(resp_header_buf[hpos..], ":status", &status_str);

    // Response headers
    for (response.headers.entries[0..response.headers.len]) |entry| {
        if (entry.name.len == 0) continue;
        // Skip HTTP/1.1-only headers
        if (Headers.eqlIgnoreCase(entry.name, "connection")) continue;
        if (Headers.eqlIgnoreCase(entry.name, "keep-alive")) continue;
        if (Headers.eqlIgnoreCase(entry.name, "transfer-encoding")) continue;
        if (hpos + entry.name.len + entry.value.len + 10 > resp_header_buf.len) break;
        hpos += try encoder.encodeHeader(resp_header_buf[hpos..], entry.name, entry.value);
    }

    // Content-Length if we have a body and auto_content_length
    if (response.auto_content_length and response.body.len > 0 and !response.strip_body) {
        var cl_buf: [20]u8 = undefined;
        const cl_str = std.fmt.bufPrint(&cl_buf, "{d}", .{response.body.len}) catch unreachable;
        hpos += try encoder.encodeHeader(resp_header_buf[hpos..], "content-length", cl_str);
    }

    const has_body = !response.strip_body and response.body.len > 0;
    const header_flags: u8 = Flags.end_headers | if (!has_body) Flags.end_stream else 0;

    // Send HEADERS frame(s) — split if exceeds max frame size
    const max_payload: usize = peer_settings.max_frame_size;
    if (hpos <= max_payload) {
        try frame.writeFrame(writer, .headers, .{ .value = header_flags }, stream_id, resp_header_buf[0..hpos]);
    } else {
        // First frame: HEADERS without END_HEADERS
        try frame.writeFrame(writer, .headers, Flags.none, stream_id, resp_header_buf[0..max_payload]);
        var sent: usize = max_payload;
        while (sent < hpos) {
            const chunk = @min(hpos - sent, max_payload);
            const is_last = sent + chunk >= hpos;
            const cont_flags: Flags = if (is_last) .{ .value = Flags.end_headers | if (!has_body) Flags.end_stream else 0 } else Flags.none;
            try frame.writeFrame(writer, .continuation, cont_flags, stream_id, resp_header_buf[sent..][0..chunk]);
            sent += chunk;
        }
    }

    // Send DATA frame(s) for the body
    if (has_body) {
        const body = response.body;
        var sent: usize = 0;
        while (sent < body.len) {
            const chunk = @min(body.len - sent, max_payload);
            const is_last = sent + chunk >= body.len;

            // Flow control: wait for window (simplified — just check)
            const avail = flow.effectiveSendWindow(stream.send_window);
            const to_send = @min(chunk, avail);
            if (to_send == 0 and chunk > 0) {
                // No window available — send what we can, which is nothing.
                // In a production implementation we'd park and wait for WINDOW_UPDATE.
                // For now, just send it anyway (peer will handle with flow control error or buffer it).
                // TODO: proper flow control backpressure
            }

            const data_flags: Flags = if (is_last) .{ .value = Flags.end_stream } else Flags.none;
            try frame.writeFrame(writer, .data, data_flags, stream_id, body[sent..][0..chunk]);

            // Consume from flow control windows
            if (chunk > 0) {
                flow.send_window.consume(@intCast(chunk)) catch {};
                stream.send_window -= @intCast(chunk);
            }

            sent += chunk;
        }
    }

    // Update stream state for sent response
    if (has_body) {
        stream.send(.data, .{ .value = Flags.end_stream }) catch {};
    } else {
        stream.send(.headers, .{ .value = Flags.end_stream }) catch {};
    }

    try writer.flush();
}

fn readFrameFromReader(reader: *Io.Reader) !frame.Frame {
    // Read the 9-byte frame header
    const hdr_buf = try reader.take(frame.header_size);
    const header = FrameHeader.parse(hdr_buf[0..frame.header_size]);

    if (header.length > frame.default_max_frame_size) {
        return error.FrameSizeError;
    }

    // Read the payload
    var payload: []const u8 = &.{};
    if (header.length > 0) {
        payload = try reader.take(header.length);
    }

    return .{
        .header = header,
        .payload = payload,
    };
}

fn sendGoaway(writer: *Io.Writer, last_stream_id: u31, error_code: ErrorCode) !void {
    try frame.writeGoaway(writer, last_stream_id, error_code, &.{});
    try writer.flush();
}

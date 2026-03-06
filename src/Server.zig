const Server = @This();
const std = @import("std");
const Io = std.Io;
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Connection = @import("Connection.zig");
const Headers = @import("Headers.zig");
const Date = @import("Date.zig");
const Proxy = @import("Proxy.zig");

/// RFC 2616 Section 1.4: HTTP/1.1 server implementation.
///
/// This server uses the Zig 0.16 std.Io interface for networking,
/// supporting both threaded and evented I/O backends.

/// Proxy access control configuration.
/// Controls which targets can be reached through CONNECT tunneling.
pub const ProxyConfig = struct {
    /// Allowed destination ports. If empty, all ports are allowed.
    /// Common safe default: &.{443} (HTTPS only).
    allowed_ports: []const u16 = &.{443},
    /// Block connections to private/loopback IP ranges (SSRF protection).
    /// When true, rejects targets resolving to 127.0.0.0/8, 10.0.0.0/8,
    /// 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, and ::1.
    block_private_ips: bool = true,
    /// Optional allowed target hosts. If non-empty, only these hosts
    /// are permitted as CONNECT targets. Checked case-insensitively.
    allowed_hosts: []const []const u8 = &.{},
};

pub const Config = struct {
    port: u16 = 8080,
    address: []const u8 = "127.0.0.1",
    /// RFC 2616 Section 8.1.4: Servers SHOULD implement persistent connections
    /// but may close idle connections after a timeout.
    read_buffer_size: usize = 8192,
    write_buffer_size: usize = 8192,
    /// Maximum total request size (headers + body)
    max_request_size: usize = 1_048_576,
    /// RFC 2616 Section 8.1.4: Idle connection timeout in seconds.
    /// Connections with no activity for this duration will be closed.
    /// 0 means no timeout. Requires async Io backend for enforcement.
    keep_alive_timeout_s: u32 = 60,
    /// Maximum number of concurrent connections. 0 means unlimited.
    /// When the limit is reached, new connections are accepted and
    /// immediately closed.
    max_connections: u32 = 512,
    /// RFC 2616 Section 9.8: Enable TRACE method support.
    /// TRACE echoes the full request (including headers like Cookie and
    /// Authorization) back to the client. This is a security risk (XST)
    /// and is disabled by default.
    enable_trace: bool = false,
    /// RFC 2616 Section 9.9 / 14.45: Enable proxy support.
    /// When true, the server handles CONNECT requests for tunneling
    /// and adds Via headers to proxied responses.
    enable_proxy: bool = false,
    /// Proxy access control settings. Only used when enable_proxy is true.
    proxy: ProxyConfig = .{},
};

config: Config,
handler: Connection.Handler,
active_connections: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

pub fn init(config: Config, handler: Connection.Handler) Server {
    return .{
        .config = config,
        .handler = handler,
    };
}

/// Start the server. This is the main entry point for running the HTTP server
/// with the Zig 0.16 std.Io networking API.
///
/// Uses Io.net.IpAddress.listen() to create a listening socket and
/// Server.accept() to handle incoming connections.
pub fn run(self: *Server, io: Io) !void {
    const addr = try Io.net.IpAddress.parseIp4(self.config.address, self.config.port);

    var server = try Io.net.IpAddress.listen(addr, io, .{});
    defer server.deinit(io);

    while (true) {
        const stream = server.accept(io) catch |err| {
            std.debug.print("Accept error: {}\n", .{err});
            continue;
        };

        // Enforce connection limit
        if (self.config.max_connections > 0) {
            const current = self.active_connections.load(.monotonic);
            if (current >= self.config.max_connections) {
                stream.close(io);
                continue;
            }
            _ = self.active_connections.fetchAdd(1, .monotonic);
        }

        self.handleConnection(stream, io) catch |err| {
            std.debug.print("Connection error: {}\n", .{err});
        };

        if (self.config.max_connections > 0) {
            _ = self.active_connections.fetchSub(1, .monotonic);
        }

        stream.close(io);
    }
}

/// Handle a single TCP connection, potentially with multiple requests
/// (keep-alive).
///
/// RFC 2616 Section 8.1: Persistent Connections
fn handleConnection(self: *Server, stream: Io.net.Stream, io: Io) !void {
    // RFC 2616 Section 8.1.4: Set socket read timeout for idle connections.
    if (self.config.keep_alive_timeout_s > 0) {
        setSocketTimeout(stream.socket.handle, self.config.keep_alive_timeout_s);
    }

    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var net_reader = Io.net.Stream.Reader.init(stream, io, &read_buf);
    var net_writer = Io.net.Stream.Writer.init(stream, io, &write_buf);

    // Heap-allocate the request buffer to avoid ~1 MiB stack usage per
    // connection, which can cause stack overflows under concurrent load.
    const request_buf = std.heap.page_allocator.alloc(u8, self.config.max_request_size) catch return;
    defer std.heap.page_allocator.free(request_buf);

    while (true) {
        // Read request headers
        const header_len = readHeaders(&net_reader.interface, request_buf) catch |err| switch (err) {
            error.EndOfStream => return, // Client closed connection
            error.ReadFailed => return, // Timeout or connection reset
        };

        // RFC 2616 Section 14.20: Check for Expect header.
        // If "100-continue", send 100 Continue before reading body.
        // If any other expectation, respond with 417 Expectation Failed.
        const expect_value = extractHeaderValue(request_buf[0..header_len], "expect");
        if (expect_value) |ev| {
            if (Headers.eqlIgnoreCase(ev, "100-continue")) {
                net_writer.interface.writeAll("HTTP/1.1 100 Continue\r\n\r\n") catch return;
                net_writer.interface.flush() catch return;
            } else {
                const resp: Response = .{ .status = .expectation_failed, .body = "Expectation Failed" };
                var resp_buf: [Response.max_response_len]u8 = undefined;
                const resp_data = resp.serialize(&resp_buf) catch return;
                net_writer.interface.writeAll(resp_data) catch return;
                net_writer.interface.flush() catch return;
                return;
            }
        }

        // Read body based on Transfer-Encoding or Content-Length
        var total = header_len;
        const te = extractHeaderValue(request_buf[0..header_len], "transfer-encoding");

        // RFC 2616 Section 3.6: If an unrecognized transfer-coding is
        // received, the server SHOULD return 501 Not Implemented.
        if (te != null and !Headers.eqlIgnoreCase(te.?, "chunked") and
            !Headers.eqlIgnoreCase(te.?, "identity"))
        {
            const resp: Response = .{ .status = .not_implemented, .body = "Unsupported Transfer-Encoding" };
            var resp_buf: [Response.max_response_len]u8 = undefined;
            const resp_data = resp.serialize(&resp_buf) catch return;
            net_writer.interface.writeAll(resp_data) catch return;
            net_writer.interface.flush() catch return;
            return;
        }

        if (te != null and Headers.eqlIgnoreCase(te.?, "chunked")) {
            // RFC 2616 Section 3.6.1: Read chunked body from stream.
            // Read chunk lines until we see the terminating "0\r\n...\r\n"
            total = readChunkedBody(&net_reader.interface, request_buf, total) catch |err| switch (err) {
                error.EndOfStream => total,
                error.ReadFailed => return error.ReadFailed,
            };
        } else {
            const cl = extractContentLength(request_buf[0..header_len]);
            if (cl) |body_len| {
                const to_read = @min(body_len, request_buf.len - total);
                if (to_read > 0) {
                    net_reader.interface.readSliceAll(request_buf[total..][0..to_read]) catch |err| switch (err) {
                        error.EndOfStream => {},
                        error.ReadFailed => return error.ReadFailed,
                    };
                    total += to_read;
                }
            }
        }

        const request_data = request_buf[0..total];

        // Parse the request
        const request = Request.parse(request_data) catch |err| {
            const status: Response.StatusCode = switch (err) {
                error.UnknownMethod => .not_implemented,
                error.InvalidVersion => .http_version_not_supported,
                error.MissingHostHeader => .bad_request,
                error.MultipleHostHeaders => .bad_request,
                error.ConflictingContentLength => .bad_request,
                error.UriPathTraversal => .bad_request,
                error.LineTooLong => .request_uri_too_long,
                error.BodyTooLarge => .request_entity_too_large,
                error.InvalidContentLength => .bad_request,
                else => .bad_request,
            };
            const resp: Response = .{ .status = status, .body = status.reason() };
            var resp_buf: [Response.max_response_len]u8 = undefined;
            const resp_data = resp.serialize(&resp_buf) catch return;
            net_writer.interface.writeAll(resp_data) catch return;
            net_writer.interface.flush() catch return;
            return;
        };

        // RFC 2616 Section 9.9: Handle CONNECT for proxy tunneling.
        if (request.method == .CONNECT and self.config.enable_proxy) {
            self.handleConnect(stream, io, &request, &net_writer) catch return;
            return;
        }

        // Process the request
        const timestamp = Date.now(io);
        var response = Connection.processRequestWithOptions(timestamp, &request, self.handler, io, .{
            .enable_trace = self.config.enable_trace,
        });

        // RFC 2616 Section 14.45: Add Via header for proxied responses.
        if (self.config.enable_proxy) {
            Proxy.addViaHeader(&response, request.version);
        }

        // Serialize and send response
        var resp_buf: [Response.max_response_len]u8 = undefined;
        const resp_data = response.serialize(&resp_buf) catch {
            const err_resp: Response = .{ .status = .internal_server_error, .body = "Internal Server Error" };
            const err_data = err_resp.serialize(&resp_buf) catch return;
            net_writer.interface.writeAll(err_data) catch return;
            net_writer.interface.flush() catch return;
            return;
        };

        net_writer.interface.writeAll(resp_data) catch return;
        net_writer.interface.flush() catch return;

        // RFC 2616 Section 8.1: Check if connection should persist
        if (!Connection.shouldKeepAlive(&request)) {
            return;
        }
    }
}

/// RFC 2616 Section 9.9: Handle CONNECT method for proxy tunneling.
///
/// Establishes a TCP tunnel between the client and the target authority.
/// After sending "200 Connection Established", raw bytes are forwarded
/// bidirectionally until either side closes the connection.
///
/// Note: Bidirectional forwarding uses an alternating read loop. For
/// full-duplex tunneling (e.g., TLS), the async Io backend is recommended.
fn handleConnect(self: *Server, client_stream: Io.net.Stream, io: Io, request: *const Request, client_writer: *Io.net.Stream.Writer) !void {
    const authority = Proxy.parseAuthority(request.uri) orelse {
        const resp: Response = .{ .status = .bad_request, .body = "Invalid CONNECT authority" };
        var resp_buf: [Response.max_response_len]u8 = undefined;
        const resp_data = resp.serialize(&resp_buf) catch return;
        client_writer.interface.writeAll(resp_data) catch return;
        client_writer.interface.flush() catch return;
        return;
    };

    // Proxy access control: check allowed ports
    const proxy_cfg = self.config.proxy;
    if (proxy_cfg.allowed_ports.len > 0) {
        var port_allowed = false;
        for (proxy_cfg.allowed_ports) |p| {
            if (p == authority.port) {
                port_allowed = true;
                break;
            }
        }
        if (!port_allowed) {
            const resp: Response = .{ .status = .forbidden, .body = "Port not allowed" };
            var resp_buf: [Response.max_response_len]u8 = undefined;
            const resp_data = resp.serialize(&resp_buf) catch return;
            client_writer.interface.writeAll(resp_data) catch return;
            client_writer.interface.flush() catch return;
            return;
        }
    }

    // Proxy access control: check allowed hosts
    if (proxy_cfg.allowed_hosts.len > 0) {
        var host_allowed = false;
        for (proxy_cfg.allowed_hosts) |h| {
            if (Headers.eqlIgnoreCase(h, authority.host)) {
                host_allowed = true;
                break;
            }
        }
        if (!host_allowed) {
            const resp: Response = .{ .status = .forbidden, .body = "Host not allowed" };
            var resp_buf: [Response.max_response_len]u8 = undefined;
            const resp_data = resp.serialize(&resp_buf) catch return;
            client_writer.interface.writeAll(resp_data) catch return;
            client_writer.interface.flush() catch return;
            return;
        }
    }

    // Proxy access control: block private/loopback IPs (SSRF protection)
    if (proxy_cfg.block_private_ips) {
        if (isPrivateIp(authority.host)) {
            const resp: Response = .{ .status = .forbidden, .body = "Private IP targets not allowed" };
            var resp_buf: [Response.max_response_len]u8 = undefined;
            const resp_data = resp.serialize(&resp_buf) catch return;
            client_writer.interface.writeAll(resp_data) catch return;
            client_writer.interface.flush() catch return;
            return;
        }
    }

    // Connect to the target server.
    const target_addr = Io.net.IpAddress.parseIp4(authority.host, authority.port) catch {
        const resp: Response = .{ .status = .bad_gateway, .body = "Cannot resolve target" };
        var resp_buf: [Response.max_response_len]u8 = undefined;
        const resp_data = resp.serialize(&resp_buf) catch return;
        client_writer.interface.writeAll(resp_data) catch return;
        client_writer.interface.flush() catch return;
        return;
    };

    const target_stream = Io.net.IpAddress.connect(target_addr, io, .{ .mode = .stream }) catch {
        const resp: Response = .{ .status = .bad_gateway, .body = "Connection to target failed" };
        var resp_buf: [Response.max_response_len]u8 = undefined;
        const resp_data = resp.serialize(&resp_buf) catch return;
        client_writer.interface.writeAll(resp_data) catch return;
        client_writer.interface.flush() catch return;
        return;
    };
    defer target_stream.close(io);

    // Send 200 Connection Established to the client.
    var est_buf: [64]u8 = undefined;
    const est_resp = Proxy.connectionEstablishedResponse(&est_buf) orelse return;
    client_writer.interface.writeAll(est_resp) catch return;
    client_writer.interface.flush() catch return;

    // Set up target reader/writer.
    var target_read_buf: [8192]u8 = undefined;
    var target_write_buf: [8192]u8 = undefined;
    var target_reader = Io.net.Stream.Reader.init(target_stream, io, &target_read_buf);
    var target_writer = Io.net.Stream.Writer.init(target_stream, io, &target_write_buf);

    // Set up client reader for tunnel (reuse existing stream).
    var tunnel_read_buf: [8192]u8 = undefined;
    var tunnel_reader = Io.net.Stream.Reader.init(client_stream, io, &tunnel_read_buf);

    // Bidirectional forwarding loop.
    // Alternates reading from each side and forwarding to the other.
    while (true) {
        // Client -> Target
        const client_data = tunnel_reader.interface.takeDelimiterInclusive(0) catch |err| switch (err) {
            error.StreamTooLong => tunnel_reader.interface.buffered(),
            error.EndOfStream => {
                // Forward any remaining buffered data
                const remaining = tunnel_reader.interface.buffered();
                if (remaining.len > 0) {
                    target_writer.interface.writeAll(remaining) catch break;
                    target_writer.interface.flush() catch break;
                }
                break;
            },
            error.ReadFailed => break,
        };
        if (client_data.len > 0) {
            target_writer.interface.writeAll(client_data) catch break;
            target_writer.interface.flush() catch break;
            tunnel_reader.interface.toss(client_data.len);
        }

        // Target -> Client
        const target_data = target_reader.interface.takeDelimiterInclusive(0) catch |err| switch (err) {
            error.StreamTooLong => target_reader.interface.buffered(),
            error.EndOfStream => {
                const remaining = target_reader.interface.buffered();
                if (remaining.len > 0) {
                    client_writer.interface.writeAll(remaining) catch break;
                    client_writer.interface.flush() catch break;
                }
                break;
            },
            error.ReadFailed => break,
        };
        if (target_data.len > 0) {
            client_writer.interface.writeAll(target_data) catch break;
            client_writer.interface.flush() catch break;
            target_reader.interface.toss(target_data.len);
        }
    }
}

/// Read HTTP headers from the stream, line by line until the blank line
/// terminator (\r\n\r\n). Returns the number of bytes read including
/// the terminator.
fn readHeaders(reader: *Io.Reader, buf: []u8) Io.Reader.Error!usize {
    var total: usize = 0;

    while (total < buf.len) {
        const line = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.StreamTooLong => return total,
            error.EndOfStream => {
                const remaining = reader.buffered();
                if (remaining.len > 0 and total + remaining.len <= buf.len) {
                    @memcpy(buf[total..][0..remaining.len], remaining);
                    total += remaining.len;
                    reader.toss(remaining.len);
                }
                if (total > 0) return total;
                return error.EndOfStream;
            },
            error.ReadFailed => return error.ReadFailed,
        };

        if (total + line.len > buf.len) return total;
        @memcpy(buf[total..][0..line.len], line);
        total += line.len;

        // Check if this was the blank line terminator (just \r\n)
        if (line.len == 2 and line[0] == '\r' and line[1] == '\n') {
            return total;
        }
    }

    return total;
}

/// Read a chunked request body from the stream into the buffer.
/// Reads chunk-size lines and chunk data until the last-chunk (0\r\n)
/// and the trailing CRLF. Returns the total bytes in the buffer
/// (headers + raw chunked body).
///
/// Each chunk-size is validated against the remaining buffer space
/// to prevent a malicious chunk-size from causing excessive reads.
fn readChunkedBody(reader: *Io.Reader, buf: []u8, start: usize) Io.Reader.Error!usize {
    var total = start;

    // Read lines until we find the terminating sequence.
    // The chunked body ends with "0\r\n" followed by optional trailers and "\r\n".
    var found_last_chunk = false;
    while (total < buf.len) {
        const line = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.StreamTooLong => return total,
            error.EndOfStream => return if (total > start) total else error.EndOfStream,
            error.ReadFailed => return error.ReadFailed,
        };

        if (total + line.len > buf.len) return total;
        @memcpy(buf[total..][0..line.len], line);
        total += line.len;

        if (found_last_chunk) {
            // After last-chunk, we're reading trailers. An empty line (\r\n)
            // terminates the chunked body.
            if (line.len == 2 and line[0] == '\r' and line[1] == '\n') {
                return total;
            }
        } else {
            // Check if this line is a chunk-size line
            if (line.len >= 2 and line[line.len - 1] == '\n' and line[line.len - 2] == '\r') {
                const size_part = line[0 .. line.len - 2];
                // Trim any chunk extension after ';'
                const size_str = if (std.mem.indexOfScalar(u8, size_part, ';')) |semi|
                    size_part[0..semi]
                else
                    size_part;
                const trimmed = Request.trimOws(size_str);
                if (trimmed.len > 0 and isAllZeros(trimmed)) {
                    found_last_chunk = true;
                } else if (trimmed.len > 0) {
                    // Validate chunk size against remaining buffer.
                    // Reject chunks that would exceed the buffer to prevent
                    // a malicious chunk-size from causing excessive reads.
                    const chunk_size = std.fmt.parseInt(usize, trimmed, 16) catch {
                        // Invalid hex in chunk-size — stop reading
                        return total;
                    };
                    const remaining = buf.len - total;
                    // Need room for chunk-data + CRLF + at least "0\r\n\r\n"
                    if (chunk_size + 2 > remaining) {
                        return total;
                    }
                }
            }
        }
    }

    return total;
}

fn isAllZeros(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (c != '0') return false;
    }
    return true;
}

/// Find the \r\n\r\n that marks the end of HTTP headers.
fn findHeaderEnd(data: []const u8) ?usize {
    if (data.len < 4) return null;
    var i: usize = 0;
    while (i + 3 < data.len) : (i += 1) {
        if (data[i] == '\r' and data[i + 1] == '\n' and data[i + 2] == '\r' and data[i + 3] == '\n') {
            return i;
        }
    }
    return null;
}

/// Quick extraction of Content-Length from raw header bytes without full parsing.
fn extractContentLength(headers: []const u8) ?usize {
    var pos: usize = 0;
    while (pos < headers.len) {
        const line_end = blk: {
            var j = pos;
            while (j + 1 < headers.len) : (j += 1) {
                if (headers[j] == '\r' and headers[j + 1] == '\n') break :blk j;
            }
            break :blk headers.len;
        };
        const line = headers[pos..line_end];
        pos = if (line_end + 2 <= headers.len) line_end + 2 else headers.len;

        if (line.len > 16 and
            (line[0] == 'C' or line[0] == 'c') and
            (line[7] == '-' or line[7] == '-'))
        {
            const lower = asciiLowerLine(line[0..@min(line.len, 16)]);
            if (std.mem.startsWith(u8, &lower, "content-length:")) {
                const val = Request.trimOws(line[15..]);
                return std.fmt.parseInt(usize, val, 10) catch null;
            }
        }
    }
    return null;
}

/// Extract the value of a named header from raw header bytes (case-insensitive).
fn extractHeaderValue(headers: []const u8, name: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < headers.len) {
        const line_end = blk: {
            var j = pos;
            while (j + 1 < headers.len) : (j += 1) {
                if (headers[j] == '\r' and headers[j + 1] == '\n') break :blk j;
            }
            break :blk headers.len;
        };
        const line = headers[pos..line_end];
        pos = if (line_end + 2 <= headers.len) line_end + 2 else headers.len;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const header_name = line[0..colon];
        if (header_name.len == name.len and Headers.eqlIgnoreCase(header_name, name)) {
            return Request.trimOws(line[colon + 1 ..]);
        }
    }
    return null;
}

/// RFC 2616 Section 8.1.4: Set SO_RCVTIMEO on a socket to enforce
/// idle connection timeouts. When the timeout expires, reads return
/// an error and the connection is closed.
fn setSocketTimeout(handle: Io.net.Socket.Handle, timeout_s: u32) void {
    const timeval = std.posix.timeval{
        .sec = @intCast(timeout_s),
        .usec = 0,
    };
    std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeval)) catch {};
}

fn asciiLowerLine(input: []const u8) [16]u8 {
    var result: [16]u8 = undefined;
    for (input, 0..) |c, i| {
        result[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    for (input.len..16) |i| {
        result[i] = 0;
    }
    return result;
}

/// Check if an IP address string is in a private/loopback range.
/// Blocks: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
/// 169.254.0.0/16 (link-local), 0.0.0.0, and IPv6 loopback (::1).
fn isPrivateIp(host: []const u8) bool {
    // IPv6 loopback
    if (std.mem.eql(u8, host, "::1")) return true;
    if (std.mem.eql(u8, host, "0.0.0.0")) return true;

    // Parse IPv4 octets
    const octets = parseIpv4Octets(host) orelse return false;

    // 127.0.0.0/8
    if (octets[0] == 127) return true;
    // 10.0.0.0/8
    if (octets[0] == 10) return true;
    // 172.16.0.0/12
    if (octets[0] == 172 and octets[1] >= 16 and octets[1] <= 31) return true;
    // 192.168.0.0/16
    if (octets[0] == 192 and octets[1] == 168) return true;
    // 169.254.0.0/16 (link-local)
    if (octets[0] == 169 and octets[1] == 254) return true;

    return false;
}

fn parseIpv4Octets(host: []const u8) ?[4]u8 {
    var octets: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var current: u16 = 0;
    var has_digit = false;

    for (host) |c| {
        if (c == '.') {
            if (!has_digit or octet_idx >= 3) return null;
            if (current > 255) return null;
            octets[octet_idx] = @intCast(current);
            octet_idx += 1;
            current = 0;
            has_digit = false;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
            has_digit = true;
        } else {
            return null;
        }
    }
    if (!has_digit or octet_idx != 3) return null;
    if (current > 255) return null;
    octets[3] = @intCast(current);
    return octets;
}

// --- Tests ---

const testing = std.testing;

// RFC 2616 Section 4: findHeaderEnd locates the blank line (CRLFCRLF)
// that separates headers from body.
test "Server: findHeaderEnd" {
    try testing.expectEqual(@as(?usize, 0), findHeaderEnd("\r\n\r\n"));
    try testing.expectEqual(@as(?usize, 5), findHeaderEnd("hello\r\n\r\n"));
    try testing.expect(findHeaderEnd("hello\r\n") == null);
    try testing.expect(findHeaderEnd("") == null);
    try testing.expect(findHeaderEnd("\r\n") == null);
}

// /// RFC 2616 Section 14.13: extractContentLength from raw headers
test "Server: extractContentLength" {
    const headers = "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\n";
    try testing.expectEqual(@as(?usize, 42), extractContentLength(headers));
}

// /// RFC 2616 Section 14.13: extractContentLength case-insensitive
test "Server: extractContentLength case-insensitive" {
    const headers = "GET / HTTP/1.1\r\nHost: example.com\r\ncontent-length: 100\r\n";
    try testing.expectEqual(@as(?usize, 100), extractContentLength(headers));
}

// /// RFC 2616 Section 14.13: extractContentLength missing
test "Server: extractContentLength missing" {
    const headers = "GET / HTTP/1.1\r\nHost: example.com\r\n";
    try testing.expect(extractContentLength(headers) == null);
}

// /// Server init
test "Server: init" {
    const handler = struct {
        fn handle(_: *const Request, _: Io) Response {
            return Response.init(.ok, "text/plain", "OK");
        }
    }.handle;

    const srv = Server.init(.{}, handler);
    try testing.expectEqual(@as(u16, 8080), srv.config.port);
}

// RFC 2616 Section 8.2.3: extractHeaderValue for Expect header
test "Server: extractHeaderValue" {
    const headers = "GET / HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\n\r\n";
    const val = extractHeaderValue(headers, "expect");
    try testing.expect(val != null);
    try testing.expectEqualStrings("100-continue", val.?);
}

// RFC 2616 Section 8.2.3: extractHeaderValue missing
test "Server: extractHeaderValue missing" {
    const headers = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    try testing.expect(extractHeaderValue(headers, "expect") == null);
}

// isAllZeros utility
test "Server: isAllZeros" {
    try testing.expect(isAllZeros("0"));
    try testing.expect(isAllZeros("000"));
    try testing.expect(!isAllZeros("01"));
    try testing.expect(!isAllZeros("a"));
    try testing.expect(!isAllZeros(""));
}

// /// asciiLowerLine utility
test "Server: asciiLowerLine" {
    const result = asciiLowerLine("Content-Length:");
    try testing.expectEqualStrings("content-length:", result[0..15]);
}

// Private IP detection for proxy SSRF protection
test "Server: isPrivateIp loopback" {
    try testing.expect(isPrivateIp("127.0.0.1"));
    try testing.expect(isPrivateIp("127.255.255.255"));
    try testing.expect(isPrivateIp("::1"));
    try testing.expect(isPrivateIp("0.0.0.0"));
}

test "Server: isPrivateIp private ranges" {
    try testing.expect(isPrivateIp("10.0.0.1"));
    try testing.expect(isPrivateIp("10.255.255.255"));
    try testing.expect(isPrivateIp("172.16.0.1"));
    try testing.expect(isPrivateIp("172.31.255.255"));
    try testing.expect(isPrivateIp("192.168.0.1"));
    try testing.expect(isPrivateIp("192.168.255.255"));
    try testing.expect(isPrivateIp("169.254.1.1"));
}

test "Server: isPrivateIp public IPs" {
    try testing.expect(!isPrivateIp("8.8.8.8"));
    try testing.expect(!isPrivateIp("1.1.1.1"));
    try testing.expect(!isPrivateIp("203.0.113.1"));
    try testing.expect(!isPrivateIp("172.32.0.1"));
    try testing.expect(!isPrivateIp("172.15.255.255"));
}

test "Server: isPrivateIp non-IP hostnames" {
    try testing.expect(!isPrivateIp("example.com"));
    try testing.expect(!isPrivateIp("localhost"));
    try testing.expect(!isPrivateIp(""));
}

test "Server: parseIpv4Octets" {
    const valid = parseIpv4Octets("192.168.1.1").?;
    try testing.expectEqual(@as(u8, 192), valid[0]);
    try testing.expectEqual(@as(u8, 168), valid[1]);
    try testing.expectEqual(@as(u8, 1), valid[2]);
    try testing.expectEqual(@as(u8, 1), valid[3]);

    try testing.expect(parseIpv4Octets("256.0.0.1") == null);
    try testing.expect(parseIpv4Octets("1.2.3") == null);
    try testing.expect(parseIpv4Octets("1.2.3.4.5") == null);
    try testing.expect(parseIpv4Octets("abc") == null);
    try testing.expect(parseIpv4Octets("") == null);
}

// ProxyConfig defaults
test "Server: ProxyConfig defaults" {
    const cfg: ProxyConfig = .{};
    try testing.expect(cfg.block_private_ips);
    try testing.expectEqual(@as(usize, 1), cfg.allowed_ports.len);
    try testing.expectEqual(@as(u16, 443), cfg.allowed_ports[0]);
    try testing.expectEqual(@as(usize, 0), cfg.allowed_hosts.len);
}

// Config defaults
test "Server: Config defaults include trace disabled" {
    const cfg: Config = .{};
    try testing.expect(!cfg.enable_trace);
    try testing.expect(!cfg.enable_proxy);
    try testing.expectEqual(@as(u32, 512), cfg.max_connections);
}

// Connection counter
test "Server: active_connections counter" {
    const handler = struct {
        fn handle(_: *const Request, _: Io) Response {
            return Response.init(.ok, "text/plain", "OK");
        }
    }.handle;
    var srv = Server.init(.{}, handler);
    try testing.expectEqual(@as(u32, 0), srv.active_connections.load(.monotonic));
    _ = srv.active_connections.fetchAdd(1, .monotonic);
    try testing.expectEqual(@as(u32, 1), srv.active_connections.load(.monotonic));
    _ = srv.active_connections.fetchSub(1, .monotonic);
    try testing.expectEqual(@as(u32, 0), srv.active_connections.load(.monotonic));
}

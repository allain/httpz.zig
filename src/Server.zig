const Server = @This();
const std = @import("std");
const Io = std.Io;
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Connection = @import("Connection.zig");
const Headers = @import("Headers.zig");
const Date = @import("Date.zig");

/// RFC 2616 Section 1.4: HTTP/1.1 server implementation.
///
/// This server uses the Zig 0.16 std.Io interface for networking,
/// supporting both threaded and evented I/O backends.

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
};

config: Config,
handler: Connection.Handler,

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

        self.handleConnection(stream, io) catch |err| {
            std.debug.print("Connection error: {}\n", .{err});
        };

        stream.close(io);
    }
}

/// Handle a single TCP connection, potentially with multiple requests
/// (keep-alive).
///
/// RFC 2616 Section 8.1: Persistent Connections
fn handleConnection(self: *Server, stream: Io.net.Stream, io: Io) !void {
    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var net_reader = Io.net.Stream.Reader.init(stream, io, &read_buf);
    var net_writer = Io.net.Stream.Writer.init(stream, io, &write_buf);

    var request_buf: [1_048_576]u8 = undefined;

    while (true) {
        // Read request headers
        const header_len = readHeaders(&net_reader.interface, &request_buf) catch |err| switch (err) {
            error.EndOfStream => return, // Client closed connection
            else => return err,
        };

        // RFC 2616 Section 8.2.3: Check for Expect: 100-continue.
        // If present, send "100 Continue" before reading the body.
        const expect_continue = extractHeaderValue(request_buf[0..header_len], "expect");
        if (expect_continue != null and Headers.eqlIgnoreCase(expect_continue.?, "100-continue")) {
            net_writer.interface.writeAll("HTTP/1.1 100 Continue\r\n\r\n") catch return;
            net_writer.interface.flush() catch return;
        }

        // Read body based on Transfer-Encoding or Content-Length
        var total = header_len;
        const te = extractHeaderValue(request_buf[0..header_len], "transfer-encoding");
        if (te != null and Headers.eqlIgnoreCase(te.?, "chunked")) {
            // RFC 2616 Section 3.6.1: Read chunked body from stream.
            // Read chunk lines until we see the terminating "0\r\n...\r\n"
            total = readChunkedBody(&net_reader.interface, &request_buf, total) catch |err| switch (err) {
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

        // Process the request
        const timestamp = Date.now(io);
        const response = Connection.processRequest(timestamp, &request, self.handler);

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
            // Check if this line is the last-chunk size line ("0\r\n")
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
        fn handle(_: *const Request) Response {
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

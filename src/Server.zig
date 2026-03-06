const Server = @This();
const std = @import("std");
const Io = std.Io;
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Connection = @import("Connection.zig");

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

    var server = try Io.net.IpAddress.listen(addr, io, .{
        .reuse_address = true,
    });
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
        // Read request data
        const request_data = readRequest(&net_reader.interface, &request_buf) catch |err| switch (err) {
            error.EndOfStream => return, // Client closed connection
            else => return err,
        };

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
        const response = Connection.processRequest(&request, self.handler);

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

/// Read a complete HTTP request from the stream.
///
/// Reads data until we find the end-of-headers marker (CRLFCRLF),
/// then reads any remaining body based on Content-Length.
fn readRequest(reader: *Io.Reader, buf: []u8) ![]const u8 {
    var total: usize = 0;

    // Read until we find \r\n\r\n (end of headers)
    while (total < buf.len) {
        const n = reader.readSliceShort(buf[total..@min(total + 4096, buf.len)]) catch |err| {
            if (total > 0) return buf[0..total];
            return err;
        };
        if (n == 0) {
            if (total > 0) return buf[0..total];
            return error.EndOfStream;
        }
        total += n;

        // Check for end of headers
        if (findHeaderEnd(buf[0..total])) |header_end| {
            // Parse Content-Length to know if we need more body data
            const cl = extractContentLength(buf[0..header_end]);
            if (cl) |body_len| {
                const needed = header_end + 4 + body_len; // +4 for \r\n\r\n
                while (total < needed and total < buf.len) {
                    const more = reader.readSliceShort(buf[total..@min(needed, buf.len)]) catch |err| {
                        _ = err;
                        break;
                    };
                    if (more == 0) break;
                    total += more;
                }
            }
            return buf[0..total];
        }
    }

    return buf[0..total];
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

// /// asciiLowerLine utility
test "Server: asciiLowerLine" {
    const result = asciiLowerLine("Content-Length:");
    try testing.expectEqualStrings("content-length:", result[0..15]);
}

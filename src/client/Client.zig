const Client = @This();
const std = @import("std");
const Io = std.Io;
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Headers = @import("../Headers.zig");

/// RFC 2616: HTTP/1.1 Client implementation.
///
/// This client uses the Zig 0.16 std.Io interface for networking,
/// supporting both threaded and evented I/O backends.
pub const Config = struct {
    host: []const u8,
    port: u16 = 80,
    read_buffer_size: usize = 8192,
    write_buffer_size: usize = 8192,
    connection_timeout_s: u32 = 30,
    read_timeout_s: u32 = 60,
};

pub const Url = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,

    pub fn parse(url_str: []const u8) ?Url {
        const scheme_end = std.mem.indexOf(u8, url_str, "://") orelse return null;
        const scheme = url_str[0..scheme_end];
        const after_scheme = url_str[scheme_end + 3 ..];

        const has_scheme = (scheme.len == 4 and std.mem.eql(u8, scheme, "http")) or
            (scheme.len == 5 and std.mem.eql(u8, scheme, "https"));

        const default_port: u16 = if (has_scheme and scheme[scheme.len - 1] == 's') 443 else 80;

        const path_start = std.mem.indexOfScalar(u8, after_scheme, '/') orelse after_scheme.len;
        const host_port = after_scheme[0..path_start];
        const path = if (path_start < after_scheme.len) after_scheme[path_start..] else "/";

        const port_end = std.mem.indexOfScalar(u8, host_port, ':');
        const host = if (port_end) |pe| host_port[0..pe] else host_port;
        const port = if (port_end) |pe|
            std.fmt.parseInt(u16, host_port[pe + 1 ..], 10) catch default_port
        else
            default_port;

        return .{
            .scheme = scheme,
            .host = host,
            .port = port,
            .path = path,
        };
    }
};

const ClientError = error{
    ConnectionFailed,
    SendFailed,
    ResponseTooLarge,
    InvalidResponse,
    ReadTimeout,
};

pub const ResponseParseError = ClientError || error{
    InvalidStatusLine,
    InvalidVersion,
    InvalidStatusCode,
    InvalidHeader,
    MissingContentLength,
    InvalidChunkedEncoding,
};

config: Config,
stream: ?Io.net.Stream = null,
read_buf: []u8,
write_buf: []u8,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, config: Config) Client {
    const buf_size = @max(config.read_buffer_size, config.write_buffer_size);
    const read_buf = allocator.alloc(u8, buf_size) catch unreachable;
    const write_buf = allocator.alloc(u8, buf_size) catch unreachable;
    return .{
        .config = config,
        .read_buf = read_buf,
        .write_buf = write_buf,
        .allocator = allocator,
    };
}

pub fn deinit(self: *Client) void {
    self.close();
    self.allocator.free(self.read_buf);
    self.allocator.free(self.write_buf);
}

pub fn connect(self: *Client, io: Io) ClientError!void {
    self.close();
    const hostname = Io.net.HostName.init(self.config.host) catch {
        return error.ConnectionFailed;
    };
    self.stream = hostname.connect(io, self.config.port, .{ .mode = .stream }) catch {
        return error.ConnectionFailed;
    };
    if (self.config.connection_timeout_s > 0) {
        setSocketTimeout(self.stream.?.socket.handle, self.config.connection_timeout_s);
    }
}

pub fn close(self: *Client) void {
    if (self.stream) |_| {
        self.stream = null;
    }
}

pub fn request(self: *Client, io: Io, method: Request.Method, uri: []const u8, headers: ?Headers, body: ?[]const u8) ResponseParseError!Response {
    const stream = self.stream orelse return error.ConnectionFailed;

    var reader = Io.net.Stream.Reader.init(stream, io, self.read_buf);
    var writer = Io.net.Stream.Writer.init(stream, io, self.write_buf);

    try self.sendRequest(&writer, method, uri, headers, body);
    writer.interface.flush() catch return error.SendFailed;

    return try self.readResponse(&reader.interface);
}

fn sendRequest(self: *Client, writer: *Io.net.Stream.Writer, method: Request.Method, uri: []const u8, headers: ?Headers, body: ?[]const u8) ClientError!void {
    const method_str = method.toBytes();
    writer.interface.writeAll(method_str) catch return error.SendFailed;
    writer.interface.writeAll(" ") catch return error.SendFailed;
    writer.interface.writeAll(uri) catch return error.SendFailed;
    writer.interface.writeAll(" HTTP/1.1\r\n") catch return error.SendFailed;

    var host_written = false;
    if (headers) |h| {
        for (h.entries[0..h.len]) |entry| {
            writer.interface.writeAll(entry.name) catch return error.SendFailed;
            writer.interface.writeAll(": ") catch return error.SendFailed;
            writer.interface.writeAll(entry.value) catch return error.SendFailed;
            writer.interface.writeAll("\r\n") catch return error.SendFailed;
            if (Headers.eqlIgnoreCase(entry.name, "Host")) {
                host_written = true;
            }
        }
    }

    if (!host_written) {
        writer.interface.writeAll("Host: ") catch return error.SendFailed;
        writer.interface.writeAll(self.config.host) catch return error.SendFailed;
        if (self.config.port != 80 and self.config.port != 443) {
            writer.interface.writeAll(":") catch return error.SendFailed;
            var port_buf: [20]u8 = undefined;
            const port_str = formatUsize(self.config.port, &port_buf);
            writer.interface.writeAll(port_str) catch return error.SendFailed;
        }
        writer.interface.writeAll("\r\n") catch return error.SendFailed;
    }

    const has_body = body != null and body.?.len > 0;
    if (has_body) {
        var cl_buf: [20]u8 = undefined;
        const cl_str = formatUsize(body.?.len, &cl_buf);
        writer.interface.writeAll("Content-Length: ") catch return error.SendFailed;
        writer.interface.writeAll(cl_str) catch return error.SendFailed;
        writer.interface.writeAll("\r\n") catch return error.SendFailed;
    }

    writer.interface.writeAll("\r\n") catch return error.SendFailed;

    if (has_body) {
        writer.interface.writeAll(body.?) catch return error.SendFailed;
    }
}

fn readResponse(self: *Client, reader: *Io.Reader) ResponseParseError!Response {
    var response: Response = .{};
    var header_buf: [8192]u8 = undefined;
    var header_pos: usize = 0;

    while (true) {
        const line = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream => {
                if (header_pos == 0) return error.InvalidResponse;
                break;
            },
            error.StreamTooLong => {
                if (header_pos == 0) return error.InvalidResponse;
                break;
            },
            else => return error.InvalidResponse,
        };

        if (header_pos + line.len > header_buf.len) return error.ResponseTooLarge;
        @memcpy(header_buf[header_pos..][0..line.len], line);
        header_pos += line.len;

        if (line.len == 2 and line[0] == '\r' and line[1] == '\n') {
            break;
        }
    }

    const header_str = header_buf[0..header_pos];

    const status_line_end = std.mem.indexOf(u8, header_str, "\r\n") orelse return error.InvalidResponse;
    try parseStatusLine(header_str[0..status_line_end], &response);

    var pos: usize = status_line_end + 2;
    while (pos + 1 < header_str.len) {
        const line_end = blk: {
            var j = pos;
            while (j + 1 < header_str.len) : (j += 1) {
                if (header_str[j] == '\r' and header_str[j + 1] == '\n') break :blk j;
            }
            break :blk header_str.len;
        };
        const line = header_str[pos..line_end];
        pos = if (line_end + 2 <= header_str.len) line_end + 2 else header_str.len;

        if (line.len == 0) break;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeader;
        const name = line[0..colon];
        const value = Request.trimOws(line[colon + 1 ..]);

        response.headers.append(name, value) catch return error.ResponseTooLarge;
    }

    const te = response.headers.get("Transfer-Encoding");
    const is_chunked = te != null and Headers.eqlIgnoreCase(te.?, "chunked");

    if (is_chunked) {
        response.chunked = true;
        response.body = "";
        return response;
    }

    const cl = response.headers.get("Content-Length");
    if (cl) |cl_str| {
        const content_length = std.fmt.parseInt(usize, cl_str, 10) catch
            return error.InvalidResponse;

        if (content_length > 0) {
            const body_buf = self.allocator.alloc(u8, content_length) catch
                return error.ResponseTooLarge;

            reader.readSliceAll(body_buf) catch {
                self.allocator.free(body_buf);
                return error.InvalidResponse;
            };
            response.body = body_buf;
            response._body_allocated = body_buf;
        }
    }

    return response;
}

fn parseStatusLine(data: []const u8, response: *Response) ResponseParseError!void {
    const version_end = std.mem.indexOfScalar(u8, data, ' ') orelse
        return error.InvalidStatusLine;

    const version_str = data[0..version_end];
    if (std.mem.eql(u8, version_str, "HTTP/1.1")) {
        response.version = .http_1_1;
    } else if (std.mem.eql(u8, version_str, "HTTP/1.0")) {
        response.version = .http_1_0;
    } else {
        return error.InvalidVersion;
    }

    const rest = data[version_end + 1 ..];
    const status_end = std.mem.indexOfScalar(u8, rest, ' ') orelse
        return error.InvalidStatusLine;

    const status_str = rest[0..status_end];
    const status_code = std.fmt.parseInt(u16, status_str, 10) catch
        return error.InvalidStatusCode;

    response.status = intToStatusCode(status_code) orelse return error.InvalidStatusCode;
}

fn intToStatusCode(code: u16) ?Response.StatusCode {
    return switch (code) {
        100 => .@"continue",
        101 => .switching_protocols,
        200 => .ok,
        201 => .created,
        202 => .accepted,
        203 => .non_authoritative_information,
        204 => .no_content,
        205 => .reset_content,
        206 => .partial_content,
        300 => .multiple_choices,
        301 => .moved_permanently,
        302 => .found,
        303 => .see_other,
        304 => .not_modified,
        305 => .use_proxy,
        307 => .temporary_redirect,
        400 => .bad_request,
        401 => .unauthorized,
        402 => .payment_required,
        403 => .forbidden,
        404 => .not_found,
        405 => .method_not_allowed,
        406 => .not_acceptable,
        407 => .proxy_authentication_required,
        408 => .request_timeout,
        409 => .conflict,
        410 => .gone,
        411 => .length_required,
        412 => .precondition_failed,
        413 => .request_entity_too_large,
        414 => .request_uri_too_long,
        415 => .unsupported_media_type,
        416 => .requested_range_not_satisfiable,
        417 => .expectation_failed,
        500 => .internal_server_error,
        501 => .not_implemented,
        502 => .bad_gateway,
        503 => .service_unavailable,
        504 => .gateway_timeout,
        505 => .http_version_not_supported,
        else => null,
    };
}

fn formatUsize(value: usize, buf: *[20]u8) []const u8 {
    var v = value;
    var i: usize = 20;
    if (v == 0) {
        buf[19] = '0';
        return buf[19..20];
    }
    while (v > 0) {
        i -= 1;
        buf[i] = @intCast(v % 10 + '0');
        v /= 10;
    }
    return buf[i..20];
}

fn setSocketTimeout(handle: Io.net.Socket.Handle, timeout_s: u32) void {
    const timeval = std.posix.timeval{
        .sec = @intCast(timeout_s),
        .usec = 0,
    };
    std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeval)) catch |err| {
        std.log.warn("setsockopt SO_RCVTIMEO failed: {}", .{err});
    };
}

const testing = std.testing;

test "Client: intToStatusCode" {
    try testing.expectEqual(Response.StatusCode.ok, intToStatusCode(200).?);
    try testing.expectEqual(Response.StatusCode.not_found, intToStatusCode(404).?);
    try testing.expectEqual(Response.StatusCode.internal_server_error, intToStatusCode(500).?);
    try testing.expect(intToStatusCode(999) == null);
}

test "Client: formatUsize" {
    var buf: [20]u8 = undefined;
    try testing.expectEqualStrings("0", formatUsize(0, &buf));
    try testing.expectEqualStrings("42", formatUsize(42, &buf));
    try testing.expectEqualStrings("1000", formatUsize(1000, &buf));
}

test "Client: Url.parse" {
    const url = Url.parse("https://api.iconify.design/mdi/home.svg").?;
    try testing.expectEqualStrings("https", url.scheme);
    try testing.expectEqualStrings("api.iconify.design", url.host);
    try testing.expectEqual(@as(u16, 443), url.port);
    try testing.expectEqualStrings("/mdi/home.svg", url.path);
}

test "Client: Url.parse http with port" {
    const url = Url.parse("http://example.com:8080/path").?;
    try testing.expectEqualStrings("http", url.scheme);
    try testing.expectEqualStrings("example.com", url.host);
    try testing.expectEqual(@as(u16, 8080), url.port);
    try testing.expectEqualStrings("/path", url.path);
}

test "Client: Url.parse no path" {
    const url = Url.parse("http://example.com").?;
    try testing.expectEqualStrings("/", url.path);
}

test "Client: download from httpbin.org" {
    const test_url = Url.parse("http://httpbin.org/html").?;

    var client = Client.init(std.testing.allocator, .{
        .host = test_url.host,
        .port = test_url.port,
        .connection_timeout_s = 10,
        .read_timeout_s = 10,
    });
    defer client.deinit();

    const io = std.testing.io;
    try client.connect(io);

    var resp = try client.request(io, .GET, test_url.path, null, null);
    defer resp.deinit(std.testing.allocator);

    try testing.expectEqual(Response.StatusCode.ok, resp.status);

    const content_type = resp.headers.get("Content-Type");
    try testing.expect(content_type != null);
    try testing.expect(std.mem.indexOf(u8, content_type.?, "text/html") != null);

    try testing.expect(resp.body.len > 0);
}

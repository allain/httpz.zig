const Connection = @This();
const std = @import("std");
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Headers = @import("Headers.zig");

/// RFC 2616 Section 8.1: Persistent Connections
///
/// HTTP/1.1 connections are persistent by default. A connection is closed
/// when either side sends "Connection: close" or after a timeout.
///
/// HTTP/1.0 connections are non-persistent by default unless
/// "Connection: keep-alive" is explicitly specified.

pub const Handler = *const fn (*const Request) Response;

/// RFC 2616 Section 8.1.2: Overall Operation
/// Determine if the connection should be kept alive.
///
/// RFC 2616 Section 8.1.2.1: For HTTP/1.1, persistent connections are the
/// default behavior. The client signals it wants to close with
/// "Connection: close".
///
/// For HTTP/1.0, connections are non-persistent by default. The client
/// must send "Connection: keep-alive" to request persistence.
pub fn shouldKeepAlive(request: *const Request) bool {
    if (request.headers.get("Connection")) |conn| {
        if (Headers.eqlIgnoreCase(conn, "close")) return false;
        if (Headers.eqlIgnoreCase(conn, "keep-alive")) return true;
    }
    return request.version == .http_1_1;
}

/// Process a single request and produce a response.
///
/// This handles the core HTTP/1.1 server-side logic per RFC 2616:
/// - RFC 2616 Section 9.4: HEAD responses must not include a body
/// - RFC 2616 Section 9.8: TRACE echoes the request
/// - RFC 2616 Section 14.13: Content-Length header
/// - RFC 2616 Section 14.18: Date header (MUST be sent by origin servers)
/// - RFC 2616 Section 14.38: Server header
/// - RFC 2616 Section 8.1: Connection header for keep-alive management
pub fn processRequest(request: *const Request, handler: Handler) Response {
    // RFC 2616 Section 9.8: TRACE method echoes the request.
    if (request.method == .TRACE) {
        return handleTrace(request);
    }

    var response = handler(request);

    // RFC 2616 Section 14.18: Origin servers MUST include a Date header.
    if (response.headers.get("Date") == null) {
        response.headers.append("Date", "Thu, 01 Jan 1970 00:00:00 GMT") catch {};
    }

    // RFC 2616 Section 14.38: Server header.
    if (response.headers.get("Server") == null) {
        response.headers.append("Server", "httpz/0.1") catch {};
    }

    // RFC 2616 Section 8.1.2.1: Connection header.
    if (!shouldKeepAlive(request)) {
        response.headers.append("Connection", "close") catch {};
    }

    // RFC 2616 Section 14.13: Content-Length is auto-generated during
    // serialization by Response.serialize() for known body sizes.
    // RFC 2616 Section 4.3: Responses to body-forbidden status codes
    // should not include Content-Length.
    if (isBodyForbidden(response.status)) {
        response.auto_content_length = false;
    }

    return response;
}

/// RFC 2616 Section 9.8: The TRACE method requests that the server
/// echo the received request message back to the client.
///
/// Note: The TRACE echo body is stored in a thread-local buffer so it
/// remains valid until the next TRACE call on the same thread.
fn handleTrace(request: *const Request) Response {
    const S = struct {
        threadlocal var body_buf: [Request.max_request_line_len + Request.max_header_line_len * Headers.max_headers]u8 = undefined;
    };

    var pos: usize = 0;

    // Request-Line
    const method = request.method.toBytes();
    @memcpy(S.body_buf[pos..][0..method.len], method);
    pos += method.len;
    S.body_buf[pos] = ' ';
    pos += 1;
    @memcpy(S.body_buf[pos..][0..request.uri.len], request.uri);
    pos += request.uri.len;
    S.body_buf[pos] = ' ';
    pos += 1;
    const ver = request.version.toBytes();
    @memcpy(S.body_buf[pos..][0..ver.len], ver);
    pos += ver.len;
    @memcpy(S.body_buf[pos..][0..2], "\r\n");
    pos += 2;

    // Headers
    for (request.headers.entries[0..request.headers.len]) |entry| {
        @memcpy(S.body_buf[pos..][0..entry.name.len], entry.name);
        pos += entry.name.len;
        @memcpy(S.body_buf[pos..][0..2], ": ");
        pos += 2;
        @memcpy(S.body_buf[pos..][0..entry.value.len], entry.value);
        pos += entry.value.len;
        @memcpy(S.body_buf[pos..][0..2], "\r\n");
        pos += 2;
    }
    @memcpy(S.body_buf[pos..][0..2], "\r\n");
    pos += 2;

    var response: Response = .{
        .status = .ok,
        .body = S.body_buf[0..pos],
    };
    response.headers.append("Content-Type", "message/http") catch {};

    return response;
}

/// RFC 2616 Section 4.3: Certain responses MUST NOT include a message-body.
/// 1xx, 204, 304 responses.
pub fn isBodyForbidden(status: Response.StatusCode) bool {
    const code = status.toInt();
    return (code >= 100 and code < 200) or code == 204 or code == 304;
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

// --- Tests ---

const testing = std.testing;

fn testHandler(request: *const Request) Response {
    _ = request;
    return Response.init(.ok, "text/plain", "Hello, World!");
}

fn notFoundHandler(request: *const Request) Response {
    _ = request;
    return Response.init(.not_found, "text/plain", "Not Found");
}

// RFC 2616 Section 8.1.2.1: HTTP/1.1 defaults to persistent connections.
// A connection is persistent unless "Connection: close" is sent.
test "Connection: HTTP/1.1 defaults to keep-alive" {
    const req = try Request.parse(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    try testing.expect(shouldKeepAlive(&req));
}

// /// RFC 2616 Section 8.1.2.1: Connection: close signals non-persistent.
test "Connection: HTTP/1.1 with Connection: close" {
    const req = try Request.parse(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );
    try testing.expect(!shouldKeepAlive(&req));
}

// /// RFC 2616 Section 8.1.2.1: HTTP/1.0 defaults to non-persistent.
test "Connection: HTTP/1.0 defaults to close" {
    const req = try Request.parse(
        "GET / HTTP/1.0\r\n" ++
            "\r\n",
    );
    try testing.expect(!shouldKeepAlive(&req));
}

// /// RFC 2616 Section 8.1.2.1: HTTP/1.0 with explicit keep-alive.
test "Connection: HTTP/1.0 with Connection: keep-alive" {
    const req = try Request.parse(
        "GET / HTTP/1.0\r\n" ++
            "Connection: keep-alive\r\n" ++
            "\r\n",
    );
    try testing.expect(shouldKeepAlive(&req));
}

// /// RFC 2616 Section 14.18: Origin servers MUST include a Date header.
test "Connection: processRequest adds Date header" {
    const req = try Request.parse(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequest(&req, testHandler);
    try testing.expect(resp.headers.get("Date") != null);
}

// /// RFC 2616 Section 14.38: Server header identification.
test "Connection: processRequest adds Server header" {
    const req = try Request.parse(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequest(&req, testHandler);
    try testing.expectEqualStrings("httpz/0.1", resp.headers.get("Server").?);
}

// /// RFC 2616 Section 14.13: Content-Length header is added for known bodies.
test "Connection: processRequest adds Content-Length" {
    const req = try Request.parse(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequest(&req, testHandler);
    // Content-Length is auto-generated during serialization, not as a header
    try testing.expect(resp.auto_content_length);
    // Verify it appears in serialized output
    var buf: [1024]u8 = undefined;
    const serialized = try resp.serialize(&buf);
    try testing.expect(std.mem.indexOf(u8, serialized, "Content-Length: 13\r\n") != null);
}

// /// RFC 2616 Section 8.1.2.1: Connection: close is added when client requests it.
test "Connection: processRequest adds Connection: close when requested" {
    const req = try Request.parse(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );
    const resp = processRequest(&req, testHandler);
    try testing.expectEqualStrings("close", resp.headers.get("Connection").?);
}

// /// RFC 2616 Section 9.8: TRACE echoes the received request.
test "Connection: TRACE method echoes request" {
    const req = try Request.parse(
        "TRACE /path HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequest(&req, testHandler);
    try testing.expectEqual(Response.StatusCode.ok, resp.status);
    try testing.expectEqualStrings("message/http", resp.headers.get("Content-Type").?);
    // Body should contain the echoed request
    try testing.expect(resp.body.len > 0);
    // Should start with the request method
    try testing.expect(std.mem.startsWith(u8, resp.body, "TRACE"));
}

// /// RFC 2616 Section 4.3: 1xx, 204, 304 responses MUST NOT include a body.
test "Connection: isBodyForbidden" {
    try testing.expect(isBodyForbidden(.@"continue"));
    try testing.expect(isBodyForbidden(.switching_protocols));
    try testing.expect(isBodyForbidden(.no_content));
    try testing.expect(isBodyForbidden(.not_modified));
    try testing.expect(!isBodyForbidden(.ok));
    try testing.expect(!isBodyForbidden(.not_found));
    try testing.expect(!isBodyForbidden(.internal_server_error));
}

// /// RFC 2616 Section 14.13: No Content-Length for body-forbidden responses.
test "Connection: no Content-Length for 204 No Content" {
    const req = try Request.parse(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: *const Request) Response {
            return .{ .status = .no_content };
        }
    }.handle;
    const resp = processRequest(&req, handler);
    try testing.expect(resp.headers.get("Content-Length") == null);
}

// /// formatUsize utility
test "Connection: formatUsize" {
    var buf: [20]u8 = undefined;
    try testing.expectEqualStrings("0", formatUsize(0, &buf));
    try testing.expectEqualStrings("13", formatUsize(13, &buf));
    try testing.expectEqualStrings("1000", formatUsize(1000, &buf));
    try testing.expectEqualStrings("1048576", formatUsize(1048576, &buf));
}

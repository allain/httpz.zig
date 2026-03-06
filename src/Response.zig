const Response = @This();
const std = @import("std");
const Headers = @import("Headers.zig");

/// RFC 2616 Section 6: Response
///
/// Response = Status-Line
///            *(( general-header | response-header | entity-header ) CRLF)
///            CRLF
///            [ message-body ]

/// RFC 2616 Section 6.1.1: Status Code and Reason Phrase
pub const StatusCode = enum(u16) {
    // 1xx Informational (RFC 2616 Section 10.1)
    @"continue" = 100,
    switching_protocols = 101,

    // 2xx Success (RFC 2616 Section 10.2)
    ok = 200,
    created = 201,
    accepted = 202,
    non_authoritative_information = 203,
    no_content = 204,
    reset_content = 205,
    partial_content = 206,

    // 3xx Redirection (RFC 2616 Section 10.3)
    multiple_choices = 300,
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    not_modified = 304,
    use_proxy = 305,
    temporary_redirect = 307,

    // 4xx Client Error (RFC 2616 Section 10.4)
    bad_request = 400,
    unauthorized = 401,
    payment_required = 402,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    proxy_authentication_required = 407,
    request_timeout = 408,
    conflict = 409,
    gone = 410,
    length_required = 411,
    precondition_failed = 412,
    request_entity_too_large = 413,
    request_uri_too_long = 414,
    unsupported_media_type = 415,
    requested_range_not_satisfiable = 416,
    expectation_failed = 417,

    // 5xx Server Error (RFC 2616 Section 10.5)
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,

    pub fn reason(self: StatusCode) []const u8 {
        return switch (self) {
            .@"continue" => "Continue",
            .switching_protocols => "Switching Protocols",
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .non_authoritative_information => "Non-Authoritative Information",
            .no_content => "No Content",
            .reset_content => "Reset Content",
            .partial_content => "Partial Content",
            .multiple_choices => "Multiple Choices",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .see_other => "See Other",
            .not_modified => "Not Modified",
            .use_proxy => "Use Proxy",
            .temporary_redirect => "Temporary Redirect",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .payment_required => "Payment Required",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .not_acceptable => "Not Acceptable",
            .proxy_authentication_required => "Proxy Authentication Required",
            .request_timeout => "Request Timeout",
            .conflict => "Conflict",
            .gone => "Gone",
            .length_required => "Length Required",
            .precondition_failed => "Precondition Failed",
            .request_entity_too_large => "Request Entity Too Large",
            .request_uri_too_long => "Request-URI Too Long",
            .unsupported_media_type => "Unsupported Media Type",
            .requested_range_not_satisfiable => "Requested Range Not Satisfiable",
            .expectation_failed => "Expectation Failed",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
            .gateway_timeout => "Gateway Timeout",
            .http_version_not_supported => "HTTP Version Not Supported",
        };
    }

    pub fn toInt(self: StatusCode) u16 {
        return @intFromEnum(self);
    }
};

status: StatusCode = .ok,
headers: Headers = .{},
body: []const u8 = "",
version: @import("Request.zig").Version = .http_1_1,
/// When true, serialize() will auto-generate a Content-Length header.
auto_content_length: bool = true,

/// Maximum response size (status line + headers + body separator)
pub const max_response_len = 65536;

pub const SerializeError = error{
    ResponseTooLarge,
};

/// Serialize the response into a buffer.
///
/// RFC 2616 Section 6: The response format is:
///   Status-Line CRLF
///   *(header-field CRLF)
///   CRLF
///   [message-body]
///
/// RFC 2616 Section 6.1:
///   Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
pub fn serialize(self: *const Response, buf: []u8) SerializeError![]const u8 {
    var pos: usize = 0;

    // Status-Line
    pos = appendSlice(buf, pos, self.version.toBytes()) orelse return error.ResponseTooLarge;
    pos = appendSlice(buf, pos, " ") orelse return error.ResponseTooLarge;
    pos = appendInt(buf, pos, self.status.toInt()) orelse return error.ResponseTooLarge;
    pos = appendSlice(buf, pos, " ") orelse return error.ResponseTooLarge;
    pos = appendSlice(buf, pos, self.status.reason()) orelse return error.ResponseTooLarge;
    pos = appendSlice(buf, pos, "\r\n") orelse return error.ResponseTooLarge;

    // Headers
    for (self.headers.entries[0..self.headers.len]) |entry| {
        pos = appendSlice(buf, pos, entry.name) orelse return error.ResponseTooLarge;
        pos = appendSlice(buf, pos, ": ") orelse return error.ResponseTooLarge;
        pos = appendSlice(buf, pos, entry.value) orelse return error.ResponseTooLarge;
        pos = appendSlice(buf, pos, "\r\n") orelse return error.ResponseTooLarge;
    }

    // Auto-generate Content-Length if needed
    if (self.auto_content_length and
        self.headers.get("Content-Length") == null and
        self.headers.get("Transfer-Encoding") == null and
        self.body.len > 0)
    {
        var cl_buf: [20]u8 = undefined;
        const cl_str = formatUsize(self.body.len, &cl_buf);
        pos = appendSlice(buf, pos, "Content-Length: ") orelse return error.ResponseTooLarge;
        pos = appendSlice(buf, pos, cl_str) orelse return error.ResponseTooLarge;
        pos = appendSlice(buf, pos, "\r\n") orelse return error.ResponseTooLarge;
    }

    // End of headers
    pos = appendSlice(buf, pos, "\r\n") orelse return error.ResponseTooLarge;

    // Body
    pos = appendSlice(buf, pos, self.body) orelse return error.ResponseTooLarge;

    return buf[0..pos];
}

fn appendSlice(buf: []u8, pos: usize, data: []const u8) ?usize {
    if (pos + data.len > buf.len) return null;
    @memcpy(buf[pos..][0..data.len], data);
    return pos + data.len;
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

fn appendInt(buf: []u8, pos: usize, value: u16) ?usize {
    var tmp: [5]u8 = undefined;
    const len = formatInt(value, &tmp);
    return appendSlice(buf, pos, tmp[0..len]);
}

fn formatInt(value: u16, buf: *[5]u8) usize {
    var v = value;
    var i: usize = 5;
    if (v == 0) {
        buf[0] = '0';
        return 1;
    }
    while (v > 0) {
        i -= 1;
        buf[i] = @intCast(v % 10 + '0');
        v /= 10;
    }
    const len = 5 - i;
    if (i > 0) {
        std.mem.copyForwards(u8, buf[0..len], buf[i..5]);
    }
    return len;
}

/// Create a simple response with status, content-type, and body.
pub fn init(status: StatusCode, content_type: []const u8, body: []const u8) Response {
    var resp: Response = .{
        .status = status,
        .body = body,
    };
    resp.headers.append("Content-Type", content_type) catch unreachable;
    // We format Content-Length inline in serialize for dynamic responses
    return resp;
}

// --- Tests ---

const testing = std.testing;

// /// RFC 2616 Section 6.1.1: Status codes and reason phrases
test "Response.StatusCode: reason phrases" {
    try testing.expectEqualStrings("OK", StatusCode.ok.reason());
    try testing.expectEqualStrings("Not Found", StatusCode.not_found.reason());
    try testing.expectEqualStrings("Internal Server Error", StatusCode.internal_server_error.reason());
    try testing.expectEqualStrings("Bad Request", StatusCode.bad_request.reason());
    try testing.expectEqualStrings("Continue", StatusCode.@"continue".reason());
    try testing.expectEqualStrings("Method Not Allowed", StatusCode.method_not_allowed.reason());
}

// /// RFC 2616 Section 6.1.1: Status code integer values
test "Response.StatusCode: toInt" {
    try testing.expectEqual(@as(u16, 200), StatusCode.ok.toInt());
    try testing.expectEqual(@as(u16, 404), StatusCode.not_found.toInt());
    try testing.expectEqual(@as(u16, 500), StatusCode.internal_server_error.toInt());
    try testing.expectEqual(@as(u16, 100), StatusCode.@"continue".toInt());
    try testing.expectEqual(@as(u16, 301), StatusCode.moved_permanently.toInt());
}

// /// RFC 2616 Section 6: Serialize a simple 200 OK response
test "Response: serialize simple 200 OK" {
    var resp: Response = .{
        .status = .ok,
    };
    try resp.headers.append("Content-Type", "text/plain");
    resp.body = "Hello";

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Content-Length: 5\r\n" ++
            "\r\n" ++
            "Hello",
        result,
    );
}

// /// RFC 2616 Section 6: Serialize a 404 Not Found response
test "Response: serialize 404 Not Found" {
    var resp: Response = .{
        .status = .not_found,
        .body = "Not Found",
    };
    try resp.headers.append("Content-Type", "text/plain");

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Content-Length: 9\r\n" ++
            "\r\n" ++
            "Not Found",
        result,
    );
}

// /// RFC 2616 Section 6: Serialize response with no body
test "Response: serialize no body" {
    const resp: Response = .{
        .status = .no_content,
    };

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 204 No Content\r\n" ++
            "\r\n",
        result,
    );
}

// /// RFC 2616 Section 6: Serialize response with multiple headers
test "Response: serialize multiple headers" {
    var resp: Response = .{
        .status = .ok,
        .body = "test",
    };
    try resp.headers.append("Content-Type", "text/html");
    try resp.headers.append("X-Custom", "value");
    try resp.headers.append("Cache-Control", "no-cache");

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/html\r\n" ++
            "X-Custom: value\r\n" ++
            "Cache-Control: no-cache\r\n" ++
            "Content-Length: 4\r\n" ++
            "\r\n" ++
            "test",
        result,
    );
}

// /// RFC 2616 Section 6: Buffer too small
test "Response: serialize buffer too small" {
    var resp: Response = .{
        .status = .ok,
    };
    try resp.headers.append("Content-Type", "text/plain");
    resp.body = "Hello";

    var buf: [10]u8 = undefined;
    try testing.expectError(error.ResponseTooLarge, resp.serialize(&buf));
}

// /// RFC 2616 Section 6: HTTP/1.0 response version
test "Response: serialize HTTP/1.0 response" {
    const resp: Response = .{
        .status = .ok,
        .version = .http_1_0,
        .body = "",
    };

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.0 200 OK\r\n" ++
            "\r\n",
        result,
    );
}

// /// RFC 2616 Section 6.1.1: All status code families
test "Response: status codes from all families" {
    const codes: []const StatusCode = &.{
        .@"continue",           .ok,               .moved_permanently,
        .bad_request,           .internal_server_error,
    };
    for (codes) |code| {
        const resp: Response = .{ .status = code };
        var buf: [1024]u8 = undefined;
        _ = try resp.serialize(&buf);
    }
}

// /// RFC 2616 Section 6: init helper
test "Response: init helper" {
    const resp = Response.init(.ok, "text/plain", "Hello");
    try testing.expectEqual(StatusCode.ok, resp.status);
    try testing.expectEqualStrings("Hello", resp.body);
    try testing.expectEqualStrings("text/plain", resp.headers.get("Content-Type").?);
}

// /// formatInt utility
test "Response: formatInt" {
    var buf: [5]u8 = undefined;

    var len = formatInt(0, &buf);
    try testing.expectEqualStrings("0", buf[0..len]);

    len = formatInt(200, &buf);
    try testing.expectEqualStrings("200", buf[0..len]);

    len = formatInt(404, &buf);
    try testing.expectEqualStrings("404", buf[0..len]);

    len = formatInt(65535, &buf);
    try testing.expectEqualStrings("65535", buf[0..len]);
}

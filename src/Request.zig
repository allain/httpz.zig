const Request = @This();
const std = @import("std");
const Headers = @import("Headers.zig");

/// RFC 2616 Section 5: Request
///
/// Request = Request-Line
///           *(( general-header | request-header | entity-header ) CRLF)
///           CRLF
///           [ message-body ]

/// RFC 2616 Section 5.1.1: Method
pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    OPTIONS,
    TRACE,
    CONNECT,
    PATCH,

    pub fn fromString(s: []const u8) ?Method {
        const map = std.StaticStringMap(Method).initComptime(.{
            .{ "GET", .GET },
            .{ "HEAD", .HEAD },
            .{ "POST", .POST },
            .{ "PUT", .PUT },
            .{ "DELETE", .DELETE },
            .{ "OPTIONS", .OPTIONS },
            .{ "TRACE", .TRACE },
            .{ "CONNECT", .CONNECT },
            .{ "PATCH", .PATCH },
        });
        return map.get(s);
    }

    pub fn toBytes(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .HEAD => "HEAD",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .OPTIONS => "OPTIONS",
            .TRACE => "TRACE",
            .CONNECT => "CONNECT",
            .PATCH => "PATCH",
        };
    }
};

/// RFC 2616 Section 3.1: HTTP Version
pub const Version = enum {
    http_1_0,
    http_1_1,

    pub fn toBytes(self: Version) []const u8 {
        return switch (self) {
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
        };
    }
};

method: Method = .GET,
uri: []const u8 = "/",
version: Version = .http_1_1,
headers: Headers = .{},
body: []const u8 = "",

pub const max_request_line_len = 8192;
pub const max_header_line_len = 8192;
pub const max_body_len = 1_048_576; // 1 MiB

pub const ParseError = error{
    /// RFC 2616 Section 5.1: Malformed request line
    InvalidRequestLine,
    /// RFC 2616 Section 5.1.1: Unknown method (501 Not Implemented)
    UnknownMethod,
    /// RFC 2616 Section 3.1: Invalid HTTP version
    InvalidVersion,
    /// RFC 2616 Section 14.23: Missing Host header in HTTP/1.1
    MissingHostHeader,
    /// RFC 2616 Section 4.2: Malformed header line
    InvalidHeader,
    /// RFC 2616 Section 5: Request line or header too long
    LineTooLong,
    /// RFC 2616 Section 4.4: Invalid or missing Content-Length
    InvalidContentLength,
    /// Body exceeds maximum allowed size
    BodyTooLarge,
    /// Unexpected end of input
    UnexpectedEndOfInput,
    /// Too many headers
    TooManyHeaders,
};

/// Parse a complete HTTP/1.1 request from raw bytes.
///
/// RFC 2616 Section 5: The request message format is:
///   Request-Line CRLF
///   *(header-field CRLF)
///   CRLF
///   [message-body]
pub fn parse(data: []const u8) ParseError!Request {
    var request: Request = .{};
    var pos: usize = 0;

    // RFC 2616 Section 4.1: "In the interest of robustness, servers SHOULD
    // ignore any empty line(s) received where a Request-Line is expected."
    while (pos + 1 < data.len and data[pos] == '\r' and data[pos + 1] == '\n') {
        pos += 2;
    }

    // Parse Request-Line: Method SP Request-URI SP HTTP-Version CRLF
    const request_line_end = findCrlf(data, pos) orelse return error.UnexpectedEndOfInput;
    const request_line = data[pos..request_line_end];
    if (request_line.len > max_request_line_len) return error.LineTooLong;

    try parseRequestLine(&request, request_line);
    pos = request_line_end + 2; // skip CRLF

    // Parse headers until empty line (CRLF CRLF)
    var found_end_of_headers = false;
    while (pos + 1 < data.len) {
        // Empty line signals end of headers
        if (data[pos] == '\r' and data[pos + 1] == '\n') {
            pos += 2;
            found_end_of_headers = true;
            break;
        }

        const header_end = findCrlf(data, pos) orelse return error.UnexpectedEndOfInput;
        const header_line = data[pos..header_end];
        if (header_line.len > max_header_line_len) return error.LineTooLong;

        try parseHeaderLine(&request.headers, header_line);
        pos = header_end + 2;
    }

    if (!found_end_of_headers) return error.UnexpectedEndOfInput;

    // RFC 2616 Section 14.23: All HTTP/1.1 requests MUST include a Host header.
    if (request.version == .http_1_1 and request.headers.get("Host") == null) {
        return error.MissingHostHeader;
    }

    // RFC 2616 Section 4.4: Parse message body based on Content-Length or
    // Transfer-Encoding.
    if (request.headers.get("Content-Length")) |cl_str| {
        const content_length = std.fmt.parseInt(usize, trimOws(cl_str), 10) catch
            return error.InvalidContentLength;
        if (content_length > max_body_len) return error.BodyTooLarge;
        if (pos + content_length > data.len) return error.UnexpectedEndOfInput;
        request.body = data[pos..][0..content_length];
    }

    return request;
}

/// RFC 2616 Section 5.1: Request-Line = Method SP Request-URI SP HTTP-Version CRLF
fn parseRequestLine(request: *Request, line: []const u8) ParseError!void {
    // Find first SP
    const method_end = std.mem.indexOfScalar(u8, line, ' ') orelse
        return error.InvalidRequestLine;
    const method_str = line[0..method_end];

    // Find second SP (searching from after method)
    const rest = line[method_end + 1 ..];
    const uri_end = std.mem.indexOfScalar(u8, rest, ' ') orelse
        return error.InvalidRequestLine;

    const uri = rest[0..uri_end];
    const version_str = rest[uri_end + 1 ..];

    // Parse method
    request.method = Method.fromString(method_str) orelse
        return error.UnknownMethod;

    // Parse URI - must not be empty
    if (uri.len == 0) return error.InvalidRequestLine;
    request.uri = uri;

    // RFC 2616 Section 3.1: HTTP-Version = "HTTP" "/" 1*DIGIT "." 1*DIGIT
    request.version = parseVersion(version_str) orelse
        return error.InvalidVersion;
}

fn parseVersion(s: []const u8) ?Version {
    if (std.mem.eql(u8, s, "HTTP/1.1")) return .http_1_1;
    if (std.mem.eql(u8, s, "HTTP/1.0")) return .http_1_0;
    return null;
}

/// RFC 2616 Section 4.2: message-header = field-name ":" [ field-value ]
fn parseHeaderLine(headers: *Headers, line: []const u8) ParseError!void {
    const colon_pos = std.mem.indexOfScalar(u8, line, ':') orelse
        return error.InvalidHeader;

    const name = line[0..colon_pos];
    // RFC 2616 Section 4.2: field-value may be preceded by optional whitespace (OWS)
    const raw_value = line[colon_pos + 1 ..];
    const value = trimOws(raw_value);

    headers.append(name, value) catch |err| switch (err) {
        error.TooManyHeaders => return error.TooManyHeaders,
        error.InvalidHeaderName => return error.InvalidHeader,
        error.InvalidHeaderValue => return error.InvalidHeader,
    };
}

/// Trim optional whitespace (OWS = *(SP / HTAB)) from both ends.
/// RFC 2616 Section 2.2
pub fn trimOws(s: []const u8) []const u8 {
    var start: usize = 0;
    while (start < s.len and (s[start] == ' ' or s[start] == '\t')) : (start += 1) {}
    var end: usize = s.len;
    while (end > start and (s[end - 1] == ' ' or s[end - 1] == '\t')) : (end -= 1) {}
    return s[start..end];
}

fn findCrlf(data: []const u8, start: usize) ?usize {
    var i = start;
    while (i + 1 < data.len) : (i += 1) {
        if (data[i] == '\r' and data[i + 1] == '\n') return i;
    }
    return null;
}

/// Parse chunked transfer-encoding body.
/// RFC 2616 Section 3.6.1:
///   Chunked-Body  = *chunk last-chunk trailer CRLF
///   chunk          = chunk-size [ chunk-extension ] CRLF chunk-data CRLF
///   chunk-size     = 1*HEX
///   last-chunk     = 1*("0") [ chunk-extension ] CRLF
pub fn parseChunkedBody(data: []const u8, out: []u8) ParseError!struct { body_len: usize, consumed: usize } {
    var pos: usize = 0;
    var out_pos: usize = 0;

    while (true) {
        // Read chunk-size line
        const size_line_end = findCrlf(data, pos) orelse return error.UnexpectedEndOfInput;
        const size_line = data[pos..size_line_end];

        // chunk-size may be followed by chunk-extension (;...)
        const size_str = if (std.mem.indexOfScalar(u8, size_line, ';')) |semi|
            size_line[0..semi]
        else
            size_line;

        const chunk_size = std.fmt.parseInt(usize, trimOws(size_str), 16) catch
            return error.InvalidContentLength;

        pos = size_line_end + 2; // skip CRLF after size

        if (chunk_size == 0) {
            // last-chunk: skip trailing headers and final CRLF
            while (pos + 1 < data.len) {
                if (data[pos] == '\r' and data[pos + 1] == '\n') {
                    pos += 2;
                    break;
                }
                // Skip trailer header line
                const trailer_end = findCrlf(data, pos) orelse return error.UnexpectedEndOfInput;
                pos = trailer_end + 2;
            }
            return .{ .body_len = out_pos, .consumed = pos };
        }

        if (out_pos + chunk_size > out.len) return error.BodyTooLarge;
        if (pos + chunk_size + 2 > data.len) return error.UnexpectedEndOfInput;

        @memcpy(out[out_pos..][0..chunk_size], data[pos..][0..chunk_size]);
        out_pos += chunk_size;
        pos += chunk_size;

        // Each chunk-data is followed by CRLF
        if (data[pos] != '\r' or data[pos + 1] != '\n') return error.InvalidRequestLine;
        pos += 2;
    }
}

// --- Tests ---

const testing = std.testing;

// RFC 2616 Section 5.1.1: Method = "OPTIONS" | "GET" | "HEAD" | "POST" |
// "PUT" | "DELETE" | "TRACE" | "CONNECT" | extension-method
test "Request.Method: fromString parses all standard methods" {
    try testing.expectEqual(Method.GET, Method.fromString("GET").?);
    try testing.expectEqual(Method.HEAD, Method.fromString("HEAD").?);
    try testing.expectEqual(Method.POST, Method.fromString("POST").?);
    try testing.expectEqual(Method.PUT, Method.fromString("PUT").?);
    try testing.expectEqual(Method.DELETE, Method.fromString("DELETE").?);
    try testing.expectEqual(Method.OPTIONS, Method.fromString("OPTIONS").?);
    try testing.expectEqual(Method.TRACE, Method.fromString("TRACE").?);
    try testing.expectEqual(Method.CONNECT, Method.fromString("CONNECT").?);
    try testing.expectEqual(Method.PATCH, Method.fromString("PATCH").?);
    try testing.expect(Method.fromString("INVALID") == null);
}

// /// RFC 2616 Section 5.1.1: Method.toBytes roundtrip
test "Request.Method: toBytes roundtrip" {
    inline for (@typeInfo(Method).@"enum".fields) |field| {
        const m: Method = @enumFromInt(field.value);
        try testing.expectEqual(m, Method.fromString(m.toBytes()).?);
    }
}

// /// RFC 2616 Section 3.1: HTTP-Version = "HTTP" "/" 1*DIGIT "." 1*DIGIT
test "Request.Version: parsing and serialization" {
    try testing.expectEqualStrings("HTTP/1.1", Version.http_1_1.toBytes());
    try testing.expectEqualStrings("HTTP/1.0", Version.http_1_0.toBytes());
}

// /// RFC 2616 Section 5: Complete GET request parsing
test "Request: parse simple GET request" {
    const raw =
        "GET /index.html HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Accept: text/html\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expectEqual(Method.GET, req.method);
    try testing.expectEqualStrings("/index.html", req.uri);
    try testing.expectEqual(Version.http_1_1, req.version);
    try testing.expectEqualStrings("example.com", req.headers.get("Host").?);
    try testing.expectEqualStrings("text/html", req.headers.get("Accept").?);
    try testing.expectEqualStrings("", req.body);
}

// /// RFC 2616 Section 5: POST request with body
test "Request: parse POST request with body" {
    const raw =
        "POST /submit HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 11\r\n" ++
        "\r\n" ++
        "hello=world";

    const req = try Request.parse(raw);
    try testing.expectEqual(Method.POST, req.method);
    try testing.expectEqualStrings("/submit", req.uri);
    try testing.expectEqualStrings("hello=world", req.body);
}

// RFC 2616 Section 4.1: "servers SHOULD ignore any empty line(s) received
// where a Request-Line is expected"
test "Request: ignore leading CRLF" {
    const raw =
        "\r\n\r\n" ++
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expectEqual(Method.GET, req.method);
    try testing.expectEqualStrings("/", req.uri);
}

// RFC 2616 Section 14.23: "All HTTP/1.1 requests MUST include exactly one
// Host header field."
test "Request: missing Host header in HTTP/1.1 returns error" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";

    try testing.expectError(error.MissingHostHeader, Request.parse(raw));
}

// /// RFC 2616 Section 14.23: HTTP/1.0 requests don't require Host.
test "Request: HTTP/1.0 without Host is valid" {
    const raw =
        "GET / HTTP/1.0\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expectEqual(Version.http_1_0, req.version);
}

// /// RFC 2616 Section 5.1: Invalid request line
test "Request: invalid request line" {
    try testing.expectError(error.InvalidRequestLine, Request.parse("GET\r\n\r\n"));
    try testing.expectError(error.InvalidRequestLine, Request.parse("GET /\r\n\r\n"));
}

// /// RFC 2616 Section 5.1.1: Unknown method
test "Request: unknown method" {
    const raw =
        "FROBNICATE / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";
    try testing.expectError(error.UnknownMethod, Request.parse(raw));
}

// /// RFC 2616 Section 3.1: Invalid HTTP version
test "Request: invalid version" {
    const raw =
        "GET / HTTP/2.0\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";
    try testing.expectError(error.InvalidVersion, Request.parse(raw));
}

// /// RFC 2616 Section 4.2: Header with optional whitespace around value
test "Request: header value whitespace trimming" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host:   example.com  \r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expectEqualStrings("example.com", req.headers.get("Host").?);
}

// /// RFC 2616 Section 4.2: Malformed header (no colon)
test "Request: malformed header" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host example.com\r\n" ++
        "\r\n";
    try testing.expectError(error.InvalidHeader, Request.parse(raw));
}

// /// RFC 2616 Section 4.4: Invalid Content-Length value
test "Request: invalid content-length" {
    const raw =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: abc\r\n" ++
        "\r\n";
    try testing.expectError(error.InvalidContentLength, Request.parse(raw));
}

// /// RFC 2616 Section 4.4: Content-Length exceeds body data
test "Request: content-length exceeds available data" {
    const raw =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 100\r\n" ++
        "\r\n" ++
        "short";
    try testing.expectError(error.UnexpectedEndOfInput, Request.parse(raw));
}

// /// RFC 2616 Section 5: Unexpected end of input
test "Request: unexpected end of input" {
    try testing.expectError(error.UnexpectedEndOfInput, Request.parse("GET / HTTP/1.1\r\n"));
}

// /// RFC 2616 Section 5.1: Request-URI with query string
test "Request: URI with query string" {
    const raw =
        "GET /search?q=test&page=1 HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expectEqualStrings("/search?q=test&page=1", req.uri);
}

// /// RFC 2616 Section 5.1.2: Request-URI as absolute URI
test "Request: absolute URI" {
    const raw =
        "GET http://example.com/path HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expectEqualStrings("http://example.com/path", req.uri);
}

// /// RFC 2616 Section 5.1.2: Request-URI "*" for OPTIONS
test "Request: OPTIONS with asterisk URI" {
    const raw =
        "OPTIONS * HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expectEqual(Method.OPTIONS, req.method);
    try testing.expectEqualStrings("*", req.uri);
}

// /// RFC 2616 Section 2.2: trimOws utility
test "Request: trimOws" {
    try testing.expectEqualStrings("hello", trimOws("  hello  "));
    try testing.expectEqualStrings("hello", trimOws("\thello\t"));
    try testing.expectEqualStrings("hello", trimOws("hello"));
    try testing.expectEqualStrings("", trimOws("   "));
    try testing.expectEqualStrings("", trimOws(""));
}

// /// RFC 2616 Section 3.6.1: Chunked transfer encoding parsing
test "Request: parseChunkedBody simple" {
    const chunked =
        "5\r\n" ++
        "Hello\r\n" ++
        "6\r\n" ++
        "World!\r\n" ++
        "0\r\n" ++
        "\r\n";

    var out: [64]u8 = undefined;
    const result = try parseChunkedBody(chunked, &out);
    try testing.expectEqualStrings("HelloWorld!", out[0..result.body_len]);
    try testing.expectEqual(chunked.len, result.consumed);
}

// /// RFC 2616 Section 3.6.1: Chunked with extension
test "Request: parseChunkedBody with extension" {
    const chunked =
        "5;ext=val\r\n" ++
        "Hello\r\n" ++
        "0\r\n" ++
        "\r\n";

    var out: [64]u8 = undefined;
    const result = try parseChunkedBody(chunked, &out);
    try testing.expectEqualStrings("Hello", out[0..result.body_len]);
    try testing.expectEqual(chunked.len, result.consumed);
}

// /// RFC 2616 Section 3.6.1: Chunked with trailer headers
test "Request: parseChunkedBody with trailers" {
    const chunked =
        "3\r\n" ++
        "abc\r\n" ++
        "0\r\n" ++
        "Trailer: value\r\n" ++
        "\r\n";

    var out: [64]u8 = undefined;
    const result = try parseChunkedBody(chunked, &out);
    try testing.expectEqualStrings("abc", out[0..result.body_len]);
    try testing.expectEqual(chunked.len, result.consumed);
}

// /// RFC 2616 Section 3.6.1: Chunked with zero-length body
test "Request: parseChunkedBody empty" {
    const chunked = "0\r\n\r\n";

    var out: [64]u8 = undefined;
    const result = try parseChunkedBody(chunked, &out);
    try testing.expectEqual(@as(usize, 0), result.body_len);
}

// /// RFC 2616 Section 5: Multiple headers with various methods
test "Request: HEAD request" {
    const raw =
        "HEAD /resource HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expectEqual(Method.HEAD, req.method);
    try testing.expectEqualStrings("/resource", req.uri);
}

// /// RFC 2616 Section 5: PUT request with body
test "Request: PUT request with body" {
    const raw =
        "PUT /resource HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 13\r\n" ++
        "\r\n" ++
        "Hello, World!";

    const req = try Request.parse(raw);
    try testing.expectEqual(Method.PUT, req.method);
    try testing.expectEqualStrings("Hello, World!", req.body);
}

// /// RFC 2616 Section 5: DELETE request
test "Request: DELETE request" {
    const raw =
        "DELETE /resource/42 HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expectEqual(Method.DELETE, req.method);
    try testing.expectEqualStrings("/resource/42", req.uri);
}

// /// RFC 2616 Section 5.1: Empty URI is invalid
test "Request: empty URI rejected" {
    const raw =
        "GET  HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";
    try testing.expectError(error.InvalidRequestLine, Request.parse(raw));
}

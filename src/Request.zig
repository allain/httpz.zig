const Request = @This();
const std = @import("std");
const Headers = @import("Headers.zig");
const Date = @import("Date.zig");

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

        // RFC 2616 Section 4.2: Header continuation lines start with SP or HTAB.
        // LWS at start of line means this is a continuation of the previous header.
        // We unfold by extending the previous header's value slice to include
        // the continuation (both are slices into the same data buffer).
        if (header_line.len > 0 and (header_line[0] == ' ' or header_line[0] == '\t')) {
            if (request.headers.len > 0) {
                const prev = &request.headers.entries[request.headers.len - 1];
                // Extend the value slice to cover from original start through
                // the end of this continuation line (including the \r\n gap,
                // which is treated as linear whitespace per RFC 2616 §2.2).
                const start = @intFromPtr(prev.value.ptr);
                const end = @intFromPtr(header_line.ptr) + header_line.len;
                prev.value = @as([*]const u8, @ptrFromInt(start))[0 .. end - start];
            }
        } else {
            try parseHeaderLine(&request.headers, header_line);
        }
        pos = header_end + 2;
    }

    if (!found_end_of_headers) return error.UnexpectedEndOfInput;

    // RFC 2616 Section 5.2: If the Request-URI is an absoluteURI, the host
    // is taken from the URI itself. The Host header, if present, is ignored
    // in favor of the URI host. If Host is missing, extract from URI.
    if (request.version == .http_1_1 and request.headers.get("Host") == null) {
        if (!extractHostFromAbsoluteUri(&request)) {
            return error.MissingHostHeader;
        }
    }

    // RFC 2616 Section 4.4: Message Length
    // Rule 3: If Transfer-Encoding is present and is not "identity",
    // it takes precedence over Content-Length.
    const te = request.headers.get("Transfer-Encoding");
    if (te != null and !Headers.eqlIgnoreCase(te.?, "identity")) {
        // Chunked body data starts at pos; store raw data for later decoding.
        // The server is responsible for calling parseChunkedBody on a mutable buffer.
        request.body = data[pos..];
    } else if (request.headers.get("Content-Length")) |cl_str| {
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

/// RFC 2616 Section 14.1: Check if the request accepts a given content type.
/// Checks the `Accept` header for a matching media type.
/// Returns true if the type is accepted or if no Accept header is present
/// (which means all types are acceptable per RFC 2616 §14.1).
pub fn accepts(self: *const Request, content_type: []const u8) bool {
    const accept = self.headers.get("Accept") orelse return true;

    // Check for wildcard
    if (std.mem.indexOf(u8, accept, "*/*") != null) return true;

    // Check for exact match or type/* match
    if (std.mem.indexOf(u8, accept, content_type) != null) return true;

    // Check for type/* match (e.g., "text/*" matches "text/html")
    if (std.mem.indexOfScalar(u8, content_type, '/')) |slash| {
        const type_prefix = content_type[0 .. slash + 1];
        var search_buf: [64]u8 = undefined;
        if (type_prefix.len + 1 <= search_buf.len) {
            @memcpy(search_buf[0..type_prefix.len], type_prefix);
            search_buf[type_prefix.len] = '*';
            if (std.mem.indexOf(u8, accept, search_buf[0 .. type_prefix.len + 1]) != null) return true;
        }
    }

    return false;
}

/// RFC 2616 Section 14.3: Check if the request accepts a given encoding.
/// Checks the `Accept-Encoding` header. Returns true if the encoding
/// is accepted or if no Accept-Encoding header is present.
pub fn acceptsEncoding(self: *const Request, encoding: []const u8) bool {
    const ae = self.headers.get("Accept-Encoding") orelse return true;
    if (std.mem.indexOf(u8, ae, "*") != null) return true;
    return std.mem.indexOf(u8, ae, encoding) != null;
}

/// RFC 2616 Section 5.2: Extract host from an absolute URI and add it
/// as a Host header. Returns true if a host was found and added.
fn extractHostFromAbsoluteUri(request: *Request) bool {
    const uri = request.uri;
    // Look for "://" scheme separator
    const scheme_end = std.mem.indexOf(u8, uri, "://") orelse return false;
    const after_scheme = uri[scheme_end + 3 ..];
    // Host ends at '/' or end of URI
    const host_end = std.mem.indexOfScalar(u8, after_scheme, '/') orelse after_scheme.len;
    const host = after_scheme[0..host_end];
    if (host.len == 0) return false;
    request.headers.append("Host", host) catch return false;
    return true;
}

/// RFC 2616 Section 14.25: Check if the resource has been modified since
/// the date in the `If-Modified-Since` header. Returns true if the
/// resource has NOT been modified (i.e., a 304 should be returned).
pub fn isNotModifiedSince(self: *const Request, resource_timestamp: i64) bool {
    const ims = self.headers.get("If-Modified-Since") orelse return false;
    const ims_timestamp = Date.parseRfc1123(ims) orelse return false;
    return resource_timestamp <= ims_timestamp;
}

/// RFC 2616 Section 14.35: Parse a byte Range header.
/// Format: "bytes=0-499", "bytes=500-999", "bytes=-500", "bytes=500-"
/// Returns the first range as start/end byte positions.
pub const ByteRange = struct {
    start: ?usize,
    end: ?usize,
};

pub fn parseRange(self: *const Request, total_size: usize) ?ByteRange {
    const range_header = self.headers.get("Range") orelse return null;
    const trimmed = trimOws(range_header);

    // Must start with "bytes="
    if (!std.mem.startsWith(u8, trimmed, "bytes=")) return null;
    const spec = trimmed[6..];

    // Only handle the first range (no multi-range support)
    const range_end = std.mem.indexOfScalar(u8, spec, ',') orelse spec.len;
    const range_str = spec[0..range_end];

    const dash = std.mem.indexOfScalar(u8, range_str, '-') orelse return null;

    if (dash == 0) {
        // Suffix range: "-500" means last 500 bytes
        const suffix_len = std.fmt.parseInt(usize, range_str[1..], 10) catch return null;
        if (suffix_len == 0 or suffix_len > total_size) return null;
        return .{ .start = total_size - suffix_len, .end = total_size - 1 };
    }

    const start = std.fmt.parseInt(usize, range_str[0..dash], 10) catch return null;
    if (start >= total_size) return null;

    if (dash + 1 >= range_str.len) {
        // Open-ended range: "500-"
        return .{ .start = start, .end = total_size - 1 };
    }

    const end = std.fmt.parseInt(usize, range_str[dash + 1 ..], 10) catch return null;
    if (end < start) return null;
    return .{ .start = start, .end = @min(end, total_size - 1) };
}

/// RFC 2616 Section 14.26: Check If-None-Match against an ETag.
/// Returns true if the request ETag matches (resource not modified).
pub fn matchesEtag(self: *const Request, etag: []const u8) bool {
    const inm = self.headers.get("If-None-Match") orelse return false;
    // Wildcard match
    if (std.mem.eql(u8, trimOws(inm), "*")) return true;
    // Simple comparison (doesn't handle comma-separated lists)
    return std.mem.eql(u8, trimOws(inm), etag);
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

// RFC 2616 Section 4.4: Transfer-Encoding takes precedence over Content-Length
test "Request: Transfer-Encoding precedence over Content-Length" {
    const raw =
        "POST /upload HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "Content-Length: 999\r\n" ++
        "\r\n" ++
        "5\r\nHello\r\n0\r\n\r\n";

    const req = try Request.parse(raw);
    // Body should contain the raw chunked data, not 999 bytes
    try testing.expect(req.body.len > 0);
    try testing.expect(req.body.len < 999);
}

// RFC 2616 Section 4.4: Transfer-Encoding "identity" defers to Content-Length
test "Request: Transfer-Encoding identity uses Content-Length" {
    const raw =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: identity\r\n" ++
        "Content-Length: 5\r\n" ++
        "\r\n" ++
        "Hello";

    const req = try Request.parse(raw);
    try testing.expectEqualStrings("Hello", req.body);
}

// RFC 2616 Section 4.2: Header continuation lines (LWS folding)
test "Request: header continuation line" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "X-Long-Header: value1\r\n" ++
        " continued-value\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    const val = req.headers.get("X-Long-Header").?;
    // The folded value should contain both parts
    try testing.expect(std.mem.indexOf(u8, val, "value1") != null);
    try testing.expect(std.mem.indexOf(u8, val, "continued-value") != null);
}

// RFC 2616 Section 4.2: Tab-prefixed continuation line
test "Request: header continuation with tab" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "X-Header: first\r\n" ++
        "\tsecond\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    const val = req.headers.get("X-Header").?;
    try testing.expect(std.mem.indexOf(u8, val, "first") != null);
    try testing.expect(std.mem.indexOf(u8, val, "second") != null);
}

// RFC 2616 Section 14.25: If-Modified-Since - not modified
test "Request: isNotModifiedSince returns true when not modified" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    // Resource modified at epoch (same time) - not modified
    try testing.expect(req.isNotModifiedSince(0));
    // Resource modified before the date - not modified
    try testing.expect(req.isNotModifiedSince(-1));
}

// RFC 2616 Section 14.25: If-Modified-Since - modified
test "Request: isNotModifiedSince returns false when modified" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    // Resource modified after the date - modified
    try testing.expect(!req.isNotModifiedSince(1));
}

// RFC 2616 Section 14.25: No If-Modified-Since header
test "Request: isNotModifiedSince returns false when header absent" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expect(!req.isNotModifiedSince(0));
}

// RFC 2616 Section 14.26: If-None-Match ETag comparison
test "Request: matchesEtag" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "If-None-Match: \"abc123\"\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expect(req.matchesEtag("\"abc123\""));
    try testing.expect(!req.matchesEtag("\"def456\""));
}

// RFC 2616 Section 14.26: If-None-Match wildcard
test "Request: matchesEtag wildcard" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "If-None-Match: *\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expect(req.matchesEtag("\"anything\""));
}

// RFC 2616 Section 14.1: Accept header - exact match
test "Request: accepts content type" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Accept: text/html, application/json\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expect(req.accepts("text/html"));
    try testing.expect(req.accepts("application/json"));
    try testing.expect(!req.accepts("image/png"));
}

// RFC 2616 Section 14.1: Accept header - wildcard
test "Request: accepts wildcard" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expect(req.accepts("text/html"));
    try testing.expect(req.accepts("application/json"));
}

// RFC 2616 Section 14.1: Accept header - type wildcard
test "Request: accepts type wildcard" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Accept: text/*\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expect(req.accepts("text/html"));
    try testing.expect(req.accepts("text/plain"));
    try testing.expect(!req.accepts("application/json"));
}

// RFC 2616 Section 14.1: No Accept header means all types accepted
test "Request: accepts without header" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expect(req.accepts("anything/at-all"));
}

// RFC 2616 Section 14.3: Accept-Encoding
test "Request: acceptsEncoding" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Accept-Encoding: gzip, deflate\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expect(req.acceptsEncoding("gzip"));
    try testing.expect(req.acceptsEncoding("deflate"));
    try testing.expect(!req.acceptsEncoding("br"));
}

// RFC 2616 Section 14.35: Range header parsing - simple range
test "Request: parseRange simple" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=0-499\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    const range = req.parseRange(1000).?;
    try testing.expectEqual(@as(usize, 0), range.start.?);
    try testing.expectEqual(@as(usize, 499), range.end.?);
}

// RFC 2616 Section 14.35: Range header - suffix range
test "Request: parseRange suffix" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=-500\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    const range = req.parseRange(1000).?;
    try testing.expectEqual(@as(usize, 500), range.start.?);
    try testing.expectEqual(@as(usize, 999), range.end.?);
}

// RFC 2616 Section 14.35: Range header - open-ended
test "Request: parseRange open-ended" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=500-\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    const range = req.parseRange(1000).?;
    try testing.expectEqual(@as(usize, 500), range.start.?);
    try testing.expectEqual(@as(usize, 999), range.end.?);
}

// RFC 2616 Section 14.35: Range header - no Range header
test "Request: parseRange no header" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expect(req.parseRange(1000) == null);
}

// RFC 2616 Section 14.35: Range header - start beyond size
test "Request: parseRange out of bounds" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=2000-3000\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expect(req.parseRange(1000) == null);
}

// RFC 2616 Section 14.35: Range header - end clamped to size
test "Request: parseRange end clamped" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=500-5000\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    const range = req.parseRange(1000).?;
    try testing.expectEqual(@as(usize, 500), range.start.?);
    try testing.expectEqual(@as(usize, 999), range.end.?);
}

// RFC 2616 Section 5.2: Absolute URI provides Host when header is missing
test "Request: absolute URI provides Host header" {
    const raw =
        "GET http://example.com/path HTTP/1.1\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expectEqualStrings("example.com", req.headers.get("Host").?);
}

// RFC 2616 Section 5.2: Absolute URI with port
test "Request: absolute URI with port provides Host" {
    const raw =
        "GET http://example.com:8080/path HTTP/1.1\r\n" ++
        "\r\n";

    const req = try Request.parse(raw);
    try testing.expectEqualStrings("example.com:8080", req.headers.get("Host").?);
}

// /// RFC 2616 Section 5.1: Empty URI is invalid
test "Request: empty URI rejected" {
    const raw =
        "GET  HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";
    try testing.expectError(error.InvalidRequestLine, Request.parse(raw));
}

const Headers = @This();
const std = @import("std");

/// RFC 2616 Section 4.2: HTTP headers are case-insensitive field names
/// with associated values. Multiple headers with the same name are
/// combined with comma separation.

pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};

entries: [max_headers]Entry = undefined,
len: usize = 0,

pub const max_headers = 64;
pub const max_name_len = 256;
pub const max_value_len = 8192;

pub const Error = error{
    TooManyHeaders,
    InvalidHeaderName,
    InvalidHeaderValue,
};

/// RFC 2616 Section 4.2: Add a header field.
pub fn append(self: *Headers, name: []const u8, value: []const u8) Error!void {
    if (self.len >= max_headers) return error.TooManyHeaders;
    if (name.len == 0 or name.len > max_name_len) return error.InvalidHeaderName;
    if (!isValidToken(name)) return error.InvalidHeaderName;
    if (value.len > max_value_len) return error.InvalidHeaderValue;

    self.entries[self.len] = .{ .name = name, .value = value };
    self.len += 1;
}

/// RFC 2616 Section 4.2: Header field names are case-insensitive.
pub fn get(self: *const Headers, name: []const u8) ?[]const u8 {
    for (self.entries[0..self.len]) |entry| {
        if (eqlIgnoreCase(entry.name, name)) return entry.value;
    }
    return null;
}

/// Get all values for a given header name.
pub fn getAll(self: *const Headers, name: []const u8, buf: [][]const u8) usize {
    var count: usize = 0;
    for (self.entries[0..self.len]) |entry| {
        if (eqlIgnoreCase(entry.name, name)) {
            if (count < buf.len) {
                buf[count] = entry.value;
            }
            count += 1;
        }
    }
    return count;
}

/// RFC 2616 Section 2.2: Check if a string is a valid HTTP token.
/// token = 1*<any CHAR except CTLs or separators>
pub fn isValidToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!isTokenChar(c)) return false;
    }
    return true;
}

/// RFC 2616 Section 2.2: Token characters.
/// separators = "(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\" | <">
///            | "/" | "[" | "]" | "?" | "=" | "{" | "}" | SP | HT
fn isTokenChar(c: u8) bool {
    // Must be a CHAR (0-127), not a CTL (0-31, 127), and not a separator
    if (c <= 31 or c == 127) return false;
    return switch (c) {
        '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}', ' ', '\t' => false,
        else => c <= 126,
    };
}

/// Case-insensitive comparison for ASCII strings.
/// RFC 2616 Section 4.2: Field names are case-insensitive.
pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (toLower(ca) != toLower(cb)) return false;
    }
    return true;
}

fn toLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

// --- Tests ---

const testing = std.testing;

// /// RFC 2616 Section 4.2: Message headers consist of field-name ":" field-value
test "Headers: basic append and get" {
    var h: Headers = .{};
    try h.append("Content-Type", "text/html");
    try h.append("Content-Length", "42");

    try testing.expectEqualStrings("text/html", h.get("Content-Type").?);
    try testing.expectEqualStrings("42", h.get("Content-Length").?);
    try testing.expect(h.get("X-Missing") == null);
}

// /// RFC 2616 Section 4.2: Field names are case-insensitive.
test "Headers: case-insensitive lookup" {
    var h: Headers = .{};
    try h.append("Content-Type", "text/html");

    try testing.expectEqualStrings("text/html", h.get("content-type").?);
    try testing.expectEqualStrings("text/html", h.get("CONTENT-TYPE").?);
    try testing.expectEqualStrings("text/html", h.get("Content-type").?);
}

// RFC 2616 Section 4.2: Multiple message-header fields with the same field-name
// MAY be present in a message.
test "Headers: multiple values for same name" {
    var h: Headers = .{};
    try h.append("Set-Cookie", "a=1");
    try h.append("Set-Cookie", "b=2");

    var buf: [4][]const u8 = undefined;
    const count = h.getAll("Set-Cookie", &buf);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings("a=1", buf[0]);
    try testing.expectEqualStrings("b=2", buf[1]);
}

// /// RFC 2616 Section 4.2: get returns the first matching header.
test "Headers: get returns first match" {
    var h: Headers = .{};
    try h.append("X-Custom", "first");
    try h.append("X-Custom", "second");

    try testing.expectEqualStrings("first", h.get("X-Custom").?);
}

// /// RFC 2616 Section 4.2: Too many headers should be rejected.
test "Headers: too many headers" {
    var h: Headers = .{};
    for (0..max_headers) |i| {
        _ = i;
        try h.append("X-Header", "value");
    }
    try testing.expectError(error.TooManyHeaders, h.append("X-Extra", "value"));
}

// /// RFC 2616 Section 2.2: Token validation - field names must be valid tokens.
test "Headers: invalid header name rejected" {
    var h: Headers = .{};
    try testing.expectError(error.InvalidHeaderName, h.append("", "value"));
    try testing.expectError(error.InvalidHeaderName, h.append("Bad Header", "value"));
    try testing.expectError(error.InvalidHeaderName, h.append("Bad:Header", "value"));
    try testing.expectError(error.InvalidHeaderName, h.append("Bad\x00Header", "value"));
}

// /// RFC 2616 Section 2.2: Token character validation.
test "Headers: token validation" {
    try testing.expect(isValidToken("Content-Type"));
    try testing.expect(isValidToken("X-Custom-Header"));
    try testing.expect(!isValidToken("Bad Header"));
    try testing.expect(!isValidToken("Bad\tHeader"));
    try testing.expect(!isValidToken(""));
    // Separators
    try testing.expect(!isValidToken("a(b"));
    try testing.expect(!isValidToken("a@b"));
    try testing.expect(!isValidToken("a[b"));
}

// /// RFC 2616 Section 4.2: Case-insensitive comparison utility.
test "Headers: eqlIgnoreCase" {
    try testing.expect(eqlIgnoreCase("abc", "ABC"));
    try testing.expect(eqlIgnoreCase("Content-Type", "content-type"));
    try testing.expect(!eqlIgnoreCase("abc", "abcd"));
    try testing.expect(!eqlIgnoreCase("abc", "abd"));
}

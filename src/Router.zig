const Router = @This();
const std = @import("std");
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Connection = @import("server/Connection.zig");
const WebSocket = @import("server/WebSocket.zig");

pub const Handler = Connection.Handler;

/// Re-export Params from Request for backwards compatibility.
pub const Params = Request.Params;

/// A single route definition.
pub const Route = struct {
    method: Request.Method,
    path: []const u8,
    handler: Handler,
    ws: ?struct { handler: WebSocket.Handler } = null,
};

/// Build a Connection.Handler from a comptime route table.
/// Dispatches requests by matching method and path, extracting parameters.
pub fn handler(comptime routes: []const Route) Connection.Handler {
    return handlerWithFallback(routes, defaultNotFound);
}

/// Build a Connection.Handler with a custom fallback for unmatched routes.
pub fn handlerWithFallback(comptime routes: []const Route, comptime not_found: Handler) Connection.Handler {
    return struct {
        fn dispatch(allocator: std.mem.Allocator, io: std.Io, request: *const Request) Response {
            const path = extractPath(request.uri);

            inline for (routes) |route| {
                if (request.method == route.method) {
                    if (matchPath(route.path, path)) |params| {
                        var mutable_req = request.*;
                        mutable_req.params = params;
                        var response = route.handler(allocator, io, &mutable_req);
                        if (route.ws) |ws| {
                            response.ws_handler = ws.handler;
                        }
                        return response;
                    }
                }
            }

            return not_found(allocator, io, request);
        }
    }.dispatch;
}

fn defaultNotFound(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
    return Response.init(.not_found, "text/plain", "Not Found");
}

/// Extract the path component from a URI, stripping query string and fragment.
pub fn extractPath(uri: []const u8) []const u8 {
    var end = uri.len;
    for (uri, 0..) |c, i| {
        if (c == '?' or c == '#') {
            end = i;
            break;
        }
    }
    return uri[0..end];
}

/// Match a comptime path pattern against a runtime path, extracting parameters.
/// Pattern segments starting with ':' are path parameters.
pub fn matchPath(comptime pattern: []const u8, path: []const u8) ?Params {
    const segments = comptime splitSegments(pattern);
    var params: Params = .{};
    var rest = stripLeadingSlash(path);

    inline for (segments, 0..) |seg, i| {
        if (seg[0] == ':') {
            // Parameter segment — extract value
            const slash_pos = std.mem.indexOfScalar(u8, rest, '/');
            const value = if (slash_pos) |pos| rest[0..pos] else rest;
            if (value.len == 0) return null; // parameter must not be empty
            params.entries[params.len] = .{
                .name = seg[1..],
                .value = value,
            };
            params.len += 1;
            rest = if (slash_pos) |pos| rest[pos + 1 ..] else "";
        } else {
            // Literal segment — must match exactly
            if (rest.len < seg.len) return null;
            if (!std.mem.eql(u8, rest[0..seg.len], seg)) return null;
            const after = rest[seg.len..];
            if (after.len == 0) {
                rest = "";
            } else if (after[0] == '/') {
                rest = after[1..];
            } else {
                return null;
            }
        }

        // If this is the last segment, rest must be empty (trailing slash tolerance)
        if (i == segments.len - 1) {
            if (rest.len != 0) return null;
        }
    }

    // Handle root path pattern
    if (segments.len == 0) {
        if (rest.len != 0) return null;
    }

    return params;
}

fn stripLeadingSlash(path: []const u8) []const u8 {
    if (path.len > 0 and path[0] == '/') {
        // Also strip trailing slash for matching
        const trimmed = path[1..];
        if (trimmed.len > 0 and trimmed[trimmed.len - 1] == '/') {
            return trimmed[0 .. trimmed.len - 1];
        }
        return trimmed;
    }
    return path;
}

/// Split a pattern like "/users/:id/posts" into ["users", ":id", "posts"] at comptime.
fn splitSegments(comptime pattern: []const u8) []const []const u8 {
    comptime {
        var count: usize = 0;
        var rest: []const u8 = pattern;
        // Strip leading slash
        if (rest.len > 0 and rest[0] == '/') rest = rest[1..];
        // Strip trailing slash
        if (rest.len > 0 and rest[rest.len - 1] == '/') rest = rest[0 .. rest.len - 1];
        if (rest.len == 0) return &.{};

        // Count segments
        var tmp = rest;
        while (true) {
            count += 1;
            if (std.mem.indexOfScalar(u8, tmp, '/')) |pos| {
                tmp = tmp[pos + 1 ..];
            } else break;
        }

        // Extract segments
        var segments: [count][]const u8 = undefined;
        var i: usize = 0;
        var src = rest;
        while (true) {
            if (std.mem.indexOfScalar(u8, src, '/')) |pos| {
                segments[i] = src[0..pos];
                src = src[pos + 1 ..];
                i += 1;
            } else {
                segments[i] = src;
                break;
            }
        }

        return &segments;
    }
}

// --- Tests ---

const testing = std.testing;

test "Router: extractPath strips query string" {
    try testing.expectEqualStrings("/users", extractPath("/users?page=1"));
    try testing.expectEqualStrings("/users", extractPath("/users#section"));
    try testing.expectEqualStrings("/users", extractPath("/users?page=1#section"));
    try testing.expectEqualStrings("/users/42", extractPath("/users/42"));
    try testing.expectEqualStrings("/", extractPath("/"));
    try testing.expectEqualStrings("", extractPath(""));
}

test "Router: matchPath exact match" {
    const result = matchPath("/", "/");
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 0), result.?.len);
}

test "Router: matchPath single segment" {
    const result = matchPath("/users", "/users");
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 0), result.?.len);
}

test "Router: matchPath no match" {
    try testing.expect(matchPath("/users", "/posts") == null);
    try testing.expect(matchPath("/users", "/") == null);
    try testing.expect(matchPath("/", "/users") == null);
}

test "Router: matchPath single param" {
    const result = matchPath("/users/:id", "/users/42");
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 1), result.?.len);
    try testing.expectEqualStrings("id", result.?.entries[0].name);
    try testing.expectEqualStrings("42", result.?.entries[0].value);
}

test "Router: matchPath multiple params" {
    const result = matchPath("/users/:id/posts/:post_id", "/users/42/posts/7");
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 2), result.?.len);
    try testing.expectEqualStrings("id", result.?.entries[0].name);
    try testing.expectEqualStrings("42", result.?.entries[0].value);
    try testing.expectEqualStrings("post_id", result.?.entries[1].name);
    try testing.expectEqualStrings("7", result.?.entries[1].value);
}

test "Router: matchPath trailing slash tolerance" {
    const result = matchPath("/users/:id", "/users/42/");
    try testing.expect(result != null);
    try testing.expectEqualStrings("42", result.?.entries[0].value);

    const result2 = matchPath("/users", "/users/");
    try testing.expect(result2 != null);
}

test "Router: matchPath empty param rejected" {
    try testing.expect(matchPath("/users/:id", "/users/") == null);
}

test "Router: matchPath extra segments rejected" {
    try testing.expect(matchPath("/users/:id", "/users/42/extra") == null);
}

test "Router: Params.get" {
    var params: Params = .{};
    params.entries[0] = .{ .name = "id", .value = "42" };
    params.entries[1] = .{ .name = "name", .value = "alice" };
    params.len = 2;

    try testing.expectEqualStrings("42", params.get("id").?);
    try testing.expectEqualStrings("alice", params.get("name").?);
    try testing.expect(params.get("missing") == null);
}

test "Router: dispatch selects correct handler" {
    const routes = [_]Route{
        .{ .method = .GET, .path = "/", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "home");
            }
        }.h },
        .{ .method = .GET, .path = "/users/:id", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
                return Response.init(.ok, "text/plain", request.params.get("id") orelse "none");
            }
        }.h },
        .{ .method = .POST, .path = "/users", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.created, "text/plain", "created");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    // GET /
    const req1 = try Request.parseConst("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp1 = dispatch(std.testing.allocator, test_io, &req1);
    try testing.expectEqualStrings("home", resp1.body);

    // GET /users/42
    const req2 = try Request.parseConst("GET /users/42 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp2 = dispatch(std.testing.allocator, test_io, &req2);
    try testing.expectEqualStrings("42", resp2.body);

    // POST /users
    const req3 = try Request.parseConst("POST /users HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp3 = dispatch(std.testing.allocator, test_io, &req3);
    try testing.expectEqual(Response.StatusCode.created, resp3.status);

    // GET /nonexistent → 404
    const req4 = try Request.parseConst("GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp4 = dispatch(std.testing.allocator, test_io, &req4);
    try testing.expectEqual(Response.StatusCode.not_found, resp4.status);
}

test "Router: custom 404 fallback" {
    const routes = [_]Route{
        .{ .method = .GET, .path = "/", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "home");
            }
        }.h },
    };

    const custom_404 = struct {
        fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return Response.init(.not_found, "text/html", "<h1>Custom 404</h1>");
        }
    }.h;

    const dispatch = handlerWithFallback(&routes, custom_404);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqualStrings("<h1>Custom 404</h1>", resp.body);
}

test "Router: dispatch with query string" {
    const routes = [_]Route{
        .{ .method = .GET, .path = "/search", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "search");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("GET /search?q=test HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqualStrings("search", resp.body);
}

test "Router: ws_handler is set on response" {
    const ws_fn = struct {
        fn h(_: *WebSocket.Conn, _: *const Request) void {}
    }.h;

    const routes = [_]Route{
        .{ .method = .GET, .path = "/ws", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
                return WebSocket.upgradeResponse(request) orelse
                    Response.init(.bad_request, "text/plain", "upgrade failed");
            }
        }.h, .ws = .{ .handler = ws_fn } },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst(
        "GET /ws HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqual(Response.StatusCode.switching_protocols, resp.status);
    try testing.expect(resp.ws_handler != null);
}

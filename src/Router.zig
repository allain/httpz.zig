const Router = @This();
const std = @import("std");
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Connection = @import("server/Connection.zig");
const WebSocket = @import("server/WebSocket.zig");

// Pattern syntax supported by `matchPath`:
//   literal    — matches one path segment exactly (`/users`)
//   :name      — matches a single path segment and captures it as `name`
//   *name      — catch-all: must be the last segment; matches the rest of the
//                path (possibly empty) and captures it as `name`. Requires the
//                prefix to be followed by `/` in the request path, i.e.
//                `/foo/*rest` matches `/foo/` and `/foo/bar/baz` but not `/foo`.

pub const Handler = Connection.Handler;

/// Re-export Params from Request for backwards compatibility.
pub const Params = Request.Params;

/// Method selector for a route. Mirrors `Request.Method` and adds `ALL`, a
/// wildcard that matches every verb — use it for prefix routes that should
/// accept any method (e.g. a proxy).
pub const Method = enum {
    ALL,
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    OPTIONS,
    TRACE,
    CONNECT,
    PATCH,

    /// True when this route method should accept the given HTTP method.
    pub fn matches(self: Method, request_method: Request.Method) bool {
        return switch (self) {
            .ALL => true,
            .GET => request_method == .GET,
            .HEAD => request_method == .HEAD,
            .POST => request_method == .POST,
            .PUT => request_method == .PUT,
            .DELETE => request_method == .DELETE,
            .OPTIONS => request_method == .OPTIONS,
            .TRACE => request_method == .TRACE,
            .CONNECT => request_method == .CONNECT,
            .PATCH => request_method == .PATCH,
        };
    }
};

/// A single route definition. Use `method = .ALL` for routes that should
/// match every HTTP verb.
pub const Route = struct {
    method: Method = .ALL,
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
                if (route.method.matches(request.method)) {
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
///
/// Pattern syntax:
///   literal — matches one path segment exactly (e.g. `/users`)
///   :name   — matches a single segment and binds it as `name`
///   *name   — matches the rest of the path (possibly empty) and binds it as
///             `name`; must be the last segment in the pattern. The prefix
///             before `*name` must be followed by `/` in the request path.
pub fn matchPath(comptime pattern: []const u8, path: []const u8) ?Params {
    const segments = comptime splitSegments(pattern);
    const has_catch_all = comptime blk: {
        if (segments.len == 0) break :blk false;
        break :blk segments[segments.len - 1][0] == '*';
    };

    // Catch-all keeps the trailing slash in `rest` (it's valid content).
    // Non-catch-all paths get a trailing slash stripped for tolerance.
    var rest = if (has_catch_all)
        stripLeadingSlashOnly(path)
    else
        stripLeadingAndTrailingSlash(path);

    var params: Params = .{};
    // Tracks whether the previous segment consumed a `/` separator from the
    // path. The catch-all requires this so that `/foo/*rest` does NOT match
    // `/foo` — only `/foo/` and deeper. Starts true because the leading `/`
    // of the path has already been stripped.
    var prev_consumed_slash = true;

    inline for (segments, 0..) |seg, i| {
        const is_last = i == segments.len - 1;
        if (seg[0] == '*') {
            // Catch-all: requires a separator to have been consumed by the
            // preceding segment, otherwise `/foo/*rest` would match `/foo`.
            if (!prev_consumed_slash) return null;
            params.entries[params.len] = .{
                .name = seg[1..],
                .value = rest,
            };
            params.len += 1;
            rest = "";
            // `inline for` has no break; the is_last branch below skips the
            // residual length check for catch-all segments.
        } else if (seg[0] == ':') {
            // Single-segment param.
            const slash_pos = std.mem.indexOfScalar(u8, rest, '/');
            const value = if (slash_pos) |pos| rest[0..pos] else rest;
            if (value.len == 0) return null;
            params.entries[params.len] = .{
                .name = seg[1..],
                .value = value,
            };
            params.len += 1;
            if (slash_pos) |pos| {
                rest = rest[pos + 1 ..];
                prev_consumed_slash = true;
            } else {
                rest = "";
                prev_consumed_slash = false;
            }
        } else {
            // Literal segment — must match exactly.
            if (rest.len < seg.len) return null;
            if (!std.mem.eql(u8, rest[0..seg.len], seg)) return null;
            const after = rest[seg.len..];
            if (after.len == 0) {
                rest = "";
                prev_consumed_slash = false;
            } else if (after[0] == '/') {
                rest = after[1..];
                prev_consumed_slash = true;
            } else {
                return null;
            }
        }

        // Last segment: in non-catch-all mode the path must be exhausted.
        if (is_last and seg[0] != '*') {
            if (rest.len != 0) return null;
        }
    }

    if (segments.len == 0) {
        if (rest.len != 0) return null;
    }

    return params;
}

fn stripLeadingAndTrailingSlash(path: []const u8) []const u8 {
    if (path.len > 0 and path[0] == '/') {
        const trimmed = path[1..];
        if (trimmed.len > 0 and trimmed[trimmed.len - 1] == '/') {
            return trimmed[0 .. trimmed.len - 1];
        }
        return trimmed;
    }
    return path;
}

fn stripLeadingSlashOnly(path: []const u8) []const u8 {
    if (path.len > 0 and path[0] == '/') return path[1..];
    return path;
}

/// Split a pattern like "/users/:id/posts" into ["users", ":id", "posts"] at comptime.
/// Enforces that a `*name` catch-all segment, if present, is the last segment
/// and has a non-empty name.
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

        // Validate catch-all usage: a `*name` segment must be last and must
        // have a non-empty name.
        for (segments, 0..) |seg, idx| {
            if (seg.len > 0 and seg[0] == '*') {
                if (idx != segments.len - 1) {
                    @compileError("catch-all segment must be the last segment in pattern '" ++ pattern ++ "'");
                }
                if (seg.len < 2) {
                    @compileError("catch-all segment needs a name, e.g. '*rest' in pattern '" ++ pattern ++ "'");
                }
            }
        }

        const final = segments;
        return &final;
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

test "Router: matchPath catch-all root" {
    const r1 = matchPath("/*rest", "/");
    try testing.expect(r1 != null);
    try testing.expectEqualStrings("rest", r1.?.entries[0].name);
    try testing.expectEqualStrings("", r1.?.entries[0].value);

    const r2 = matchPath("/*rest", "/foo");
    try testing.expect(r2 != null);
    try testing.expectEqualStrings("foo", r2.?.entries[0].value);

    const r3 = matchPath("/*rest", "/foo/bar/baz");
    try testing.expect(r3 != null);
    try testing.expectEqualStrings("foo/bar/baz", r3.?.entries[0].value);
}

test "Router: matchPath catch-all prefix" {
    // /foo/*rest should match /foo/ and /foo/... but not /foo and not /foobar
    const r1 = matchPath("/foo/*rest", "/foo/");
    try testing.expect(r1 != null);
    try testing.expectEqualStrings("", r1.?.entries[0].value);

    const r2 = matchPath("/foo/*rest", "/foo/bar");
    try testing.expect(r2 != null);
    try testing.expectEqualStrings("bar", r2.?.entries[0].value);

    const r3 = matchPath("/foo/*rest", "/foo/bar/baz/qux");
    try testing.expect(r3 != null);
    try testing.expectEqualStrings("bar/baz/qux", r3.?.entries[0].value);

    try testing.expect(matchPath("/foo/*rest", "/foo") == null);
    try testing.expect(matchPath("/foo/*rest", "/foobar") == null);
    try testing.expect(matchPath("/foo/*rest", "/") == null);
}

test "Router: matchPath catch-all preserves query trimming via dispatcher" {
    // extractPath strips query, so matchPath sees the bare path.
    const r = matchPath("/api/*rest", extractPath("/api/users/42?q=1"));
    try testing.expect(r != null);
    try testing.expectEqualStrings("users/42", r.?.entries[0].value);
}

test "Router: matchPath named param then catch-all" {
    const r = matchPath("/api/:app/*rest", "/api/demo/data/batch");
    try testing.expect(r != null);
    try testing.expectEqual(@as(usize, 2), r.?.len);
    try testing.expectEqualStrings("app", r.?.entries[0].name);
    try testing.expectEqualStrings("demo", r.?.entries[0].value);
    try testing.expectEqualStrings("rest", r.?.entries[1].name);
    try testing.expectEqualStrings("data/batch", r.?.entries[1].value);

    const r2 = matchPath("/api/:app/*rest", "/api/demo/");
    try testing.expect(r2 != null);
    try testing.expectEqualStrings("demo", r2.?.entries[0].value);
    try testing.expectEqualStrings("", r2.?.entries[1].value);
}

test "Router: any-method route matches all verbs" {
    const routes = [_]Route{
        .{ .method = .ALL, .path = "/api/*rest", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
                return Response.init(.ok, "text/plain", request.params.get("rest") orelse "");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req_get = try Request.parseConst("GET /api/foo HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp_get = dispatch(std.testing.allocator, test_io, &req_get);
    try testing.expectEqualStrings("foo", resp_get.body);

    const req_post = try Request.parseConst("POST /api/bar HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp_post = dispatch(std.testing.allocator, test_io, &req_post);
    try testing.expectEqualStrings("bar", resp_post.body);

    const req_delete = try Request.parseConst("DELETE /api/baz HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp_delete = dispatch(std.testing.allocator, test_io, &req_delete);
    try testing.expectEqualStrings("baz", resp_delete.body);
}

test "Router: first-match-wins ordering with catch-alls" {
    const routes = [_]Route{
        .{ .method = .GET, .path = "/@cnc/admin/*rest", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "admin");
            }
        }.h },
        .{ .method = .GET, .path = "/@cnc/*rest", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "static");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req1 = try Request.parseConst("GET /@cnc/admin/users HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try testing.expectEqualStrings("admin", dispatch(std.testing.allocator, test_io, &req1).body);

    const req2 = try Request.parseConst("GET /@cnc/cnc.mjs HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try testing.expectEqualStrings("static", dispatch(std.testing.allocator, test_io, &req2).body);
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

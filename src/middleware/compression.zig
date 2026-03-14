const std = @import("std");
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Router = @import("../Router.zig");
const Connection = @import("../server/Connection.zig");
const Compression = @import("../server/Compression.zig");

/// Wrap a route handler to automatically gzip-compress responses
/// when the client accepts gzip and the content type is compressible.
pub fn wrap(comptime inner: Router.RouteHandler) Router.RouteHandler {
    return struct {
        fn handle(req: *const Request, params: *const Router.Params, io: std.Io) Response {
            var resp = inner(req, params, io);
            if (req.acceptsEncoding("gzip")) {
                const ct = resp.headers.get("Content-Type") orelse "";
                if (Compression.isCompressible(ct)) resp.gzip();
            }
            return resp;
        }
    }.handle;
}

/// Wrap a Connection.Handler to automatically gzip-compress responses.
pub fn wrapAll(comptime inner: Connection.Handler) Connection.Handler {
    return struct {
        fn handle(req: *const Request, io: std.Io) Response {
            var resp = inner(req, io);
            if (req.acceptsEncoding("gzip")) {
                const ct = resp.headers.get("Content-Type") orelse "";
                if (Compression.isCompressible(ct)) resp.gzip();
            }
            return resp;
        }
    }.handle;
}

// --- Tests ---

const testing = std.testing;

test "compression middleware: wraps route handler and compresses" {
    const inner = struct {
        fn h(_: *const Request, _: *const Router.Params, _: std.Io) Response {
            // Use a body large enough that gzip actually shrinks it
            return Response.init(.ok, "text/plain",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            );
        }
    }.h;

    const wrapped = wrap(inner);
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Accept-Encoding: gzip, deflate\r\n" ++
            "\r\n",
    );
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };
    var params: Router.Params = .{};

    var resp = wrapped(&req, &params, test_io);
    defer resp.deinit(std.heap.page_allocator);

    try testing.expectEqualStrings("gzip", resp.headers.get("Content-Encoding").?);
    try testing.expect(resp.body.len < 256);
}

test "compression middleware: skips when not accepted" {
    const inner = struct {
        fn h(_: *const Request, _: *const Router.Params, _: std.Io) Response {
            return Response.init(.ok, "text/plain",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            );
        }
    }.h;

    const wrapped = wrap(inner);
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "\r\n",
    );
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };
    var params: Router.Params = .{};

    const resp = wrapped(&req, &params, test_io);
    try testing.expect(resp.headers.get("Content-Encoding") == null);
}

test "compression middleware: skips non-compressible content types" {
    const inner = struct {
        fn h(_: *const Request, _: *const Router.Params, _: std.Io) Response {
            return Response.init(.ok, "image/png",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            );
        }
    }.h;

    const wrapped = wrap(inner);
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Accept-Encoding: gzip\r\n" ++
            "\r\n",
    );
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };
    var params: Router.Params = .{};

    const resp = wrapped(&req, &params, test_io);
    try testing.expect(resp.headers.get("Content-Encoding") == null);
}

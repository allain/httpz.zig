const std = @import("std");
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Router = @import("../Router.zig");
const Connection = @import("../server/Connection.zig");
const Compression = @import("../server/Compression.zig");
const flate = std.compress.flate;

/// Wrap a route handler to automatically gzip-compress responses
/// when the client accepts gzip and the content type is compressible.
pub fn wrap(comptime inner: Router.RouteHandler) Router.RouteHandler {
    return struct {
        fn handle(allocator: std.mem.Allocator, io: std.Io, req: *const Request, params: *const Router.Params) Response {
            var resp = inner(allocator, io, req, params);
            if (req.acceptsEncoding("gzip")) {
                const ct = resp.headers.get("Content-Type") orelse "";
                if (Compression.isCompressible(ct)) {
                    if (resp.stream_fn != null) {
                        wrapStreamingGzip(&resp);
                    } else {
                        compressBody(&resp, allocator);
                    }
                }
            }
            return resp;
        }
    }.handle;
}

/// Wrap a Connection.Handler to automatically gzip-compress responses.
pub fn wrapAll(comptime inner: Connection.Handler) Connection.Handler {
    return struct {
        fn handle(allocator: std.mem.Allocator, io: std.Io, req: *const Request) Response {
            var resp = inner(allocator, io, req);
            if (req.acceptsEncoding("gzip")) {
                const ct = resp.headers.get("Content-Type") orelse "";
                if (Compression.isCompressible(ct)) {
                    if (resp.stream_fn != null) {
                        wrapStreamingGzip(&resp);
                    } else {
                        compressBody(&resp, allocator);
                    }
                }
            }
            return resp;
        }
    }.handle;
}

/// Gzip-compress the response body in place.
fn compressBody(resp: *Response, allocator: std.mem.Allocator) void {
    if (resp.body.len == 0) return;
    if (resp.headers.get("Content-Encoding") != null) return;

    const compressed = Compression.compress(resp.body, allocator) catch return;
    if (compressed.len >= resp.body.len) {
        allocator.free(compressed);
        return;
    }

    resp.deinit(allocator);
    resp.body = compressed;
    resp._body_allocated = compressed;
    resp.headers.append("Content-Encoding", "gzip") catch {};
    resp.headers.append("Vary", "Accept-Encoding") catch {};
}

/// Context for wrapping a streaming response with gzip compression.
const GzipStreamContext = struct {
    original_fn: *const fn (?*anyopaque, *std.Io.Writer) void,
    original_ctx: ?*anyopaque,

    fn streamFn(ctx_ptr: ?*anyopaque, writer: *std.Io.Writer) void {
        const self: *GzipStreamContext = @ptrCast(@alignCast(ctx_ptr));
        defer std.heap.page_allocator.destroy(self);

        // Allocate window buffer for the compressor
        const window_buf = std.heap.page_allocator.alloc(u8, flate.max_window_len) catch return;
        defer std.heap.page_allocator.free(window_buf);

        var comp = flate.Compress.init(writer, window_buf, .gzip, .default) catch return;

        // Call the original stream function with the compressor's writer
        self.original_fn(self.original_ctx, &comp.writer);

        // Finalize the gzip stream
        comp.finish() catch return;
    }
};

/// Replace a streaming response's stream_fn with a gzip-wrapping version.
fn wrapStreamingGzip(resp: *Response) void {
    const ctx = std.heap.page_allocator.create(GzipStreamContext) catch return;
    ctx.* = .{
        .original_fn = resp.stream_fn.?,
        .original_ctx = resp.stream_context,
    };
    resp.stream_fn = GzipStreamContext.streamFn;
    resp.stream_context = @ptrCast(ctx);
    resp.headers.append("Content-Encoding", "gzip") catch {};
    resp.headers.append("Vary", "Accept-Encoding") catch {};
    // Remove Content-Length since compressed size is unknown
    resp.headers.remove("Content-Length");
    resp.auto_content_length = false;
}

// --- Tests ---

const testing = std.testing;

test "compression middleware: wraps route handler and compresses" {
    const inner = struct {
        fn h(_: std.mem.Allocator, _: std.Io, _: *const Request, _: *const Router.Params) Response {
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

    var resp = wrapped(std.testing.allocator, test_io, &req, &params);
    defer resp.deinit(std.testing.allocator);

    try testing.expectEqualStrings("gzip", resp.headers.get("Content-Encoding").?);
    try testing.expect(resp.body.len < 256);
}

test "compression middleware: skips when not accepted" {
    const inner = struct {
        fn h(_: std.mem.Allocator, _: std.Io, _: *const Request, _: *const Router.Params) Response {
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

    const resp = wrapped(std.testing.allocator, test_io, &req, &params);
    try testing.expect(resp.headers.get("Content-Encoding") == null);
}

test "compression middleware: skips non-compressible content types" {
    const inner = struct {
        fn h(_: std.mem.Allocator, _: std.Io, _: *const Request, _: *const Router.Params) Response {
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

    const resp = wrapped(std.testing.allocator, test_io, &req, &params);
    try testing.expect(resp.headers.get("Content-Encoding") == null);
}

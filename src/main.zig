const std = @import("std");
const Io = std.Io;
const httpz = @import("httpz");

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    try stdout.writeAll("httpz - HTTP/1.1 Server (RFC 2616)\n");
    try stdout.writeAll("Listening on 127.0.0.1:8080\n");
    try stdout.flush();

    var server = httpz.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
    }, handler);

    try server.run(io);
}

fn handler(request: *const httpz.Request, _: std.Io) httpz.Response {
    if (std.mem.eql(u8, request.uri, "/")) {
        return httpz.Response.init(.ok, "text/plain", "Hello from httpz!");
    }

    if (std.mem.eql(u8, request.uri, "/health")) {
        return httpz.Response.init(.ok, "application/json", "{\"status\":\"ok\"}");
    }

    return httpz.Response.init(.not_found, "text/plain", "Not Found");
}

test "handler returns 200 for root" {
    const req = try httpz.Request.parseConst(
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    const resp = handler(&req, .{ .userdata = null, .vtable = undefined });
    try std.testing.expectEqual(httpz.Response.StatusCode.ok, resp.status);
}

test "handler returns 404 for unknown path" {
    const req = try httpz.Request.parseConst(
        "GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    const resp = handler(&req, .{ .userdata = null, .vtable = undefined });
    try std.testing.expectEqual(httpz.Response.StatusCode.not_found, resp.status);
}

test "handler returns health check" {
    const req = try httpz.Request.parseConst(
        "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    const resp = handler(&req, .{ .userdata = null, .vtable = undefined });
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", resp.body);
}

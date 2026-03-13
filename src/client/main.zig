const std = @import("std");
const Io = std.Io;
const httpz = @import("httpz");
const Client = httpz.Client;

pub fn main(init: std.process.Init) !void {
    _ = init;
    const io = std.Io.ContextForThread.getOrInit() catch @panic("failed to get IO");

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    const url_str = "http://example.com";
    const url = Client.Url.parse(url_str).?;

    try stdout.print("Connecting to {s}:{}...\n", .{ url.host, url.port });

    var client = Client.init(std.heap.page_allocator, .{
        .host = url.host,
        .port = url.port,
        .connection_timeout_s = 10,
        .read_timeout_s = 10,
    });

    try client.connect(io);

    try stdout.print("Connected! Sending request...\n", .{});

    const resp = try client.request(io, .GET, url.path, null, null);

    try stdout.print("Status: {}\n", .{resp.status});
    try stdout.print("Content-Type: {s}\n", .{resp.headers.get("Content-Type") orelse "unknown"});
    try stdout.print("Body length: {} bytes\n", .{resp.body.len});

    if (resp.body.len > 0 and resp.body.len < 1000) {
        try stdout.print("Body: {s}\n", .{resp.body});
    }

    client.deinit();
}

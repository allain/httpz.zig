const std = @import("std");
const Io = std.Io;
const httpz = @import("httpz");
const Client = httpz.Client;
const Response = httpz.Response;
const tls = @import("tls");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    const url_str = "https://api.iconify.design/mdi/home.svg";
    const url = Client.Url.parse(url_str).?;

    const is_https = std.mem.eql(u8, url.scheme, "https");

    try stdout.print("Connecting to {s}:{}...\n", .{ url.host, url.port });
    try stdout.flush();

    const rng_impl: std.Random.IoSource = .{ .io = io };
    const root_ca: tls.config.cert.Bundle = .{};

    var client_tls_config: ?tls.config.Client = null;
    if (is_https) {
        client_tls_config = .{
            .host = url.host,
            .root_ca = root_ca,
            .insecure_skip_verify = true,
            .now = std.Io.Clock.real.now(io),
            .rng = rng_impl.interface(),
        };
    }

    var client = Client.init(allocator, .{
        .host = url.host,
        .port = url.port,
        .connection_timeout_s = 10,
        .read_timeout_s = 10,
        .tls_config = client_tls_config,
    });

    try client.connect(io);

    try stdout.print("Connected! Sending request...\n", .{});
    try stdout.flush();

    var resp = try client.request(io, .GET, url.path, null, null);

    try stdout.print("Status: {}\n", .{resp.status});
    try stdout.print("Content-Type: {s}\n", .{resp.headers.get("Content-Type") orelse "unknown"});
    try stdout.print("Body length: {} bytes\n", .{resp.body.len});
    try stdout.flush();

    if (resp.body.len > 0 and resp.body.len < 1000) {
        try stdout.print("Body: {s}\n", .{resp.body});
        try stdout.flush();
    }

    resp.deinit(allocator);
    client.deinit();
}

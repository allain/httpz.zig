const std = @import("std");
const Io = std.Io;
const httpz = @import("httpz");
const tls = @import("tls");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    std.debug.print("httpsz - HTTPS/1.1 Server\n", .{});
    std.debug.print("Listening on 127.0.0.1:4433\n", .{});

    const dir = std.Io.Dir.cwd().openDir(io, "examples/cert", .{}) catch {
        std.debug.print("\nError: Certificate directory not found.\n", .{});
        std.debug.print("Run the following to generate certificates:\n", .{});
        std.debug.print("  bash examples/gen_cert.sh\n\n", .{});
        return error.NoCertificate;
    };
    defer dir.close(io);

    var auth = tls.config.CertKeyPair.fromFilePath(allocator, io, dir, "cert.pem", "key.pem") catch {
        std.debug.print("\nError: Could not load certificates.\n", .{});
        std.debug.print("Run the following to generate certificates:\n", .{});
        std.debug.print("  bash examples/gen_cert.sh\n\n", .{});
        return error.InvalidCertificate;
    };
    defer auth.deinit(allocator);

    const rng_impl: std.Random.IoSource = .{ .io = io };

    var server = httpz.Server.init(.{
        .port = 4433,
        .address = "127.0.0.1",
        .tls_config = .{
            .auth = &auth,
            .now = std.Io.Clock.real.now(io),
            .rng = rng_impl.interface(),
        },
    }, handler);

    server.run(io) catch |err| {
        std.debug.print("Error: {}\n", .{err});
        std.process.exit(1);
    };
}

fn handler(request: *const httpz.Request, _: std.Io) httpz.Response {
    if (std.mem.eql(u8, request.uri, "/")) {
        return httpz.Response.init(.ok, "text/plain", "Hello from httpsz!");
    }

    if (std.mem.eql(u8, request.uri, "/health")) {
        return httpz.Response.init(.ok, "application/json", "{\"status\":\"ok\"}");
    }

    return httpz.Response.init(.not_found, "text/plain", "Not Found");
}

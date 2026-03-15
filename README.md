# httpz

An HTTP/1.1 library for Zig 0.16, built on the `std.Io` async model.

## Features

- **HTTP Server** — keep-alive, chunked transfer encoding, connection limits, slowloris protection
- **HTTP Client** — configurable timeouts, response size limits
- **Router** — path parameters (`:id`), comptime dispatch, custom 404 handlers
- **WebSocket** — RFC 6455 upgrade, text/binary frames, fragmentation reassembly, per-route handlers
- **Streaming Responses** — chunked encoding, Server-Sent Events, zero-copy file serving
- **Middleware** — CORS and gzip compression via composable `wrap` functions
- **HTTPS / TLS** — server and client TLS via [tls.zig](https://github.com/allain/tls.zig)
- **CONNECT Proxy** — SSRF protection with private IP blocking and host/port allowlists
- **Cookies** — RFC 6265 cookie parsing and Set-Cookie generation with Secure, HttpOnly, SameSite, Max-Age, Domain, Path
- **RFC 2616 Compliant** — HTTP date parsing, path traversal protection, TRACE support (off by default)

## Quick Start

```zig
const std = @import("std");
const httpz = @import("httpz");

pub fn main(init: std.process.Init) !void {
    var server = httpz.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
    }, handler);

    server.run(init.io) catch |err| switch (err) {
        error.AddressInUse => {
            std.debug.print("Error: port 8080 is already in use\n", .{});
            std.process.exit(1);
        },
    };
}

fn handler(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    if (std.mem.eql(u8, request.uri, "/")) {
        return httpz.Response.init(.ok, "text/plain", "Hello from httpz!");
    }
    return httpz.Response.init(.not_found, "text/plain", "Not Found");
}
```

Handlers receive a per-request arena allocator, an `std.Io` instance, and the parsed request. Return a `Response` value — the server handles serialization and cleanup.

## Using as a Dependency

```sh
zig fetch --save git+https://github.com/allain/httpz.zig
```

Then in your `build.zig`:

```zig
const httpz_mod = b.dependency("httpz", .{ .target = target }).module("httpz");
exe.root_module.addImport("httpz", httpz_mod);
```

## Routing

The `Router` dispatches requests by method and path at comptime. Path parameters are stored on the request and accessed via `request.params`.

```zig
const std = @import("std");
const httpz = @import("httpz");

pub fn main(init: std.process.Init) !void {
    var server = httpz.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
    }, comptime httpz.Router.handler(&.{
        .{ .method = .GET, .path = "/", .handler = handleHome },
        .{ .method = .GET, .path = "/hello/:name", .handler = handleHello },
    }));

    server.run(init.io) catch |err| switch (err) {
        error.AddressInUse => std.process.exit(1),
    };
}

fn handleHome(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.ok, "text/plain", "Welcome!");
}

fn handleHello(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    const name = request.params.get("name") orelse "world";
    _ = name; // use name to build a response
    return httpz.Response.init(.ok, "text/plain", "Hello!");
}
```

`GET /hello/alice` matches the `:name` parameter — retrieve it with `request.params.get("name")`.

Use `Router.handlerWithFallback` to provide a custom 404 handler instead of the default.

## Middleware

`wrap` works on both route handlers and plain handlers — use it per-route or globally:

```zig
const std = @import("std");
const httpz = @import("httpz");

const cors = httpz.middleware.cors.init(.{ .origin = "https://myapp.com" });
const compress = httpz.middleware.compression;

pub fn main(init: std.process.Init) !void {
    var server = httpz.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
    }, comptime httpz.Router.handler(&.{
        // Compression on a single route
        .{ .method = .GET, .path = "/data", .handler = compress.wrap(handleData) },
        // CORS + compression composed together
        .{ .method = .GET, .path = "/api", .handler = cors.wrap(compress.wrap(handleData)) },
    }));

    server.run(init.io) catch |err| switch (err) {
        error.AddressInUse => std.process.exit(1),
    };
}

fn handleData(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.ok, "application/json", "{\"ok\":true}");
}
```

To apply middleware globally without the Router:

```zig
var server = httpz.Server.init(config, compress.wrap(handler));
```

### Passing State to Handlers

Middleware can attach typed state to `request.context` for downstream handlers. The context is keyed by type, so multiple middleware can each store their own state without clobbering each other.

```zig
const GeoInfo = struct { lat: f64, lon: f64 };
const AuthInfo = struct { user_id: []const u8 };

fn geoMiddleware(comptime inner: httpz.Handler) httpz.Handler {
    return struct {
        fn handle(allocator: std.mem.Allocator, io: std.Io, req: *const httpz.Request) httpz.Response {
            var geo = GeoInfo{ .lat = 45.0, .lon = -73.0 }; // looked up from req IP
            var ctx_req = req.*;
            ctx_req.context.put(GeoInfo, &geo);
            return inner(allocator, io, &ctx_req);
        }
    }.handle;
}

fn authMiddleware(comptime inner: httpz.Handler) httpz.Handler {
    return struct {
        fn handle(allocator: std.mem.Allocator, io: std.Io, req: *const httpz.Request) httpz.Response {
            var auth = AuthInfo{ .user_id = "alice" }; // parsed from header
            var ctx_req = req.*;
            ctx_req.context.put(AuthInfo, &auth);
            return inner(allocator, io, &ctx_req);
        }
    }.handle;
}

fn handleDashboard(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    // Both are available — middleware don't clobber each other
    const geo = request.context.get(GeoInfo) orelse return httpz.Response.init(.internal_server_error, "text/plain", "No geo");
    const auth = request.context.get(AuthInfo) orelse return httpz.Response.init(.unauthorized, "text/plain", "No auth");
    _ = geo;
    _ = auth;
    return httpz.Response.init(.ok, "text/plain", "OK");
}
```

Context values live on each middleware's stack frame and are valid for the handler's lifetime. Up to 8 entries are supported (matching the `Params` limit).

### CORS Options

```zig
httpz.middleware.cors.init(.{
    .origin = "*",                                            // Access-Control-Allow-Origin
    .methods = "GET, POST, PUT, DELETE, OPTIONS, PATCH",      // Access-Control-Allow-Methods
    .headers = "Content-Type, Authorization",                 // Access-Control-Allow-Headers
    .max_age = "86400",                                       // Access-Control-Max-Age (seconds)
});
```

## Cookies

`httpz.Cookie` provides RFC 6265 cookie parsing from requests and `Set-Cookie` header generation for responses.

### Reading Cookies

```zig
fn handler(allocator: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    // Look up a single cookie by name
    const session = httpz.Cookie.get(request, "session_id") orelse
        return httpz.Response.init(.unauthorized, "text/plain", "No session");

    // Iterate all cookies
    var iter = httpz.Cookie.iterator(request);
    while (iter.next()) |cookie| {
        std.debug.print("{s} = {s}\n", .{ cookie.name, cookie.value });
    }

    _ = session;
    _ = allocator;
    return httpz.Response.init(.ok, "text/plain", "OK");
}
```

### Setting Cookies

```zig
fn login(allocator: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp = httpz.Response.init(.ok, "text/plain", "Logged in");

    // Session cookie — expires when browser closes
    httpz.Cookie.set(&resp, allocator, .{
        .name = "session_id",
        .value = "abc123",
        .path = "/",
        .http_only = true,
        .secure = true,
        .same_site = .lax,
    }) catch {};

    // Persistent cookie — 30 day expiry
    httpz.Cookie.set(&resp, allocator, .{
        .name = "preferences",
        .value = "dark_mode",
        .path = "/",
        .max_age = 86400 * 30,
    }) catch {};

    return resp;
}
```

### Deleting Cookies

```zig
fn logout(allocator: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp = httpz.Response.init(.ok, "text/plain", "Logged out");

    // Domain and Path must match the original cookie
    httpz.Cookie.remove(&resp, allocator, .{
        .name = "session_id",
        .path = "/",
    }) catch {};

    return resp;
}
```

The allocator is used to format `Set-Cookie` header values. Use a per-request arena so the memory lives until the response is serialized.

## Streaming Responses

Set `stream_fn` on a response to stream the body directly to the network writer. The server serializes headers first, then calls your function.

### Chunked Encoding

```zig
fn handleStream(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp: httpz.Response = .{ .status = .ok, .chunked = true };
    resp.headers.append("Content-Type", "text/plain") catch {};
    resp.stream_fn = streamFn;
    return resp;
}

fn streamFn(_: ?*anyopaque, writer: *std.Io.Writer) void {
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var buf: [32]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "line {d}\n", .{i}) catch return;
        writer.writeAll(line) catch return;
    }
}
```

### Server-Sent Events

```zig
fn handleEvents(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp: httpz.Response = .{ .status = .ok };
    resp.headers.append("Content-Type", "text/event-stream") catch {};
    resp.headers.append("Cache-Control", "no-cache") catch {};
    resp.auto_content_length = false;
    resp.stream_fn = sseStreamFn;
    return resp;
}

fn sseStreamFn(_: ?*anyopaque, writer: *std.Io.Writer) void {
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        var buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "data: event {d}\n\n", .{i}) catch return;
        writer.writeAll(msg) catch return;
        writer.flush() catch return;
    }
}
```

Use `stream_context` to pass state to the stream function (Zig has no closures).

## WebSocket

Return a 101 upgrade response and provide a WebSocket handler. The handler owns the connection loop.

### Per-route (with Router)

```zig
.{ .method = .GET, .path = "/ws", .handler = handleWsUpgrade, .ws = .{ .handler = wsHandler } },
```

```zig
fn handleWsUpgrade(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    return httpz.WebSocket.upgradeResponse(request) orelse
        httpz.Response.init(.bad_request, "text/plain", "WebSocket upgrade required");
}

fn wsHandler(conn: *httpz.WebSocket.Conn, _: *const httpz.Request) void {
    while (true) {
        const msg = conn.recv() catch break orelse break;
        switch (msg.opcode) {
            .text => conn.send(msg.payload) catch break,
            .binary => conn.sendBinary(msg.payload) catch break,
            else => {},
        }
    }
}
```

### Global (without Router)

Set `websocket_handler` in the server config:

```zig
var server = httpz.Server.init(.{
    .port = 8080,
    .address = "127.0.0.1",
    .websocket_handler = wsHandler,
}, handler);
```

Then return `WebSocket.upgradeResponse(request)` from your handler to trigger the upgrade.

The `Conn` API: `recv() !?Message`, `send([]const u8) !void`, `sendBinary([]const u8) !void`, `close(u16, []const u8) !void`.

## File Serving

`Response.sendFile` streams a file from disk using zero-copy I/O when available:

```zig
fn handleFile(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.sendFile("/var/www/index.html", "text/html", 10 * 1024 * 1024);
}
```

The third argument is the maximum allowed file size in bytes (0 for unlimited). Returns 404 if the file doesn't exist, 413 if it exceeds the limit.

## HTTPS / TLS

### Server

```zig
const tls = @import("tls");

var auth = tls.config.CertKeyPair.fromFilePath(allocator, io, cert_dir, "cert.pem", "key.pem") catch return error.InvalidCertificate;
defer auth.deinit(allocator);

var server = httpz.Server.init(.{
    .port = 4433,
    .address = "127.0.0.1",
    .tls_config = .{
        .auth = &auth,
        .now = std.Io.Clock.real.now(io),
        .rng = rng.interface(),
    },
}, handler);
```

### Client

```zig
var client = httpz.Client.init(allocator, .{
    .host = "example.com",
    .port = 443,
    .tls_config = .{
        .host = "example.com",
        .root_ca = .{},
        .now = std.Io.Clock.real.now(io),
        .rng = rng.interface(),
    },
});
```

## HTTP Client

```zig
const httpz = @import("httpz");
const Client = httpz.Client;

const url = Client.Url.parse("http://example.com/path").?;

var client = Client.init(allocator, .{
    .host = url.host,
    .port = url.port,
    .connection_timeout_s = 10,
    .read_timeout_s = 10,
});
defer client.deinit();

try client.connect(io);

var resp = try client.request(io, .GET, url.path, null, null);
defer resp.deinit(allocator);
```

`request` takes method, URI path, optional `Headers`, and optional body (`[]const u8`).

## Server Configuration

All fields with their defaults:

```zig
httpz.Server.init(.{
    .port = 8080,
    .address = "127.0.0.1",
    .read_buffer_size = 8192,
    .write_buffer_size = 8192,
    .max_request_size = 1_048_576,       // 1 MiB max total request
    .max_header_size = 65536,            // 64 KiB max headers
    .keep_alive_timeout_s = 60,          // idle connection timeout
    .initial_read_timeout_s = 30,        // slowloris protection
    .max_connections = 512,              // 0 = unlimited
    .enable_trace = false,               // TRACE method (security risk)
    .enable_proxy = false,               // CONNECT proxy support
    .proxy = .{
        .allowed_ports = &.{443},
        .block_private_ips = true,
        .allowed_hosts = &.{},
    },
    .websocket_handler = null,           // global WebSocket handler
    .tls_config = null,                  // TLS for HTTPS
}, handler);
```

## Building & Testing

Requires Zig 0.16+.

```sh
# Run all tests (unit + integration)
zig build test

# Run integration tests only
zig build test-integration

# Run tests with kcov coverage
zig build coverage
```

Examples:

```sh
zig build example_server_http
zig build example_server_https
zig build example_server_router
zig build example_server_streaming
zig build example_server_websocket
zig build example_client_http
zig build example_client_https
```

## License

See [LICENSE](LICENSE) for details.

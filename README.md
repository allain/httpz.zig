# httpz

An HTTP/1.1 server implementation in Zig 0.16, built on the `std.Io` async model.

## Features

- **RFC 2616 compliant** HTTP/1.1 request parsing and response building
- **Keep-alive** connections with configurable idle timeout
- **Chunked transfer encoding** support
- **CONNECT proxy** with SSRF protection (private IP blocking, port/host allowlists)
- **TRACE method** support (disabled by default for security)
- **Path traversal protection** (percent-encoded, double-encoded, overlong UTF-8, backslash variants)
- **Connection limits** and slowloris timeout protection
- **HTTP date parsing** (RFC 1123, RFC 850, asctime formats)
- Zero dependencies beyond the Zig standard library

## Quick Start

```zig
const std = @import("std");
const httpz = @import("httpz");

pub fn main(init: std.process.Init) !void {
    var server = httpz.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
    }, handler);

    try server.run(init.io);
}

fn handler(request: *const httpz.Request, _: std.Io) httpz.Response {
    if (std.mem.eql(u8, request.uri, "/")) {
        return httpz.Response.init(.ok, "text/plain", "Hello from httpz!");
    }
    return httpz.Response.init(.not_found, "text/plain", "Not Found");
}
```

## Building

Requires Zig 0.16+.

```sh
# Run the demo server on 127.0.0.1:8080
zig build run

# Run all tests
zig build test

# Run tests with kcov coverage (requires kcov)
zig build coverage
```

## Using as a Dependency

Add httpz to your `build.zig.zon`:

```sh
zig fetch --save git+https://github.com/allain/httpz
```

Then in your `build.zig`:

```zig
const httpz_mod = b.dependency("httpz", .{ .target = target }).module("httpz");
exe.root_module.addImport("httpz", httpz_mod);
```

## Server Configuration

```zig
httpz.Server.init(.{
    .port = 8080,
    .address = "127.0.0.1",
    .max_request_size = 1_048_576,     // 1 MiB
    .max_header_size = 65536,          // 64 KiB
    .keep_alive_timeout_s = 60,
    .initial_read_timeout_s = 30,
    .max_connections = 512,
    .enable_trace = false,
    .enable_proxy = false,
    .proxy = .{
        .allowed_ports = &.{443},
        .block_private_ips = true,
        .allowed_hosts = &.{},
    },
}, handler);
```

## Modules

| Module | Description |
|--------|-------------|
| `Server` | TCP listener and connection manager |
| `Request` | HTTP request parser |
| `Response` | HTTP response builder |
| `Headers` | Case-insensitive header storage |
| `Connection` | Per-connection keep-alive and request processing |
| `Proxy` | CONNECT tunneling and Via header support |
| `Date` | HTTP date parsing (RFC 1123, RFC 850, asctime) |

## License

See [LICENSE](LICENSE) for details.

# httpz Security Hardening

## Critical

- [x] **1. Race condition in connection counting**
  - `Server.zig:95-109`
  - TOCTOU between `load` and `fetchAdd` lets concurrent connections bypass `max_connections`
  - Fixed: atomic `fetchAdd` first, check result, `fetchSub` if over limit
  - Also upgraded to `acquire`/`release` ordering

- [x] **2. Single-threaded accept loop blocks on connection handling**
  - `Server.zig:88-113`
  - One slow client blocks the entire server; trivial DoS
  - Fixed: accepted sockets are now dispatched via
    `std.Io.Group.concurrent`, so the accept loop returns immediately
    instead of waiting for per-connection keep-alive handling

## High

- [x] **3. CONNECT tunnel has no target socket timeout**
  - `Server.zig:350, 378-417`
  - Target socket had no `SO_RCVTIMEO`; a malicious/stalled target blocks forever
  - Fixed: `setSocketTimeout` applied to target socket after connect

- [x] **4. SSRF bypass via hostname in proxy**
  - `Server.zig:329-338`
  - `isPrivateIp()` only checked IP string literals, not resolved addresses
  - Fixed: now blocks "localhost", bracketed IPv6, long-form IPv6,
    IPv6-mapped IPv4 (`::ffff:127.0.0.1`), and `0.0.0.0/8` range
  - Note: DNS rebinding still requires post-resolution IP check

## Medium

- [x] **5. 1 MiB allocation per connection enables memory exhaustion**
  - `Server.zig:138`
  - 512 connections x 1 MiB = 512 MiB committed memory
  - Fixed: request buffer now starts at a bounded header-sized allocation
    (default 64 KiB, minimum 16 KiB) and grows on demand up to
    `max_request_size`

- [x] **6. CONNECT tunnel can be held open indefinitely**
  - `Server.zig:378-417`
  - No idle timeout on the tunnel forwarding loop
  - Fixed: target socket gets `SO_RCVTIMEO` (shares fix with #3)

## Low

- [x] **7. `appendServer` silently drops headers in release builds**
  - `Headers.zig:48-57`
  - `std.debug.assert(false)` is a no-op in release; critical headers silently dropped
  - Fixed: added `std.log.err` before the assert so it's visible in all builds

- [x] **8. readHeaders accepts unterminated headers**
  - `Server.zig:423-453`
  - If headers never end with `\r\n\r\n`, the full 1 MiB buffer is consumed
  - Fixed: new `max_header_size` config (default 64 KiB) limits header reads

- [x] **9. Chunked body read doesn't validate chunk protocol**
  - `Server.zig:462-516`
  - Line-by-line reading doesn't properly enforce chunk framing
  - Malformed chunks may be silently accepted
  - Fixed: chunked reads now validate each size line, read exact chunk bytes,
    require trailing CRLF for every chunk, and require a properly terminated
    trailer section

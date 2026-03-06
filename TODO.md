# httpz - RFC 2616 Compliance Audit

## Critical MUST Violations

- [x] **Body-forbidden responses can include a body** (§4.3) - 1xx/204/304 now strip body AND disable Content-Length (`Connection.zig`)
- [x] **Absolute URI host doesn't take precedence** (§5.2) - Host header now replaced by absolute URI host (`Request.zig`)
- [x] **TRACE responses lack Date header** (§14.18) - `addStandardHeaders()` now called for TRACE too (`Connection.zig`)
- [x] **201 Created not enforced to include Location** (§10.2.2) - Not enforced (201 is SHOULD, not MUST per RFC 2616)
- [x] **Redirect responses not enforced to include Location** (§10.3.x) - Default Location "/" added for redirects missing it (`Connection.zig`)
- [x] **Multiple Content-Length headers not detected** (§4.4) - Conflicting values now rejected with error (`Request.zig`)

## Important MUST Violations

- [x] **Only RFC 1123 date parsing** (§3.3.1) - Now accepts RFC 850 and asctime formats via `parseHttpDate()` (`Date.zig`)
- [x] **Chunked responses can be sent to HTTP/1.0 clients** (§3.6) - Chunked flag cleared for HTTP/1.0, falls back to Content-Length (`Connection.zig`)
- [x] **No 417 Expectation Failed** (§14.20) - Unrecognized Expect values now return 417 (`Server.zig`)
- [x] **Content-Length: 0 not generated for empty bodies** (§14.13) - Now emitted for all non-chunked responses (`Response.zig`)
- [x] **Multiple Host headers not rejected** (§14.23) - Now returns MultipleHostHeaders error (`Request.zig`)

## SHOULD Violations

- [x] **Unrecognized Transfer-Encoding not rejected** (§3.6) - Now returns 501 Not Implemented (`Server.zig`)
- [x] **Header continuation preserves CRLF** (§4.2) - `parse()` now takes `[]u8` and replaces CRLF with spaces in-place (`Request.zig`)
- [x] **100 Continue always sent unconditionally** (§8.2.3) - Now only sent for "100-continue"; other Expect values get 417 (`Server.zig`)
- [x] **TRACE echoes reconstructed request** (§9.8) - Now echoes raw bytes via `request.raw` field (`Connection.zig`)
- [x] **No If-None-Match precedence over If-Modified-Since** (§14.25) - Documented in API; callers should check matchesEtag first (`Request.zig`)
- [x] **If-None-Match only matches single ETag** (§14.26) - Now handles comma-separated lists (`Request.zig`)

## Architectural / Security

- [x] **Keep-alive timeout never enforced** (§8.1.4) - `SO_RCVTIMEO` set via `setsockopt`, configurable via `keep_alive_timeout_s` (`Server.zig`)
- [x] **Hop-by-hop header list incomplete** (§13.5.1) - Added Transfer-Encoding to list (`Connection.zig`)
- [x] **Connection header tokens not parsed** (§14.10) - Now parses Connection field for custom hop-by-hop header names (`Connection.zig`)

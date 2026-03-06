# httpz - RFC 2616 Compliance Audit

## Security Vulnerabilities

### LOW Priority

- [x] **10. No Host Header Value Validation**
  - `Request.zig:183-205`
  - Host header now validated: rejects control chars, whitespace, invalid chars
  - IPv4, IPv6 literals, and hostname:port all supported

- [x] **11. No Initial Request Read Timeout**
  - `Server.zig:115-129`
  - New `initial_read_timeout_s` config (default 30s)
  - Prevents slowloris attacks on new connections
  - Switches to keep_alive_timeout after first request

- [x] **12. `setsockopt` Failure Ignored**
  - `Server.zig:setSocketTimeout`
  - Now logs warning on failure via `std.log.warn`

- [x] **13. Fragile `extractContentLength` Matching**
  - `Server.zig:extractContentLength`
  - Replaced with delegation to `extractHeaderValue` for robust matching

- [x] **14. `parseConst` Shared Threadlocal Buffer**
  - `Request.zig:parseConst`
  - Now restricted to test/debug builds via comptime check
  - Production code must use `parse()` with a mutable buffer

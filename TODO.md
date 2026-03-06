# httpz - RFC 2616 Compliance Audit

## Security Vulnerabilities

### HIGH Priority

- [x] **1. TRACE Method Enabled by Default (XST/Credential Theft)**
  - `Connection.zig:50-54, 138-146`
  - TRACE echoes raw request headers (Cookie, Authorization) in response body
  - Fix: Make TRACE off by default, configurable via `Server.Config.enable_trace`

- [x] **2. No URI Validation (Path Traversal)**
  - `Request.zig:246`
  - URIs like `/../../../etc/passwd` or `/%2e%2e/` passed directly to handler
  - Fix: Validate and reject URIs with path traversal patterns including
    percent-encoded and Unicode-escaped variants

- [x] **3. Incomplete Content-Length Conflict Detection (Request Smuggling)**
  - `Request.zig:210-214`
  - Only checks first 2 Content-Length headers; 3+ headers can bypass detection
  - Fix: Check all Content-Length values against each other

- [x] **4. Open Proxy via CONNECT (SSRF/Abuse)**
  - `Server.zig:174-177, 216-306`
  - No access control on CONNECT targets when `enable_proxy` is true
  - Fix: Add proxy config with allowed ports, blocked private IPs,
    optional authentication, target allow-lists

### MEDIUM Priority

- [ ] **5. Stack-Allocated 1 MiB Request Buffer (Stack Overflow)**
  - `Server.zig:85`
  - Each connection uses ~1.1 MiB stack; can overflow under load
  - Fix: Use heap allocation

- [ ] **6. No Connection Limit (DoS)**
  - `Server.zig:56-68`
  - No cap on concurrent connections; slowloris vulnerable
  - Fix: Add `max_connections` to Config with atomic counter

- [ ] **7. Chunked Body No Per-Chunk Size Limit**
  - `Server.zig:347-388`
  - Individual chunk sizes not validated before read attempt
  - Fix: Validate chunk size against remaining buffer

- [ ] **8. Threadlocal Buffer Lifetime (Via/Date headers)**
  - `Proxy.zig:36-57`, `Connection.zig:122-126`
  - Response must be serialized on same thread or data corrupts
  - Fix: Document constraint or use caller-provided buffers

- [ ] **9. Silent Error Swallowing (`catch {}`)**
  - Multiple files
  - Critical headers (Connection: close, Date) silently dropped if header slots full
  - Fix: Reserve header slots or use `catch unreachable` for server headers

### LOW Priority

- [ ] **10. No Host Header Value Validation**
  - `Request.zig:183-197`
  - Host header accepts arbitrary characters
  - Fix: Validate hostname pattern

- [ ] **11. No Initial Request Read Timeout**
  - `Server.zig:76-78`
  - Only keep-alive timeout set; first read can block indefinitely
  - Fix: Apply separate initial timeout

- [ ] **12. `setsockopt` Failure Ignored**
  - `Server.zig:469`
  - Timeout may silently not be set
  - Fix: Log or return error

- [ ] **13. Fragile `extractContentLength` Matching**
  - `Server.zig:424-433`
  - Quick extraction could mismatch with full parser (smuggling risk)
  - Fix: More robust matching

- [ ] **14. `parseConst` Shared Threadlocal Buffer**
  - `Request.zig:610-616`
  - Concurrent calls on same thread corrupt data
  - Fix: Restrict to test builds

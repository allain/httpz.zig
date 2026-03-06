# httpz - RFC 2616 Compliance Audit

## Security Vulnerabilities

### MEDIUM Priority

- [x] **5. Stack-Allocated 1 MiB Request Buffer (Stack Overflow)**
  - `Server.zig:85`
  - Each connection uses ~1.1 MiB stack; can overflow under load
  - Fix: Heap-allocate request buffer via `page_allocator` using `config.max_request_size`

- [x] **6. No Connection Limit (DoS)**
  - `Server.zig:56-68`
  - No cap on concurrent connections; slowloris vulnerable
  - Fix: `max_connections: u32 = 512` with `std.atomic.Value(u32)` counter

- [x] **7. Chunked Body No Per-Chunk Size Limit**
  - `Server.zig:347-388`
  - Individual chunk sizes not validated before read attempt
  - Fix: Parse and validate each chunk-size against remaining buffer space

- [x] **8. Threadlocal Buffer Lifetime (Via/Date headers)**
  - `Proxy.zig:36-57`, `Connection.zig:122-126`
  - Response must be serialized on same thread or data corrupts
  - Fix: Embedded `server_header_buf` in Response; Via/Date stored there

- [x] **9. Silent Error Swallowing (`catch {}`)**
  - Multiple files
  - Critical headers (Connection: close, Date) silently dropped if header slots full
  - Fix: `Headers.appendServer()` uses reserved slots, asserts on overflow;
    `Headers.reserved_headers = 8` guarantees space for server headers

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

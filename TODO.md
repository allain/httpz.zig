# httpz TLS Support (RFC 2818)

## Overview

RFC 2818 "HTTP Over TLS" defines how to use TLS to secure HTTP connections.

## Requirements (RFC 2818)

### 1. Connection Initiation
**Section 2.1** - IN PROGRESS

- [x] Client acts as TLS client, initiates connection to server on appropriate port
- [x] Send TLS ClientHello to begin TLS handshake  
- [ ] After TLS handshake completes, send HTTP request as TLS "application_data"
- [x] Follow normal HTTP behavior (retained connections, etc.)

### 2. Connection Closure
**Section 2.2** - PENDING

- [ ] TLS provides secure connection closure with closure alerts
- [ ] Must initiate exchange of closure alerts before closing connection
- [ ] Implement incomplete close detection - MUST NOT reuse session after premature close
- [ ] Client: treat premature closes as errors, data potentially truncated
- [ ] Server: attempt to initiate closure alert exchange before closing

### 3. Port Number
**Section 2.3** - DONE

- [x] Default HTTPS port is 443
- [x] TLS presumes reliable connection-oriented data stream

### 4. URI Format
**Section 2.4** - DONE

- [x] Support `https://` protocol identifier in URIs
- [x] Parse https URLs and automatically use TLS

### 5. Server Identity
**Section 3.1** - PENDING

- [ ] Verify server hostname against certificate
- [ ] Check subjectAltName extension (dNSName preferred)
- [ ] Fall back to Common Name (deprecated)
- [ ] Support wildcard matching (*.example.com)
- [ ] For IP URIs, match against iPAddress subjectAltName
- [ ] Reject certificate on mismatch (with user-facing warning option)

### 6. Client Identity
**Section 3.2** - PENDING

- [ ] Validate certificate chain is rooted in trusted CA

## Current Status

### Tls.zig - Skeleton Implementation
A minimal TLS 1.3 client skeleton exists at `src/client/Tls.zig` but requires:
1. Complete TLS 1.3 handshake implementation
2. Key derivation (HKDF)
3. X.509 certificate chain validation
4. Hostname verification
5. Proper cipher suite implementation

### Implementation Options

**Option A: Full Zig Implementation**
- Implement TLS 1.3 per RFC 8446
- Use std.crypto for all primitives
- ~2000-4000 lines of code

**Option B: Use System TLS Library**
- Link against OpenSSL/libssl via C interop
- Use system certificates
- Simpler integration

**Option C: Minimal HTTPS Support**
- Support only specific cipher suites
- Skip certificate validation (insecure)
- Faster to implement

## Technical Notes

### TLS 1.3 Key Exchange (RFC 8446 Section 8.1)
```
HKDF-Extract(salt, IKM) -> PRK
HKDF-Expand-Label(PRK, label, context, length) -> OKM
```

### Available in Zig 0.16 std.crypto
- AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- SHA-256, SHA-384
- HMAC
- X.509 Certificate parsing (partial)

### Missing from Zig 0.16 std
- TLS protocol state machine
- ASN.1 DER full parsing
- TLS 1.3 key derivation
- Certificate chain validation with root CA store

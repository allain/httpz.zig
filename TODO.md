# httpz TLS Support (RFC 2818)

## Overview

RFC 2818 "HTTP Over TLS" defines how to use TLS to secure HTTP connections.

## Requirements (RFC 2818)

### 1. Connection Initiation
**Section 2.1**

- [ ] Client acts as TLS client, initiates connection to server on appropriate port
- [ ] Send TLS ClientHello to begin TLS handshake
- [ ] After TLS handshake completes, send HTTP request as TLS "application_data"
- [ ] Follow normal HTTP behavior (retained connections, etc.)

### 2. Connection Closure
**Section 2.2**

- [ ] TLS provides secure connection closure with closure alerts
- [ ] Must initiate exchange of closure alerts before closing connection
- [ ] Implement incomplete close detection - MUST NOT reuse session after premature close
- [ ] Client: treat premature closes as errors, data potentially truncated
- [ ] Server: attempt to initiate closure alert exchange before closing

### 3. Port Number
**Section 2.3**

- [ ] Default HTTPS port is 443
- [ ] TLS presumes reliable connection-oriented data stream

### 4. URI Format
**Section 2.4**

- [ ] Support `https://` protocol identifier in URIs
- [ ] Parse https URLs and automatically use TLS

### 5. Server Identity
**Section 3.1**

- [ ] Verify server hostname against certificate
- [ ] Check subjectAltName extension (dNSName preferred)
- [ ] Fall back to Common Name (deprecated)
- [ ] Support wildcard matching (*.example.com)
- [ ] For IP URIs, match against iPAddress subjectAltName
- [ ] Reject certificate on mismatch (with user-facing warning option)

### 6. Client Identity
**Section 3.2**

- [ ] Validate certificate chain is rooted in trusted CA

## Implementation Notes

### TLS Primitives (available in std.crypto)
- AES-GCM, ChaCha20-Poly1305 (encryption)
- SHA-256/384 (handshake)
- X.509 certificate parsing (partial in crypto.Certificate)

### What's NOT available in Zig 0.16 std
- TLS protocol implementation
- ASN.1 DER certificate parsing (full)
- TLS 1.2/1.3 state machines

### Technical approach
1. Implement TLS 1.3 handshake (simpler than 1.2)
2. Implement X.509 certificate chain validation
3. Implement hostname verification per RFC 2818 Section 3.1
4. Implement proper close handling per RFC 2818 Section 2.2

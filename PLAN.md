# HTTP/2 Development Plan for httpz (RFC 9113)

## Current State

- Fully RFC 2616-compliant HTTP/1.1 server and client
- TLS 1.3 via `tls.zig` dependency (no ALPN support yet)
- Binary framing, multiplexing, HPACK — all unimplemented
- Branch `http2` exists but is clean (no work started)

---

## Phase 0: ALPN Negotiation in tls.zig
**Prerequisite — unblocks everything else**

The `tls.zig` dependency defines the ALPN extension type (16) but has zero implementation. Without ALPN, clients and servers cannot negotiate `h2`.

### Tasks
- [x] **Client ALPN** — Add `alpn_protocols: []const []const u8` to client `Options`; write the ALPN extension in `makeClientHello`; parse the server's selected protocol from ServerHello/EncryptedExtensions
- [x] **Server ALPN** — Parse the client's ALPN list in `readClientHello`; select a protocol (server preference order); write the selected protocol in EncryptedExtensions
- [x] **Expose negotiated protocol** — Store `alpn_protocol` on `Connection` struct; propagate from handshake through `root.zig` client/server functions and NonBlock API
- [x] **Tests** — h2 negotiation, server preference order, no-ALPN passthrough, no-common-protocol error

### RFC References
- RFC 9113 §3.2 (ALPN required for `h2` over TLS)
- RFC 7301 (ALPN extension format)

---

## Phase 1: Binary Framing Layer
**The foundation everything else builds on**

### Tasks
- [x] **Frame types and constants** (`src/h2/frame.zig`)
  - 9-byte frame header: Length(24) + Type(8) + Flags(8) + Reserved(1) + StreamID(31)
  - All 10 frame types: DATA(0x0), HEADERS(0x1), PRIORITY(0x2), RST_STREAM(0x3), SETTINGS(0x4), PUSH_PROMISE(0x5), PING(0x6), GOAWAY(0x7), WINDOW_UPDATE(0x8), CONTINUATION(0x9)
  - Flag constants: END_STREAM(0x1), END_HEADERS(0x4), PADDED(0x8), PRIORITY(0x20), ACK(0x1)
- [x] **Frame reader** — Parse frame header from `std.Io`, validate length against `SETTINGS_MAX_FRAME_SIZE` (default 16,384; max 16,777,215), dispatch by type
- [x] **Frame writer** — Serialize frame header + payload; convenience writers for SETTINGS, SETTINGS ACK, GOAWAY, WINDOW_UPDATE, RST_STREAM, PING
- [x] **Error codes** (`src/h2/errors.zig`) — All 14 codes: NO_ERROR(0x0) through HTTP_1_1_REQUIRED(0xD); ConnectionError and StreamError types
- [x] **Connection preface handling** — `connection_preface` constant defined; preface detection to be wired in Phase 6

### RFC References
- §4.1 (frame format), §4.2 (frame size), §7 (error codes), §3.4 (connection preface)

---

## Phase 2: HPACK Header Compression
**Mandatory for HTTP/2 — headers cannot be sent uncompressed**

### Tasks
- [x] **Static table** (`src/h2/hpack.zig`) — The 61-entry predefined table from RFC 7541 Appendix A
- [x] **Dynamic table** — Ring buffer with FIFO eviction, configurable max size (default 4,096 bytes via `SETTINGS_HEADER_TABLE_SIZE`)
- [x] **Decoder** — Handle all 3 representation types:
  - Indexed header field (prefix 1, 7-bit index)
  - Literal with incremental indexing (prefix 01, 6-bit)
  - Literal without indexing / never indexed (prefix 0000/0001, 4-bit)
  - Integer decoding with prefix-based variable-length encoding
- [x] **Encoder** — Compress headers using static table lookups + dynamic table insertion; respect `SETTINGS_HEADER_TABLE_SIZE` from peer; emit Dynamic Table Size Update when table size changes
- [x] **Huffman coding** (`src/h2/huffman.zig`) — RFC 7541 Appendix B static Huffman table; encode with 1-bit padding; decode with bit-level tree walk
- [x] **Tests** — RFC 7541 §C.2 (literal representations), §C.3 (requests without Huffman), §C.4 (requests with Huffman), plus Huffman encode verification against RFC byte sequences

### RFC References
- §4.3 (field section compression), §4.3.1 (compression state)
- RFC 7541 (HPACK specification)

---

## Phase 3: Stream Multiplexing & State Machine
**The core of HTTP/2**

### Tasks
- [x] **Stream state machine** (`src/h2/Stream.zig`) — 7 states: idle → open → half-closed(local/remote) → closed, plus reserved(local/remote); recv/send transition methods; CloseReason tracking; isActive/isClosed helpers
- [x] **Stream registry** (`src/h2/StreamRegistry.zig`) — Track active streams by ID (client=odd, server=even); enforce `max_concurrent_streams`; monotonically increasing IDs; GC of closed streams; GOAWAY handling
- [x] **Stream-level I/O** (`src/h2/ConnectionIO.zig`) — `FrameReader` demultiplexes incoming frames and assembles CONTINUATION sequences into complete header blocks; `FrameWriter` splits HEADERS and DATA across multiple frames when exceeding max_frame_size

### RFC References
- §5.1 (stream states), §5.1.1 (stream identifiers), §5.1.2 (concurrency limits)

---

## Phase 4: Flow Control
**Prevents fast senders from overwhelming receivers**

### Tasks
- [x] **Window tracking** — Per-stream and connection-level windows via `Window` struct; initial size 65,535 bytes
- [x] **WINDOW_UPDATE sending** — `FlowController.recordRecv` tracks unacked bytes; triggers update at threshold
- [x] **WINDOW_UPDATE receiving** — `FlowController.recvWindowUpdate` replenishes send window
- [x] **SETTINGS_INITIAL_WINDOW_SIZE** — `Window.adjustInitial` applies delta to existing stream windows
- [x] **Overflow protection** — Window > 2^31-1 = FlowControlError; effective window is min(connection, stream)

### RFC References
- §5.2 (flow control), §6.9 (WINDOW_UPDATE), §6.9.1–6.9.3 (window mechanics)

---

## Phase 5: SETTINGS Negotiation
**Connection-level parameter exchange**

### Tasks
- [x] **SETTINGS frame processing** — `Settings.applyAll` parses payload; `Settings.encode` emits non-default values
- [x] **All 6 defined settings** — header_table_size, enable_push, max_concurrent_streams, initial_window_size, max_frame_size, max_header_list_size with validation
- [x] **ACK mechanism** — `Settings.Sync` tracks pending HPACK encoder table size; defers change until peer ACKs; decoder table size applied immediately on receipt
- [x] **Unknown settings** — Ignored per RFC 9113 §6.5.2

### RFC References
- §6.5 (SETTINGS), §6.5.2 (defined settings), §6.5.3 (synchronization)

---

## Phase 6: Server-Side HTTP/2
**Integrate with existing httpz server**

### Tasks
- [x] **Protocol detection** — After TLS handshake, check ALPN result; if `h2`, enter HTTP/2 mode; h2c via connection preface detection on cleartext
- [x] **H2 connection handler** (`src/server/H2Connection.zig`) — Full frame loop with HPACK decode/encode, stream registry, flow control, settings negotiation
- [x] **Request mapping** — HPACK-decoded pseudo-headers → synthetic HTTP/1.1 request → existing `Request.parse` → handler
- [x] **Response mapping** — `Response` → HPACK-encoded HEADERS frame (`:status` + headers) + DATA frames, with frame splitting for large payloads
- [x] **Prohibited headers** — Connection, Keep-Alive, Transfer-Encoding, Upgrade stripped from both request and response
- [x] **100-continue** — Sends informational `:status: 100` HEADERS when client sends `expect: 100-continue`
- [ ] **Trailers** — Not yet supported (handler API has no trailer field; future enhancement)
- [x] **PING/GOAWAY handling** — PING ACK responses; GOAWAY on protocol errors with last-stream-id
- [x] **Graceful shutdown** — Deferred GOAWAY with NO_ERROR on clean frame loop exit
- [x] **Request body support** — DATA frames buffered per-stream (up to 1 MiB); body included in synthetic request with Content-Length; handler receives full body

### RFC References
- §8.1 (message framing), §8.2 (fields), §8.3 (control data), §9.1 (connection management)

---

## Phase 7: Client-Side HTTP/2
**Extend the existing httpz client**

### Tasks
- [x] **ALPN negotiation** — Client checks `tls_conn.alpn_protocol` after TLS handshake; if `h2`, initializes H2Client
- [x] **Connection preface** — H2Client sends 24-byte magic + SETTINGS, reads server SETTINGS, exchanges ACKs
- [x] **Request sending** — HPACK-encodes pseudo-headers + regular headers into HEADERS frame, sends DATA for body
- [x] **Response receiving** — Reads HEADERS + DATA frames, handles SETTINGS/PING/WINDOW_UPDATE interleaved, skips 1xx informational responses, assembles body from DATA parts
- [x] **Stream multiplexing** — Sequential multiplexing via StreamRegistry (each `request()` uses a new stream ID); concurrent in-flight requests require async I/O (future enhancement)
- [ ] **Prior knowledge mode** — Server supports h2c via preface detection; client h2c requires reader/writer lifetime refactor

### RFC References
- §3.2 (starting h2 over TLS), §3.3 (prior knowledge), §8.3.1 (request pseudo-headers)

---

## Phase 8: Connection Management & Hardening
**Production readiness**

### Tasks
- [x] **Connection reuse** — H2Client persists across multiple `request()` calls on the same connection; each call opens a new stream
- [x] **GOAWAY handling** — Server sends deferred GOAWAY on exit; client breaks response loop on GOAWAY; `StreamRegistry.goaway()` closes affected streams
- [x] **RST_STREAM** — Server and client handle RST_STREAM by updating stream state; neither sends RST in response to RST (RFC 9113 §5.4.2)
- [x] **Idle stream cleanup** — `StreamRegistry.gc()` runs periodically when stream count exceeds threshold
- [x] **Settings timeout** — `Settings.Sync.frameReceived()` counts frames since SETTINGS was sent; GOAWAY with SETTINGS_TIMEOUT after 1000 frames without ACK
- [x] **DoS protection** — Concurrent streams limited by `max_concurrent_streams`; header list size validated against 8KB limit; rapid reset detection with ENHANCE_YOUR_CALM after 100 RST_STREAMs per GC cycle
- [x] **CONNECT method** — Validates CONNECT pseudo-headers (only `:method` + `:authority`, no `:scheme`/`:path`); passes through to handler as `CONNECT host:port HTTP/1.1`

### RFC References
- §5.4 (error handling), §9.1.1 (connection reuse), §10.5 (DoS considerations)

---

## Phase 9: Server Push (Optional)
**Low priority — many clients disable it, and it's being deprecated in practice**

### Tasks
- [ ] **PUSH_PROMISE** — Server sends on an existing client stream; reserves an even-numbered promised stream
- [ ] **Promised response** — Send HEADERS + DATA on the promised stream
- [x] **Client handling** — Client sends `SETTINGS_ENABLE_PUSH=0`; server rejects PUSH_PROMISE from clients as protocol error
- [x] **SETTINGS_ENABLE_PUSH** — H2Client disables push in initial SETTINGS; server checks `peer.enable_push` before pushing (currently never pushes)

### RFC References
- §8.4 (server push), §6.6 (PUSH_PROMISE frame)

---

## File Structure

```
src/
├── h2/
│   ├── frame.zig           # Frame types, parsing, serialization (Phase 1)
│   ├── hpack.zig           # HPACK encoder/decoder + tables (Phase 2)
│   ├── Stream.zig          # Stream state machine (Phase 3)
│   ├── StreamRegistry.zig  # Stream tracking & concurrency (Phase 3)
│   ├── FlowControl.zig     # Window management (Phase 4)
│   ├── Settings.zig        # Settings negotiation (Phase 5)
│   └── errors.zig          # Error codes (Phase 1)
├── server/
│   ├── H2Connection.zig    # HTTP/2 server connection handler (Phase 6)
│   └── Server.zig          # Modified: protocol detection branch (Phase 6)
├── client/
│   └── Client.zig          # Modified: ALPN + h2 request path (Phase 7)
└── root.zig                # Modified: export h2 types (Phase 1+)
```

---

## Key Risks & Considerations

- **tls.zig is a vendored dependency** — ALPN changes (Phase 0) need to be upstreamed or maintained as a fork
- **HPACK is complex** — Use RFC 7541 test vectors extensively; compression bugs corrupt the entire connection
- **Multiplexing changes the concurrency model** — HTTP/1.1 is one-request-per-connection; HTTP/2 needs concurrent stream handling within a single connection
- **Priority signaling is deprecated** — Implement PRIORITY frame parsing for interop but don't invest in complex scheduling (§5.3.2)
- **Server Push is falling out of favor** — Chrome removed support; Phase 9 is truly optional

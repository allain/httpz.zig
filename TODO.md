# httpz - RFC 2616 Compliance TODO

## Major Features

- [x] **Real Date header** (RFC 2616 §14.18) - Use actual current time in RFC 1123 format instead of hardcoded epoch
- [x] **HEAD response handling** (RFC 2616 §9.4) - Return same headers as GET but strip the body during serialization
- [x] **100 Continue** (RFC 2616 §8.2.3) - When `Expect: 100-continue` is present, send `100 Continue` before reading body
- [ ] **Chunked response encoding** (RFC 2616 §3.6.1) - Support sending responses with `Transfer-Encoding: chunked`
- [ ] **Chunked request body in Server** (RFC 2616 §3.6.1) - Wire `parseChunkedBody` into server request reading
- [x] **Transfer-Encoding vs Content-Length precedence** (RFC 2616 §4.4) - When both present, Transfer-Encoding wins
- [x] **Header continuation lines** (RFC 2616 §4.2) - LWS at start of line continues the previous header value
- [ ] **OPTIONS method** (RFC 2616 §9.2) - Return `Allow` header listing supported methods
- [ ] **405 Method Not Allowed** (RFC 2616 §10.4.6) - Must include `Allow` header in response
- [ ] **Conditional requests** (RFC 2616 §14.24-28) - `If-Modified-Since`, `If-None-Match`, `If-Match`, `If-Unmodified-Since`, `If-Range`
- [ ] **Range requests** (RFC 2616 §14.35) - `Range` header, `206 Partial Content`, `416 Requested Range Not Satisfiable`
- [ ] **Content negotiation** (RFC 2616 §12) - `Accept`, `Accept-Charset`, `Accept-Encoding`, `Accept-Language`
- [ ] **Connection hop-by-hop header removal** (RFC 2616 §13.5.1) - Remove hop-by-hop headers
- [ ] **Persistent connection pipelining** (RFC 2616 §8.1.2.2) - Multiple requests on one connection processed in order
- [ ] **Request timeout** (RFC 2616 §8.1.4) - Close idle connections after timeout
- [x] **414 URI Too Long** (RFC 2616 §10.4.15) - Return 414 when request URI exceeds max length

## Minor / Edge Cases

- [ ] **CONNECT method** (RFC 2616 §9.9) - Tunneling for proxies
- [ ] **Absolute URI to Host mapping** (RFC 2616 §5.2) - Extract host from absolute URI if Host header missing
- [x] **HTTP/1.0 version downgrade** (RFC 2616 §3.1) - Respond with HTTP/1.0 to HTTP/1.0 clients
- [ ] **Trailer header in chunked** (RFC 2616 §14.40) - Proper trailer header handling
- [ ] **Multipart body parsing** (RFC 2616 §3.7.2)
- [ ] **Via header** (RFC 2616 §14.45) - For proxies

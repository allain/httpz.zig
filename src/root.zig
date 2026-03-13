/// httpz - An HTTP/1.1 server implementation in Zig 0.16
///
/// Implements RFC 2616 (HTTP/1.1) with the new std.Io async model.
///
/// Public API:
/// - Server: TCP listener and connection manager
/// - Client: HTTP/1.1 client
/// - Request: HTTP request parser
/// - Response: HTTP response builder
/// - Headers: HTTP header storage
pub const Server = @import("server/Server.zig");
pub const Client = @import("client/Client.zig");
pub const Request = @import("Request.zig");
pub const Response = @import("Response.zig");
pub const Headers = @import("Headers.zig");

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}

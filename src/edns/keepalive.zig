const std = @import("std");

pub const Error = error{InvalidKeepalive};

/// RFC 7828 TCP Keepalive option semantics.
/// Query form has no payload; response form carries a 16-bit timeout in
/// units of 100 milliseconds.
pub const Keepalive = union(enum) {
    request,
    timeout: u16,

    pub fn timeoutMilliseconds(self: Keepalive) ?u32 {
        return switch (self) {
            .request => null,
            .timeout => |units| @as(u32, units) * 100,
        };
    }
};

pub fn parse(data: []const u8) Error!Keepalive {
    return switch (data.len) {
        0 => .request,
        2 => .{ .timeout = std.mem.readInt(u16, data[0..2], .big) },
        else => error.InvalidKeepalive,
    };
}

test "RFC 7828 keepalive payload forms" {
    try std.testing.expectEqual(Keepalive.request, try parse(&.{}));
    const timeout = try parse(&.{ 0x00, 0x25 });
    try std.testing.expectEqual(@as(u16, 37), timeout.timeout);
    try std.testing.expectEqual(@as(?u32, 3700), timeout.timeoutMilliseconds());
    try std.testing.expectError(error.InvalidKeepalive, parse(&.{0}));
    try std.testing.expectError(error.InvalidKeepalive, parse(&.{ 0, 1, 2 }));
}

const std = @import("std");
const name = @import("../name.zig");

pub const Error = error{InvalidChain};

/// RFC 7901 CHAIN option payload.
///
/// A zero-length payload is capability discovery/refusal. A non-empty payload
/// is one complete, uncompressed FQDN naming the closest trust point.
pub const Chain = union(enum) {
    discovery,
    closest_trust_point: name.Uncompressed,
};

pub fn parse(data: []const u8) Error!Chain {
    if (data.len == 0) return .discovery;
    const trust_point = name.Uncompressed.init(data) catch return error.InvalidChain;
    return .{ .closest_trust_point = trust_point };
}

test "RFC 7901 CHAIN parses discovery and uncompressed trust point" {
    try std.testing.expectEqual(Chain.discovery, try parse(&.{}));

    const wire = [_]u8{ 3, 'c', 'o', 'm', 0 };
    const chain = try parse(&wire);
    try std.testing.expectEqualSlices(u8, &wire, chain.closest_trust_point.bytes);
}

test "RFC 7901 CHAIN rejects compressed partial and trailing names" {
    try std.testing.expectError(error.InvalidChain, parse(&.{ 0xc0, 0x00 }));
    try std.testing.expectError(error.InvalidChain, parse(&.{ 3, 'c', 'o', 'm' }));
    try std.testing.expectError(error.InvalidChain, parse(&.{ 1, 'a', 0, 0 }));
}

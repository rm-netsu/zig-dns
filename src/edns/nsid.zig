const std = @import("std");

/// RFC 5001 NSID semantics.
///
/// Request payload bytes are deliberately not exposed: RFC 5001 requires a
/// compliant resolver to send an empty request, but also requires a receiving
/// name server to ignore payload bytes if a peer sends them anyway.
pub const Nsid = union(enum) {
    request,
    response: []const u8,
};

pub fn parse(data: []const u8, response: bool) Nsid {
    return if (response) .{ .response = data } else .request;
}

test "RFC 5001 request ignores peer payload while response stays opaque" {
    try std.testing.expectEqual(Nsid.request, parse(&.{ 0xde, 0xad }, false));
    const response = parse(&.{ 0, 1, 0xff }, true);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 0xff }, response.response);
}

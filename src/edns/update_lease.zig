const std = @import("std");

pub const Error = error{InvalidUpdateLease};

/// RFC 9664 Update Lease payload.
/// `key_lease` selects the 8-byte form used when KEY RRs need a distinct
/// lease duration; null selects the 4-byte form applying one lease to all RRs.
pub const UpdateLease = struct {
    lease: u32,
    key_lease: ?u32 = null,

    pub fn wireLength(self: UpdateLease) usize {
        return if (self.key_lease == null) 4 else 8;
    }
};

pub fn parse(data: []const u8) Error!UpdateLease {
    return switch (data.len) {
        4 => .{ .lease = std.mem.readInt(u32, data[0..4], .big) },
        8 => .{
            .lease = std.mem.readInt(u32, data[0..4], .big),
            .key_lease = std.mem.readInt(u32, data[4..8], .big),
        },
        else => error.InvalidUpdateLease,
    };
}

pub fn write(value: UpdateLease, out: []u8) error{NoSpace}![]const u8 {
    const len = value.wireLength();
    if (out.len < len) return error.NoSpace;
    std.mem.writeInt(u32, out[0..4], value.lease, .big);
    if (value.key_lease) |key_lease| std.mem.writeInt(u32, out[4..8], key_lease, .big);
    return out[0..len];
}

test "RFC 9664 Update Lease 4-byte and 8-byte forms" {
    var out: [8]u8 = undefined;
    const short = try write(.{ .lease = 3600 }, &out);
    try std.testing.expectEqual(@as(usize, 4), short.len);
    try std.testing.expectEqual(@as(u32, 3600), (try parse(short)).lease);

    const full = try write(.{ .lease = 7200, .key_lease = 86_400 }, &out);
    const parsed = try parse(full);
    try std.testing.expectEqual(@as(u32, 7200), parsed.lease);
    try std.testing.expectEqual(@as(?u32, 86_400), parsed.key_lease);

    try std.testing.expectError(error.InvalidUpdateLease, parse(&.{ 0, 0, 0, 1, 0 }));
}

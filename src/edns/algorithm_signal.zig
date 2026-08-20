const std = @import("std");

/// Borrowed RFC 6975 algorithm-understood list. Each byte is an IANA
/// algorithm/hash registry value. Ordering is explicitly not a preference.
pub const List = struct {
    algorithms: []const u8,

    pub fn count(self: List) usize {
        return self.algorithms.len;
    }

    pub fn iterator(self: List) Iterator {
        return .{ .algorithms = self.algorithms };
    }

    pub fn contains(self: List, algorithm: u8) bool {
        return std.mem.indexOfScalar(u8, self.algorithms, algorithm) != null;
    }
};

pub const Iterator = struct {
    algorithms: []const u8,
    pos: usize = 0,

    pub fn next(self: *Iterator) ?u8 {
        if (self.pos == self.algorithms.len) return null;
        const value = self.algorithms[self.pos];
        self.pos += 1;
        return value;
    }
};

/// RFC 6975 has no additional on-wire framing beyond the EDNS option length:
/// each payload octet is one algorithm code. Receiving servers are allowed to
/// ignore registry-reserved values, so parsing deliberately preserves every
/// byte instead of baking a time-sensitive IANA registry snapshot into the
/// protocol layer.
pub fn parse(data: []const u8) List {
    return .{ .algorithms = data };
}

test "RFC 6975 list is borrowed ordered signaling not preference" {
    const bytes = [_]u8{ 15, 8, 13 };
    const list = parse(&bytes);
    try std.testing.expectEqual(@as(usize, 3), list.count());
    try std.testing.expect(list.contains(8));
    try std.testing.expect(!list.contains(14));

    var it = list.iterator();
    try std.testing.expectEqual(@as(?u8, 15), it.next());
    try std.testing.expectEqual(@as(?u8, 8), it.next());
    try std.testing.expectEqual(@as(?u8, 13), it.next());
    try std.testing.expectEqual(@as(?u8, null), it.next());
}

test "RFC 6975 receiver preserves empty and future-code lists" {
    try std.testing.expectEqual(@as(usize, 0), parse(&.{}).count());
    const future = parse(&.{ 0, 200, 254 });
    try std.testing.expectEqual(@as(usize, 3), future.count());
}

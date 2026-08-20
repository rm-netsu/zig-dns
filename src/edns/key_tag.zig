const std = @import("std");

pub const Error = error{InvalidKeyTag};

/// Borrowed RFC 8145 edns-key-tag list in network byte order.
pub const List = struct {
    data: []const u8,

    pub fn count(self: List) usize {
        return self.data.len / 2;
    }

    pub fn iterator(self: List) Iterator {
        return .{ .data = self.data };
    }

    pub fn contains(self: List, key_tag: u16) bool {
        var it = self.iterator();
        while (it.next()) |value| if (value == key_tag) return true;
        return false;
    }
};

pub const Iterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn next(self: *Iterator) ?u16 {
        if (self.pos == self.data.len) return null;
        const value = std.mem.readInt(u16, self.data[self.pos..][0..2], .big);
        self.pos += 2;
        return value;
    }
};

/// RFC 8145 requires one or more 16-bit Key Tag values.
pub fn parse(data: []const u8) Error!List {
    if (data.len < 2 or (data.len & 1) != 0) return error.InvalidKeyTag;
    return .{ .data = data };
}

test "RFC 8145 key tag list parses without allocation" {
    const list = try parse(&.{ 0x4a, 0x5c, 0x30, 0x39 });
    try std.testing.expectEqual(@as(usize, 2), list.count());
    try std.testing.expect(list.contains(19036));
    try std.testing.expect(list.contains(12345));

    var it = list.iterator();
    try std.testing.expectEqual(@as(?u16, 19036), it.next());
    try std.testing.expectEqual(@as(?u16, 12345), it.next());
    try std.testing.expectEqual(@as(?u16, null), it.next());
}

test "RFC 8145 key tag list rejects empty and partial tags" {
    try std.testing.expectError(error.InvalidKeyTag, parse(&.{}));
    try std.testing.expectError(error.InvalidKeyTag, parse(&.{0x4a}));
    try std.testing.expectError(error.InvalidKeyTag, parse(&.{ 0x4a, 0x5c, 0x30 }));
}

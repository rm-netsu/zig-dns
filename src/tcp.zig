const std = @import("std");

pub const Error = error{ MessageTooLarge, BufferTooSmall, UnexpectedEof };

pub fn frame(message: []const u8, out: []u8) Error![]const u8 {
    if (message.len > std.math.maxInt(u16)) return error.MessageTooLarge;
    if (out.len < message.len + 2) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[0..2], @intCast(message.len), .big);
    @memcpy(out[2..][0..message.len], message);
    return out[0 .. message.len + 2];
}

pub const Decoder = struct {
    storage: []u8,
    prefix: [2]u8 = undefined,
    prefix_len: u2 = 0,
    expected: ?u16 = null,
    len: usize = 0,

    pub const Event = union(enum) { need_more, message: []const u8 };
    pub const Feed = struct { consumed: usize, event: Event };

    pub fn init(storage: []u8) Decoder {
        return .{ .storage = storage };
    }

    pub fn isIdle(self: *const Decoder) bool {
        return self.prefix_len == 0 and self.expected == null and self.len == 0;
    }

    pub fn pendingMessageLength(self: *const Decoder) ?u16 {
        return self.expected;
    }

    pub fn finish(self: *const Decoder) Error!void {
        if (!self.isIdle()) return error.UnexpectedEof;
    }

    pub fn feed(self: *Decoder, input: []const u8) Error!Feed {
        var used: usize = 0;
        while (self.prefix_len < 2 and used < input.len) {
            self.prefix[self.prefix_len] = input[used];
            self.prefix_len += 1;
            used += 1;
        }
        if (self.prefix_len < 2) return .{ .consumed = used, .event = .need_more };
        if (self.expected == null) {
            self.expected = std.mem.readInt(u16, &self.prefix, .big);
            if (self.expected.? > self.storage.len) return error.BufferTooSmall;
        }
        const want: usize = self.expected.? - self.len;
        const take = @min(want, input.len - used);
        if (take != 0) {
            @memcpy(self.storage[self.len..][0..take], input[used..][0..take]);
            self.len += take;
            used += take;
        }
        if (self.len != self.expected.?) return .{ .consumed = used, .event = .need_more };
        const msg = self.storage[0..self.len];
        self.prefix_len = 0;
        self.expected = null;
        self.len = 0;
        return .{ .consumed = used, .event = .{ .message = msg } };
    }
};

test "tcp decoder handles fragmentation and coalescing" {
    var storage: [64]u8 = undefined;
    var d = Decoder.init(&storage);
    const a = try d.feed(&.{0});
    try std.testing.expect(a.event == .need_more);
    const b = try d.feed(&.{ 3, 1, 2, 3, 0, 1, 9 });
    try std.testing.expectEqual(@as(usize, 4), b.consumed);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, b.event.message);
    const c = try d.feed((&[_]u8{ 0, 1, 9 })[0..]);
    try std.testing.expectEqualSlices(u8, &.{9}, c.event.message);
}

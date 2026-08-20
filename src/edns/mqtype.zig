const std = @import("std");
const types = @import("../types.zig");

pub const Error = error{InvalidMultipleQtype};

/// Borrowed RFC 10029 QTYPE list. The list is kept in network byte order so
/// parsing requires no allocation and future data RRTYPE values are preserved.
pub const List = struct {
    data: []const u8,

    pub fn count(self: List) usize {
        return self.data.len / 2;
    }

    pub fn iterator(self: List) Iterator {
        return .{ .data = self.data };
    }

    /// Validate duplicate/primary-QTYPE constraints using caller-owned fixed
    /// scratch. `parseQuery` / `parseResponse` have already checked lengths
    /// and that every QTx is a data RRTYPE.
    pub fn validate(self: List, primary: types.Type, scratch: *Scratch) Error!void {
        if (!types.isDataRrType(primary)) return error.InvalidMultipleQtype;
        scratch.reset();
        var it = self.iterator();
        while (it.next()) |rr_type| {
            if (rr_type == primary or !scratch.insert(rr_type)) return error.InvalidMultipleQtype;
        }
    }
};

pub const Iterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn next(self: *Iterator) ?types.Type {
        if (self.pos == self.data.len) return null;
        const value = std.mem.readInt(u16, self.data[self.pos..][0..2], .big);
        self.pos += 2;
        return @enumFromInt(value);
    }
};

/// Exact duplicate-detection scratch for all 65536 RRTYPE values.
///
/// Keeping this caller-owned prevents large hidden stack frames in generic
/// DNS parsing. Ordinary public-DNS use is expected to request only a few
/// additional types, but RFC 10029 leaves the operator work limit policy to
/// the application.
pub const Scratch = struct {
    bits: [1024]u64 = [_]u64{0} ** 1024,

    pub fn reset(self: *Scratch) void {
        @memset(&self.bits, 0);
    }

    fn insert(self: *Scratch, rr_type: types.Type) bool {
        const value: u16 = @intFromEnum(rr_type);
        const word: usize = value >> 6;
        const bit: u6 = @truncate(value);
        const mask = @as(u64, 1) << bit;
        if (self.bits[word] & mask != 0) return false;
        self.bits[word] |= mask;
        return true;
    }
};

pub fn parseQuery(data: []const u8) Error!List {
    return parse(data, false);
}

pub fn parseResponse(data: []const u8) Error!List {
    return parse(data, true);
}

fn parse(data: []const u8, allow_empty: bool) Error!List {
    if ((data.len & 1) != 0 or (!allow_empty and data.len == 0)) return error.InvalidMultipleQtype;
    var pos: usize = 0;
    while (pos < data.len) : (pos += 2) {
        const rr_type: types.Type = @enumFromInt(std.mem.readInt(u16, data[pos..][0..2], .big));
        if (!types.isDataRrType(rr_type)) return error.InvalidMultipleQtype;
    }
    return .{ .data = data };
}

/// Validate a caller-provided list before serializing it. This path handles
/// caller-owned input rather than attacker-controlled wire data, so a compact
/// pairwise duplicate check avoids forcing 8 KiB scratch on simple builders.
pub fn validateSlice(qtypes: []const types.Type, primary: types.Type, allow_empty: bool) Error!void {
    if (!types.isDataRrType(primary) or (!allow_empty and qtypes.len == 0)) return error.InvalidMultipleQtype;
    if (qtypes.len > std.math.maxInt(u16) / 2) return error.InvalidMultipleQtype;
    for (qtypes, 0..) |rr_type, i| {
        if (!types.isDataRrType(rr_type) or rr_type == primary) return error.InvalidMultipleQtype;
        for (qtypes[0..i]) |previous| {
            if (rr_type == previous) return error.InvalidMultipleQtype;
        }
    }
}

test "RFC 10029 A and additional AAAA HTTPS list" {
    const wire = [_]u8{ 0x00, 0x1c, 0x00, 0x41 };
    const list = try parseQuery(&wire);
    try std.testing.expectEqual(@as(usize, 2), list.count());
    var scratch: Scratch = .{};
    try list.validate(.A, &scratch);

    var it = list.iterator();
    try std.testing.expectEqual(types.Type.AAAA, it.next().?);
    try std.testing.expectEqual(types.Type.HTTPS, it.next().?);
    try std.testing.expectEqual(@as(?types.Type, null), it.next());
}

test "MQTYPE response may be empty while query may not" {
    try std.testing.expectError(error.InvalidMultipleQtype, parseQuery(&.{}));
    const response = try parseResponse(&.{});
    try std.testing.expectEqual(@as(usize, 0), response.count());
}

test "MQTYPE rejects meta primary values duplicate QTx and non-data QTx" {
    var scratch: Scratch = .{};
    const duplicate = try parseQuery(&.{ 0x00, 0x1c, 0x00, 0x1c });
    try std.testing.expectError(error.InvalidMultipleQtype, duplicate.validate(.A, &scratch));

    const primary_duplicate = try parseQuery(&.{ 0x00, 0x01 });
    try std.testing.expectError(error.InvalidMultipleQtype, primary_duplicate.validate(.A, &scratch));
    try std.testing.expectError(error.InvalidMultipleQtype, duplicate.validate(.ANY, &scratch));
    try std.testing.expectError(error.InvalidMultipleQtype, parseQuery(&.{ 0x00, 0xff }));
    try std.testing.expectError(error.InvalidMultipleQtype, parseQuery(&.{0}));
}

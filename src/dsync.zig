const std = @import("std");
const message = @import("message.zig");
const name_mod = @import("name.zig");
const types = @import("types.zig");

pub const Error = error{ WrongType, InvalidDsync, DuplicateEndpoint };

/// RFC 9859 DSYNC scheme registry. Values 128..255 are private use and
/// unassigned/future standard values remain representable through `_`.
pub const Scheme = enum(u8) {
    null_scheme = 0,
    notify = 1,
    _,

    pub fn isPrivate(self: Scheme) bool {
        return @intFromEnum(self) >= 128;
    }
};

pub const Record = struct {
    notification_type: types.Type,
    scheme: Scheme,
    port: u16,
    target: name_mod.Uncompressed,

    /// Returns the currently standardized RFC 9859 NOTIFY endpoint, or null
    /// when consumers are required to ignore the record or the combination is
    /// not understood by this library version.
    pub fn notifyEndpoint(self: Record) ?NotifyEndpoint {
        if (self.scheme != .notify or self.port == 0) return null;
        const kind: NotifyKind = switch (self.notification_type) {
            .CDS => .cds,
            .CSYNC => .csync,
            else => return null,
        };
        return .{ .kind = kind, .port = self.port, .target = self.target };
    }
};

pub const NotifyKind = enum {
    cds,
    csync,

    pub fn rrType(self: NotifyKind) types.Type {
        return switch (self) {
            .cds => .CDS,
            .csync => .CSYNC,
        };
    }
};

pub const NotifyEndpoint = struct {
    kind: NotifyKind,
    port: u16,
    target: name_mod.Uncompressed,
};

pub fn parse(rr: message.Record) Error!Record {
    if (rr.rr_type != .DSYNC) return error.WrongType;
    return parseRdata(rr.rdata);
}

/// Parse DSYNC RDATA without requiring a complete DNS message. This is useful
/// for fuzzing and for callers that already extracted opaque RDATA elsewhere.
pub fn parseRdata(data: []const u8) error{InvalidDsync}!Record {
    if (data.len < 6) return error.InvalidDsync;
    const target = name_mod.Uncompressed.init(data[5..]) catch return error.InvalidDsync;
    return .{
        .notification_type = @enumFromInt(std.mem.readInt(u16, data[0..2], .big)),
        .scheme = @enumFromInt(data[2]),
        .port = std.mem.readInt(u16, data[3..5], .big),
        .target = target,
    };
}

/// Validate RFC 9859's per-owner uniqueness rule for an already-grouped DSYNC
/// RRset. The caller owns RRset grouping; this helper checks only the required
/// (notification type, scheme) uniqueness and each record's RDATA structure.
pub fn validateUnique(records: []const message.Record) Error!void {
    for (records, 0..) |rr, i| {
        const current = try parse(rr);
        for (records[0..i]) |previous_rr| {
            const previous = try parse(previous_rr);
            if (current.notification_type == previous.notification_type and current.scheme == previous.scheme) {
                return error.DuplicateEndpoint;
            }
        }
    }
}

test "RFC 9859 DSYNC parses uncompressed future-compatible endpoint" {
    const wire = [_]u8{
        0x00, 0x3b, // CDS
        0x01, // NOTIFY
        0x14, 0xef, // 5359
        3,    'c',
        'd',  's',
        7,    's',
        'c',  'a',
        'n',  'n',
        'e',  'r',
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'n',
        'e',  't',
        0,
    };
    const parsed = try parseRdata(&wire);
    try std.testing.expectEqual(types.Type.CDS, parsed.notification_type);
    try std.testing.expectEqual(Scheme.notify, parsed.scheme);
    try std.testing.expectEqual(@as(u16, 5359), parsed.port);
    const endpoint = parsed.notifyEndpoint().?;
    try std.testing.expectEqual(NotifyKind.cds, endpoint.kind);
    try std.testing.expectEqualSlices(u8, wire[5..], endpoint.target.bytes);

    var future = wire;
    future[0] = 0x12;
    future[1] = 0x34;
    future[2] = 42;
    const preserved = try parseRdata(&future);
    try std.testing.expectEqual(@as(u16, 0x1234), @intFromEnum(preserved.notification_type));
    try std.testing.expectEqual(@as(u8, 42), @intFromEnum(preserved.scheme));
    try std.testing.expect(preserved.notifyEndpoint() == null);
}

test "DSYNC consumer ignores null scheme zero port and unsupported notify type" {
    const target = [_]u8{ 2, 'n', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    var wire: [5 + target.len]u8 = undefined;
    std.mem.writeInt(u16, wire[0..2], @intFromEnum(types.Type.CDS), .big);
    wire[2] = 0;
    std.mem.writeInt(u16, wire[3..5], 53, .big);
    @memcpy(wire[5..], &target);
    try std.testing.expect((try parseRdata(&wire)).notifyEndpoint() == null);

    wire[2] = 1;
    std.mem.writeInt(u16, wire[3..5], 0, .big);
    try std.testing.expect((try parseRdata(&wire)).notifyEndpoint() == null);

    std.mem.writeInt(u16, wire[0..2], @intFromEnum(types.Type.A), .big);
    std.mem.writeInt(u16, wire[3..5], 53, .big);
    try std.testing.expect((try parseRdata(&wire)).notifyEndpoint() == null);
}

test "DSYNC rejects compressed partial and trailing target names" {
    try std.testing.expectError(error.InvalidDsync, parseRdata(&.{ 0, 59, 1, 0, 53, 0xc0, 0x00 }));
    try std.testing.expectError(error.InvalidDsync, parseRdata(&.{ 0, 59, 1, 0, 53, 3, 'c', 'o', 'm' }));
    try std.testing.expectError(error.InvalidDsync, parseRdata(&.{ 0, 59, 1, 0, 53, 0, 0 }));
}

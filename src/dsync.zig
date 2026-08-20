const std = @import("std");
const message = @import("message.zig");
const name_mod = @import("name.zig");
const types = @import("types.zig");

pub const Error = error{ WrongType, InvalidDsync, DuplicateEndpoint };
pub const DiscoveryError = error{ NoSpace, NameTooLong, InvalidDelegation, InvalidDiscoveryName, UnrelatedParent };

const dsync_label = [_]u8{ 6, '_', 'd', 's', 'y', 'n', 'c' };

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

/// Build RFC 9859 section 4.1's first endpoint-discovery lookup by inserting
/// `_dsync` after the first label of the delegation owner. The operation is
/// transactional with respect to `out`: failures leave it untouched.
pub fn initialLookupName(delegation: name_mod.Uncompressed, out: []u8) DiscoveryError!name_mod.Uncompressed {
    if (delegation.bytes.len == 1) return error.InvalidDelegation;
    const first_len: usize = delegation.bytes[0];
    const insert_at = 1 + first_len;
    const total = delegation.bytes.len + dsync_label.len;
    if (total > name_mod.Name.max_wire_len) return error.NameTooLong;
    if (out.len < total) return error.NoSpace;

    var tmp: [name_mod.Name.max_wire_len]u8 = undefined;
    @memcpy(tmp[0..insert_at], delegation.bytes[0..insert_at]);
    @memcpy(tmp[insert_at..][0..dsync_label.len], &dsync_label);
    @memcpy(tmp[insert_at + dsync_label.len ..][0 .. delegation.bytes.len - insert_at], delegation.bytes[insert_at..]);
    _ = name_mod.Uncompressed.init(tmp[0..total]) catch return error.InvalidDiscoveryName;

    @memcpy(out[0..total], tmp[0..total]);
    return .{ .bytes = out[0..total] };
}

/// Continue RFC 9859 section 4.1 after an authenticated negative DSYNC answer.
/// `soa_owner` is the enclosing parent zone inferred from that negative
/// response. Returns null when no further discovery name exists.
///
/// DNSSEC validation and negative-answer classification remain caller-owned;
/// this helper only performs the bounded DNS-name transformation.
pub fn nextLookupAfterNegative(
    current: name_mod.Uncompressed,
    soa_owner: name_mod.Uncompressed,
    out: []u8,
) DiscoveryError!?name_mod.Uncompressed {
    var current_offsets: [127]u8 = undefined;
    const current_count = labelOffsets(current.bytes, &current_offsets);
    var parent_offsets: [127]u8 = undefined;
    const parent_count = labelOffsets(soa_owner.bytes, &parent_offsets);

    var marker_index: ?usize = null;
    for (current_offsets[0..current_count], 0..) |offset_u8, i| {
        const offset: usize = offset_u8;
        const len: usize = current.bytes[offset];
        if (len != 6) continue;
        if (!std.ascii.eqlIgnoreCase(current.bytes[offset + 1 ..][0..6], "_dsync")) continue;
        if (marker_index != null) return error.InvalidDiscoveryName;
        marker_index = i;
    }
    const marker = marker_index orelse return error.InvalidDiscoveryName;

    if (parent_count > current_count) return error.UnrelatedParent;
    const parent_start = current_count - parent_count;
    if (parent_start <= marker) return error.UnrelatedParent;
    for (0..parent_count) |i| {
        const current_off: usize = current_offsets[parent_start + i];
        const parent_off: usize = parent_offsets[i];
        const current_len: usize = current.bytes[current_off];
        const parent_len: usize = soa_owner.bytes[parent_off];
        if (current_len != parent_len) return error.UnrelatedParent;
        if (!std.ascii.eqlIgnoreCase(
            current.bytes[current_off + 1 ..][0..current_len],
            soa_owner.bytes[parent_off + 1 ..][0..parent_len],
        )) return error.UnrelatedParent;
    }

    const marker_start: usize = current_offsets[marker];
    const marker_end = marker_start + dsync_label.len;

    if (parent_start - marker > 1) {
        const parent_start_byte: usize = if (parent_count == 0)
            current.bytes.len - 1
        else
            current_offsets[parent_start];
        const insert_at = parent_start_byte - dsync_label.len;
        const delegation_len = current.bytes.len - dsync_label.len;

        var delegation: [name_mod.Name.max_wire_len]u8 = undefined;
        @memcpy(delegation[0..marker_start], current.bytes[0..marker_start]);
        @memcpy(delegation[marker_start..][0 .. current.bytes.len - marker_end], current.bytes[marker_end..]);

        var tmp: [name_mod.Name.max_wire_len]u8 = undefined;
        @memcpy(tmp[0..insert_at], delegation[0..insert_at]);
        @memcpy(tmp[insert_at..][0..dsync_label.len], &dsync_label);
        @memcpy(tmp[insert_at + dsync_label.len ..][0 .. delegation_len - insert_at], delegation[insert_at..delegation_len]);
        const total = delegation_len + dsync_label.len;
        if (out.len < total) return error.NoSpace;
        _ = name_mod.Uncompressed.init(tmp[0..total]) catch return error.InvalidDiscoveryName;
        @memcpy(out[0..total], tmp[0..total]);
        return .{ .bytes = out[0..total] };
    }

    if (marker != 0) {
        const suffix = current.bytes[marker_start..];
        if (out.len < suffix.len) return error.NoSpace;
        @memcpy(out[0..suffix.len], suffix);
        return .{ .bytes = out[0..suffix.len] };
    }

    return null;
}

fn labelOffsets(bytes: []const u8, out: *[127]u8) usize {
    var pos: usize = 0;
    var count: usize = 0;
    while (bytes[pos] != 0) {
        out[count] = @intCast(pos);
        count += 1;
        pos += 1 + @as(usize, bytes[pos]);
    }
    return count;
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

test "RFC 9859 discovery lookup sequence follows parent negative SOA" {
    var child_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const child_wire = try name_mod.writePresentationWire("subsub.sub.child.example", &child_buf);
    const child = try name_mod.Uncompressed.init(child_wire);

    var first_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const first = try initialLookupName(child, &first_buf);
    var first_text: [name_mod.Name.max_presentation_len]u8 = undefined;
    const first_name = try name_mod.Name.init(first.bytes, 0);
    try std.testing.expectEqualStrings("subsub._dsync.sub.child.example", try first_name.writePresentation(&first_text));

    var parent_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const parent = try name_mod.Uncompressed.init(try name_mod.writePresentationWire("example", &parent_buf));
    var second_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const second = (try nextLookupAfterNegative(first, parent, &second_buf)).?;
    var second_text: [name_mod.Name.max_presentation_len]u8 = undefined;
    try std.testing.expectEqualStrings("subsub.sub.child._dsync.example", try (try name_mod.Name.init(second.bytes, 0)).writePresentation(&second_text));

    var final_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const final = (try nextLookupAfterNegative(second, parent, &final_buf)).?;
    var final_text: [name_mod.Name.max_presentation_len]u8 = undefined;
    try std.testing.expectEqualStrings("_dsync.example", try (try name_mod.Name.init(final.bytes, 0)).writePresentation(&final_text));

    var unused: [name_mod.Name.max_wire_len]u8 = undefined;
    try std.testing.expect((try nextLookupAfterNegative(final, parent, &unused)) == null);
}

test "DSYNC discovery names are bounded transactional and parent-scoped" {
    var child_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const child = try name_mod.Uncompressed.init(try name_mod.writePresentationWire("child.example", &child_buf));
    var untouched = [_]u8{0xa5} ** 8;
    try std.testing.expectError(error.NoSpace, initialLookupName(child, &untouched));
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 8), &untouched);

    var current_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const current = try initialLookupName(child, &current_buf);
    var other_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const other = try name_mod.Uncompressed.init(try name_mod.writePresentationWire("other", &other_buf));
    try std.testing.expectError(error.UnrelatedParent, nextLookupAfterNegative(current, other, &untouched));
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 8), &untouched);
}

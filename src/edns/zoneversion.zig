const std = @import("std");
const name = @import("../name.zig");

pub const Error = error{InvalidZoneVersion};

pub const VersionType = enum(u8) {
    soa_serial = 0,
    _,
};

pub const ZoneVersion = union(enum) {
    request,
    response: Response,

    pub const Response = struct {
        label_count: u8,
        version_type: VersionType,
        version: []const u8,

        pub fn soaSerial(self: Response) ?u32 {
            if (self.version_type != .soa_serial or self.version.len != 4) return null;
            return std.mem.readInt(u32, self.version[0..4], .big);
        }

        /// RFC 9660 binds LABELCOUNT to the original QNAME. This helper is
        /// separate from the wire parser because generic EDNS parsing does not
        /// otherwise need access to the DNS Question.
        pub fn validateQname(self: Response, qname: name.Name) (Error || name.Error)!void {
            var wire_buf: [name.Name.max_wire_len]u8 = undefined;
            const wire = try qname.writeWire(&wire_buf);
            var labels: usize = 0;
            var pos: usize = 0;
            while (wire[pos] != 0) {
                labels += 1;
                pos += 1 + wire[pos];
            }
            if (@as(usize, self.label_count) > labels) return error.InvalidZoneVersion;
        }
    };
};

pub fn parse(data: []const u8, response: bool) Error!ZoneVersion {
    if (!response) {
        if (data.len != 0) return error.InvalidZoneVersion;
        return .request;
    }

    if (data.len < 2) return error.InvalidZoneVersion;
    const version_type: VersionType = @enumFromInt(data[1]);
    const version = data[2..];
    if (version_type == .soa_serial and version.len != 4) return error.InvalidZoneVersion;
    return .{ .response = .{
        .label_count = data[0],
        .version_type = version_type,
        .version = version,
    } };
}

pub fn writeRequest(out: []u8) error{NoSpace}![]const u8 {
    return out[0..0];
}

pub fn writeSoaSerial(label_count: u8, serial: u32, out: []u8) error{NoSpace}![]const u8 {
    if (out.len < 6) return error.NoSpace;
    out[0] = label_count;
    out[1] = @intFromEnum(VersionType.soa_serial);
    std.mem.writeInt(u32, out[2..6], serial, .big);
    return out[0..6];
}

test "RFC 9660 query and SOA-SERIAL response forms" {
    try std.testing.expectEqual(ZoneVersion.request, try parse(&.{}, false));
    try std.testing.expectError(error.InvalidZoneVersion, parse(&.{0}, false));

    var out: [6]u8 = undefined;
    const wire = try writeSoaSerial(2, 2_023_073_001, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0x00, 0x78, 0x95, 0xa4, 0xe9 }, wire);
    const parsed = try parse(wire, true);
    try std.testing.expectEqual(@as(u8, 2), parsed.response.label_count);
    try std.testing.expectEqual(@as(?u32, 2_023_073_001), parsed.response.soaSerial());
}

test "ZONEVERSION preserves future version types" {
    const parsed = try parse(&.{ 1, 77, 0xaa, 0xbb }, true);
    try std.testing.expectEqual(@as(u8, 77), @intFromEnum(parsed.response.version_type));
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, parsed.response.version);
}

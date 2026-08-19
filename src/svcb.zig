const std = @import("std");
const message = @import("message.zig");
const name_mod = @import("name.zig");
const rdata = @import("rdata.zig");

pub const ParamKey = enum(u16) {
    mandatory = 0,
    alpn = 1,
    no_default_alpn = 2,
    port = 3,
    ipv4hint = 4,
    ech = 5,
    ipv6hint = 6,
    dohpath = 7,
    ohttp = 8,
    _,
};

pub const Error = rdata.Error || error{ WrongClass, CompressedTarget, InvalidParam, MissingMandatory, InconsistentParams };

pub const AlpnIterator = struct {
    bytes: []const u8,
    pos: usize = 0,
    pub fn next(self: *AlpnIterator) Error!?[]const u8 {
        if (self.pos == self.bytes.len) return null;
        const len: usize = self.bytes[self.pos];
        self.pos += 1;
        if (len == 0 or self.pos + len > self.bytes.len) return error.InvalidParam;
        const value = self.bytes[self.pos..][0..len];
        self.pos += len;
        return value;
    }
};

pub const Validated = struct {
    priority: u16,
    target: name_mod.Name,
    params_bytes: []const u8,
    alias_mode: bool,

    pub fn params(self: Validated) rdata.SvcParamIterator {
        return .{ .bytes = self.params_bytes };
    }
};

pub fn validateRecord(rr: message.Record) Error!Validated {
    if (@intFromEnum(rr.class) != 1) return error.WrongClass;
    if (rr.rdata.len < 3) return error.InvalidParam;
    const target_abs: usize = rr.rdata_offset + 2;
    const target_len = name_mod.uncompressedConsumedLen(rr.packet, target_abs) catch |err| switch (err) {
        error.InvalidLabel => return error.CompressedTarget,
        else => return err,
    };
    if (2 + target_len > rr.rdata.len) return error.InvalidParam;
    const target = try name_mod.Name.init(rr.packet, target_abs);
    const params_bytes = rr.rdata[2 + target_len ..];
    const priority = std.mem.readInt(u16, rr.rdata[0..2], .big);
    if (priority == 0) return .{ .priority = 0, .target = target, .params_bytes = params_bytes, .alias_mode = true };

    var seen_alpn = false;
    var seen_no_default = false;
    var it = rdata.SvcParamIterator{ .bytes = params_bytes };
    while (try it.next()) |p| {
        switch (@as(ParamKey, @enumFromInt(p.key))) {
            .mandatory => try validateMandatory(params_bytes, p.value),
            .alpn => {
                if (p.value.len == 0) return error.InvalidParam;
                var ai: AlpnIterator = .{ .bytes = p.value };
                while (try ai.next()) |_| {}
                seen_alpn = true;
            },
            .no_default_alpn => {
                if (p.value.len != 0) return error.InvalidParam;
                seen_no_default = true;
            },
            .port => if (p.value.len != 2) return error.InvalidParam,
            .ipv4hint => if (p.value.len == 0 or p.value.len % 4 != 0) return error.InvalidParam,
            .ipv6hint => if (p.value.len == 0 or p.value.len % 16 != 0) return error.InvalidParam,
            else => {},
        }
    }
    if (seen_no_default and !seen_alpn) return error.InconsistentParams;
    return .{ .priority = priority, .target = target, .params_bytes = params_bytes, .alias_mode = false };
}

fn validateMandatory(params_bytes: []const u8, value: []const u8) Error!void {
    if (value.len == 0 or value.len % 2 != 0) return error.InvalidParam;
    var prev: ?u16 = null;
    var pos: usize = 0;
    while (pos < value.len) : (pos += 2) {
        const key = std.mem.readInt(u16, value[pos..][0..2], .big);
        if (key == 0) return error.InvalidParam;
        if (prev) |p| if (key <= p) return error.InvalidParam;
        prev = key;
        var found = false;
        var it = rdata.SvcParamIterator{ .bytes = params_bytes };
        while (try it.next()) |param| if (param.key == key) {
            found = true;
            break;
        };
        if (!found) return error.MissingMandatory;
    }
}

test "SVCB validates uncompressed target and params" {
    const Builder = @import("builder.zig").Builder;
    const CompressionEntry = @import("builder.zig").CompressionEntry;
    const msg = @import("message.zig");
    var out: [256]u8 = undefined;
    var ce: [16]CompressionEntry = undefined;
    var b = try Builder.init(&out, &ce, 1, .{ .response = true });
    try b.addQuestion("example.com", .HTTPS, .IN);
    var w = try b.beginRecord(.answer, "example.com", .HTTPS, .IN, 60);
    errdefer w.abort();
    try w.writeU16(1);
    const wire = try name_mod.Uncompressed.init(&.{ 3, 's', 'v', 'c', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 });
    try w.writeWireName(wire);
    try w.writeU16(3);
    try w.writeU16(2);
    try w.writeU16(443);
    try w.finish();
    const bytes = try b.finish();
    const m = try msg.Message.init(bytes);
    var ri = try m.records(.answer);
    const rr = (try ri.next()).?;
    const v = try validateRecord(rr);
    try std.testing.expectEqual(@as(u16, 1), v.priority);
}

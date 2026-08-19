const std = @import("std");
const message = @import("message.zig");

pub const OptionCode = enum(u16) { NSID = 3, DAU = 5, DHU = 6, N3U = 7, ECS = 8, EXPIRE = 9, COOKIE = 10, KEEPALIVE = 11, PADDING = 12, CHAIN = 13, KEY_TAG = 14, EDE = 15, REPORT_CHANNEL = 18, _ };
pub const Error = error{ NotOpt, Truncated, InvalidOption, InvalidClientSubnet };

pub const Flags = packed struct(u16) {
    unassigned: u14 = 0,
    compact_answers_ok: bool = false,
    dnssec_ok: bool = false,

    pub fn fromInt(value: u16) Flags {
        return @bitCast(value);
    }

    pub fn toInt(self: Flags) u16 {
        return @bitCast(self);
    }
};

pub const Opt = struct {
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    flags: Flags,
    options: []const u8,

    pub fn fromRecord(rr: message.Record) Error!Opt {
        if (@intFromEnum(rr.rr_type) != 41) return error.NotOpt;
        return .{
            .udp_payload_size = @intFromEnum(rr.class),
            .extended_rcode = @intCast((rr.ttl >> 24) & 0xff),
            .version = @intCast((rr.ttl >> 16) & 0xff),
            .flags = .fromInt(@truncate(rr.ttl)),
            .options = rr.rdata,
        };
    }

    pub fn iterator(self: Opt) Iterator {
        return .{ .bytes = self.options };
    }

    pub fn dnssecOk(self: Opt) bool {
        return self.flags.dnssec_ok;
    }

    pub fn compactAnswersOk(self: Opt) bool {
        return self.flags.compact_answers_ok;
    }
};

pub const Option = struct { code: OptionCode, data: []const u8 };
pub const Iterator = struct {
    bytes: []const u8,
    pos: usize = 0,
    pub fn next(self: *Iterator) Error!?Option {
        if (self.pos == self.bytes.len) return null;
        if (self.pos + 4 > self.bytes.len) return error.Truncated;
        const code: OptionCode = @enumFromInt(std.mem.readInt(u16, self.bytes[self.pos..][0..2], .big));
        const len = std.mem.readInt(u16, self.bytes[self.pos + 2 ..][0..2], .big);
        self.pos += 4;
        if (self.pos + len > self.bytes.len) return error.Truncated;
        const data = self.bytes[self.pos..][0..len];
        self.pos += len;
        return .{ .code = code, .data = data };
    }
};

pub const ExtendedError = struct { info_code: u16, extra_text: []const u8 };
pub fn extendedError(opt: Option) Error!ExtendedError {
    if (opt.code != .EDE or opt.data.len < 2) return error.InvalidOption;
    return .{ .info_code = std.mem.readInt(u16, opt.data[0..2], .big), .extra_text = opt.data[2..] };
}

pub const ClientSubnet = struct { family: u16, source_prefix: u8, scope_prefix: u8, address: []const u8 };
pub fn clientSubnet(opt: Option) Error!ClientSubnet {
    if (opt.code != .ECS or opt.data.len < 4) return error.InvalidOption;
    const family = std.mem.readInt(u16, opt.data[0..2], .big);
    const source = opt.data[2];
    const scope = opt.data[3];
    const max_bits: u8 = switch (family) {
        1 => 32,
        2 => 128,
        else => return error.InvalidClientSubnet,
    };
    if (source > max_bits or scope > max_bits) return error.InvalidClientSubnet;
    const address_len: usize = (@as(usize, source) + 7) / 8;
    if (4 + address_len != opt.data.len) return error.InvalidClientSubnet;
    if (address_len != 0 and source % 8 != 0) {
        const unused: u3 = @intCast(8 - (source % 8));
        const mask: u8 = (@as(u8, 1) << unused) - 1;
        if ((opt.data[opt.data.len - 1] & mask) != 0) return error.InvalidClientSubnet;
    }
    return .{ .family = family, .source_prefix = source, .scope_prefix = scope, .address = opt.data[4..] };
}

pub const OptionBuilder = struct {
    out: []u8,
    pos: usize = 0,
    pub fn init(out: []u8) OptionBuilder {
        return .{ .out = out };
    }
    pub fn add(self: *OptionBuilder, code: OptionCode, data: []const u8) error{NoSpace}!void {
        if (data.len > std.math.maxInt(u16) or self.pos + 4 + data.len > self.out.len) return error.NoSpace;
        std.mem.writeInt(u16, self.out[self.pos..][0..2], @intFromEnum(code), .big);
        std.mem.writeInt(u16, self.out[self.pos + 2 ..][0..2], @intCast(data.len), .big);
        @memcpy(self.out[self.pos + 4 ..][0..data.len], data);
        self.pos += 4 + data.len;
    }
    pub fn addClientSubnet(self: *OptionBuilder, family: u16, source_prefix: u8, scope_prefix: u8, full_address: []const u8) (error{ NoSpace, InvalidClientSubnet })!void {
        const max_bits: u8 = switch (family) {
            1 => 32,
            2 => 128,
            else => return error.InvalidClientSubnet,
        };
        const full_len: usize = max_bits / 8;
        if (full_address.len != full_len or source_prefix > max_bits or scope_prefix > max_bits) return error.InvalidClientSubnet;
        const address_len: usize = (@as(usize, source_prefix) + 7) / 8;
        if (self.pos + 8 + address_len > self.out.len) return error.NoSpace;
        const start = self.pos;
        std.mem.writeInt(u16, self.out[start..][0..2], @intFromEnum(OptionCode.ECS), .big);
        std.mem.writeInt(u16, self.out[start + 2 ..][0..2], @intCast(4 + address_len), .big);
        std.mem.writeInt(u16, self.out[start + 4 ..][0..2], family, .big);
        self.out[start + 6] = source_prefix;
        self.out[start + 7] = scope_prefix;
        if (address_len != 0) {
            @memcpy(self.out[start + 8 ..][0..address_len], full_address[0..address_len]);
            if (source_prefix % 8 != 0) {
                const remainder: u8 = source_prefix % 8;
                const shift: u3 = @intCast(8 - remainder);
                self.out[start + 8 + address_len - 1] &= @as(u8, 0xff) << shift;
            }
        }
        self.pos += 8 + address_len;
    }

    pub fn addExtendedError(self: *OptionBuilder, info_code: u16, text: []const u8) error{NoSpace}!void {
        if (self.pos + 6 + text.len > self.out.len or text.len > std.math.maxInt(u16) - 2) return error.NoSpace;
        var tmp: [2]u8 = undefined;
        std.mem.writeInt(u16, &tmp, info_code, .big);
        const start = self.pos;
        try self.add(.EDE, &tmp);
        // Extend the just-written EDE option to include optional UTF-8 diagnostic text.
        if (text.len != 0) {
            const old_len = std.mem.readInt(u16, self.out[start + 2 ..][0..2], .big);
            if (self.pos + text.len > self.out.len) return error.NoSpace;
            @memcpy(self.out[self.pos..][0..text.len], text);
            self.pos += text.len;
            std.mem.writeInt(u16, self.out[start + 2 ..][0..2], old_len + @as(u16, @intCast(text.len)), .big);
        }
    }

    pub fn addPadding(self: *OptionBuilder, len: usize) error{NoSpace}!void {
        if (len > std.math.maxInt(u16) or self.pos + 4 + len > self.out.len) return error.NoSpace;
        const start = self.pos;
        self.pos += 4 + len;
        std.mem.writeInt(u16, self.out[start..][0..2], @intFromEnum(OptionCode.PADDING), .big);
        std.mem.writeInt(u16, self.out[start + 2 ..][0..2], @intCast(len), .big);
        @memset(self.out[start + 4 ..][0..len], 0);
    }

    pub fn bytes(self: OptionBuilder) []const u8 {
        return self.out[0..self.pos];
    }
};

test "ECS builder truncates and canonicalizes address prefix" {
    var out: [32]u8 = undefined;
    var b = OptionBuilder.init(&out);
    try b.addClientSubnet(1, 17, 0, &.{ 192, 0, 255, 9 });
    var it: Iterator = .{ .bytes = b.bytes() };
    const opt = (try it.next()).?;
    const ecs = try clientSubnet(opt);
    try std.testing.expectEqual(@as(u8, 17), ecs.source_prefix);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 0x80 }, ecs.address);
}

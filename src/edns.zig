const std = @import("std");
const message = @import("message.zig");
const types = @import("types.zig");
const cookie_mod = @import("edns/cookie.zig");
const keepalive_mod = @import("edns/keepalive.zig");
const ede_mod = @import("edns/ede.zig");
const update_lease_mod = @import("edns/update_lease.zig");
const zoneversion_mod = @import("edns/zoneversion.zig");

pub const cookie = cookie_mod;
pub const keepalive = keepalive_mod;
pub const ede = ede_mod;
pub const update_lease = update_lease_mod;
pub const zoneversion = zoneversion_mod;

pub const OptionCode = enum(u16) { UPDATE_LEASE = 2, NSID = 3, DAU = 5, DHU = 6, N3U = 7, ECS = 8, EXPIRE = 9, COOKIE = 10, KEEPALIVE = 11, PADDING = 12, CHAIN = 13, KEY_TAG = 14, EDE = 15, REPORT_CHANNEL = 18, ZONEVERSION = 19, _ };
pub const Error = error{ NotOpt, Truncated, InvalidOption, InvalidClientSubnet, InvalidCookie, InvalidKeepalive, MissingCookie, IncorrectClientCookie, MissingServerCookie, InvalidExtendedError, InvalidUpdateLease, InvalidZoneVersion };

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

pub const Cookie = cookie_mod.Cookie;
pub fn parseCookie(opt: Option) Error!Cookie {
    if (opt.code != .COOKIE) return error.InvalidOption;
    return cookie_mod.parse(opt.data) catch error.InvalidCookie;
}

/// Returns the first COOKIE option, matching RFC 7873 multiple-option rules.
pub fn firstCookie(opt: Opt) Error!?Cookie {
    var iterator = opt.iterator();
    while (try iterator.next()) |option| {
        if (option.code == .COOKIE) return try parseCookie(option);
    }
    return null;
}

/// RFC 7873 client-side response validation for an expected Client Cookie.
///
/// When `required` is true, absence of COOKIE is an error. If COOKIE exists,
/// only the first instance is considered and its echoed Client Cookie must
/// match; the returned Server Cookie borrows from the OPT RDATA.
pub fn validateCookieResponse(opt: ?Opt, expected_client: [cookie_mod.client_length]u8, required: bool) Error!?[]const u8 {
    const value = if (opt) |present| try firstCookie(present) else null;
    const cookie_value = value orelse {
        if (required) return error.MissingCookie;
        return null;
    };
    return cookie_mod.validateResponse(cookie_value, expected_client) catch |err| switch (err) {
        error.IncorrectClientCookie => error.IncorrectClientCookie,
        error.MissingServerCookie => error.MissingServerCookie,
    };
}

pub const Keepalive = keepalive_mod.Keepalive;
pub fn parseKeepalive(opt: Option) Error!Keepalive {
    if (opt.code != .KEEPALIVE) return error.InvalidOption;
    return keepalive_mod.parse(opt.data) catch error.InvalidKeepalive;
}

pub const UpdateLease = update_lease_mod.UpdateLease;
pub fn parseUpdateLease(opt: Option) Error!UpdateLease {
    if (opt.code != .UPDATE_LEASE) return error.InvalidOption;
    return update_lease_mod.parse(opt.data) catch error.InvalidUpdateLease;
}

pub const ZoneVersion = zoneversion_mod.ZoneVersion;
pub fn parseZoneVersion(opt: Option, response: bool) Error!ZoneVersion {
    if (opt.code != .ZONEVERSION) return error.InvalidOption;
    return zoneversion_mod.parse(opt.data, response) catch error.InvalidZoneVersion;
}

pub fn validateKnownOption(opt: Option, response: bool) Error!void {
    switch (opt.code) {
        .UPDATE_LEASE => _ = try parseUpdateLease(opt),
        .ECS => _ = try clientSubnet(opt),
        .COOKIE => _ = try parseCookie(opt),
        .KEEPALIVE => {
            const value = try parseKeepalive(opt);
            switch (value) {
                .request => if (response) return error.InvalidKeepalive,
                .timeout => if (!response) return error.InvalidKeepalive,
            }
        },
        .EDE => _ = try extendedError(opt),
        .ZONEVERSION => _ = try parseZoneVersion(opt, response),
        else => {},
    }
}

pub fn validateOptions(opt: Opt, response: bool) Error!void {
    var iterator = opt.iterator();
    var seen_cookie = false;
    while (try iterator.next()) |option| {
        // RFC 7873 requires only the first COOKIE option to be considered;
        // later COOKIE options are ignored rather than interpreted.
        if (option.code == .COOKIE) {
            if (seen_cookie) continue;
            seen_cookie = true;
        }
        try validateKnownOption(option, response);
    }
}

/// Strict message-context checks for options whose validity depends on the
/// DNS opcode or on whether the message is a query/response.
pub fn validateMessageOptions(opt: Opt, response: bool, opcode: types.Opcode) Error!void {
    try validateOptions(opt, response);

    var iterator = opt.iterator();
    var seen_zoneversion_query = false;
    while (try iterator.next()) |option| {
        switch (option.code) {
            .UPDATE_LEASE => if (opcode != .update) return error.InvalidUpdateLease,
            .ZONEVERSION => {
                if (opcode != .query) return error.InvalidZoneVersion;
                if (!response) {
                    if (seen_zoneversion_query) return error.InvalidZoneVersion;
                    seen_zoneversion_query = true;
                }
            },
            else => {},
        }
    }
}

pub const ExtendedErrorCode = ede_mod.InfoCode;
pub const ExtendedError = ede_mod.ExtendedError;
pub fn extendedError(opt: Option) Error!ExtendedError {
    if (opt.code != .EDE) return error.InvalidOption;
    return ede_mod.parse(opt.data) catch error.InvalidExtendedError;
}

pub const ExtendedErrorIterator = struct {
    inner: Iterator,

    pub fn next(self: *ExtendedErrorIterator) Error!?ExtendedError {
        while (try self.inner.next()) |option| {
            if (option.code == .EDE) return try extendedError(option);
        }
        return null;
    }
};

pub fn extendedErrors(opt: Opt) ExtendedErrorIterator {
    return .{ .inner = opt.iterator() };
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
    pub fn addUpdateLease(self: *OptionBuilder, value: UpdateLease) error{NoSpace}!void {
        var payload: [8]u8 = undefined;
        const wire = try update_lease_mod.write(value, &payload);
        try self.add(.UPDATE_LEASE, wire);
    }

    pub fn addCookie(self: *OptionBuilder, client: [cookie_mod.client_length]u8, server: ?[]const u8) (error{ NoSpace, InvalidCookie })!void {
        const data_len = cookie_mod.validateServerLength(server) catch return error.InvalidCookie;
        if (self.pos + 4 + data_len > self.out.len) return error.NoSpace;

        const start = self.pos;
        std.mem.writeInt(u16, self.out[start..][0..2], @intFromEnum(OptionCode.COOKIE), .big);
        std.mem.writeInt(u16, self.out[start + 2 ..][0..2], @intCast(data_len), .big);
        @memcpy(self.out[start + 4 ..][0..cookie_mod.client_length], &client);
        if (server) |server_bytes| {
            @memcpy(self.out[start + 4 + cookie_mod.client_length ..][0..server_bytes.len], server_bytes);
        }
        self.pos += 4 + data_len;
    }

    pub fn addKeepaliveRequest(self: *OptionBuilder) error{NoSpace}!void {
        try self.add(.KEEPALIVE, &.{});
    }

    pub fn addKeepaliveResponse(self: *OptionBuilder, timeout_units: u16) error{NoSpace}!void {
        if (self.pos + 6 > self.out.len) return error.NoSpace;
        const start = self.pos;
        std.mem.writeInt(u16, self.out[start..][0..2], @intFromEnum(OptionCode.KEEPALIVE), .big);
        std.mem.writeInt(u16, self.out[start + 2 ..][0..2], 2, .big);
        std.mem.writeInt(u16, self.out[start + 4 ..][0..2], timeout_units, .big);
        self.pos += 6;
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

    pub fn addExtendedError(self: *OptionBuilder, info_code: u16, text: []const u8) error{ NoSpace, InvalidExtendedError }!void {
        if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidExtendedError;
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

    pub fn addExtendedErrorCode(self: *OptionBuilder, code: ExtendedErrorCode, text: []const u8) error{ NoSpace, InvalidExtendedError }!void {
        return self.addExtendedError(@intFromEnum(code), text);
    }

    pub fn addZoneVersionRequest(self: *OptionBuilder) error{NoSpace}!void {
        try self.add(.ZONEVERSION, &.{});
    }

    pub fn addZoneVersionSoaSerial(self: *OptionBuilder, label_count: u8, serial: u32) error{NoSpace}!void {
        var payload: [6]u8 = undefined;
        const wire = try zoneversion_mod.writeSoaSerial(label_count, serial, &payload);
        try self.add(.ZONEVERSION, wire);
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

test "COOKIE builder is transactional and typed" {
    const client: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const server: [16]u8 = .{0xaa} ** 16;
    var out: [44]u8 = undefined;
    var b = OptionBuilder.init(&out);
    try b.addCookie(client, &server);

    var it: Iterator = .{ .bytes = b.bytes() };
    const parsed = try parseCookie((try it.next()).?);
    try std.testing.expectEqual(client, parsed.client);
    try std.testing.expectEqualSlices(u8, &server, parsed.server.?);

    const before = b.pos;
    try std.testing.expectError(error.InvalidCookie, b.addCookie(client, &([_]u8{0} ** 7)));
    try std.testing.expectEqual(before, b.pos);
}

test "TCP keepalive builders preserve RFC 7828 forms" {
    var out: [16]u8 = undefined;
    var b = OptionBuilder.init(&out);
    try b.addKeepaliveRequest();
    try b.addKeepaliveResponse(123);

    var it: Iterator = .{ .bytes = b.bytes() };
    try std.testing.expectEqual(Keepalive.request, try parseKeepalive((try it.next()).?));
    const response = try parseKeepalive((try it.next()).?);
    try std.testing.expectEqual(@as(u16, 123), response.timeout);
    try std.testing.expectEqual(@as(?u32, 12_300), response.timeoutMilliseconds());
}

test "client cookie response validation uses first COOKIE only" {
    const client: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const server: [16]u8 = .{0x42} ** 16;
    var bytes: [64]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    try builder.addCookie(client, &server);
    try builder.add(.COOKIE, &.{0});

    const opt: Opt = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .flags = .{}, .options = builder.bytes() };
    try std.testing.expectEqualSlices(u8, &server, (try validateCookieResponse(opt, client, true)).?);

    var wrong = client;
    wrong[0] ^= 1;
    try std.testing.expectError(error.IncorrectClientCookie, validateCookieResponse(opt, wrong, true));
    try std.testing.expectError(error.MissingCookie, validateCookieResponse(null, client, true));
    try std.testing.expectEqual(@as(?[]const u8, null), try validateCookieResponse(null, client, false));
}

test "EDE typed builder and filtered iterator preserve multiple diagnostics" {
    var bytes: [64]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    try builder.addExtendedErrorCode(.dnssec_bogus, "signature failed");
    try builder.add(.PADDING, &.{ 0, 0 });
    try builder.addExtendedError(0x1234, "future");

    const opt: Opt = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .flags = .{}, .options = builder.bytes() };
    var it = extendedErrors(opt);
    const first = (try it.next()).?;
    try std.testing.expectEqual(ExtendedErrorCode.dnssec_bogus, first.code());
    try std.testing.expectEqualStrings("signature failed", first.extra_text);
    const second = (try it.next()).?;
    try std.testing.expectEqual(@as(u16, 0x1234), second.info_code);
    try std.testing.expect((try it.next()) == null);

    const before = builder.pos;
    try std.testing.expectError(error.InvalidExtendedError, builder.addExtendedErrorCode(.other_error, "bad\xc0"));
    try std.testing.expectEqual(before, builder.pos);
}

test "Update Lease and ZONEVERSION typed builders round trip" {
    var bytes: [64]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    try builder.addUpdateLease(.{ .lease = 120, .key_lease = 3600 });
    try builder.addZoneVersionSoaSerial(2, 2_023_073_001);

    var iterator: Iterator = .{ .bytes = builder.bytes() };
    const lease = try parseUpdateLease((try iterator.next()).?);
    try std.testing.expectEqual(@as(u32, 120), lease.lease);
    try std.testing.expectEqual(@as(?u32, 3600), lease.key_lease);

    const version = try parseZoneVersion((try iterator.next()).?, true);
    try std.testing.expectEqual(@as(?u32, 2_023_073_001), version.response.soaSerial());
}

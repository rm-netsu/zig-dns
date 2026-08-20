const std = @import("std");
const message = @import("message.zig");
const types = @import("types.zig");
const name_mod = @import("name.zig");
const cookie_mod = @import("edns/cookie.zig");
const keepalive_mod = @import("edns/keepalive.zig");
const ede_mod = @import("edns/ede.zig");
const update_lease_mod = @import("edns/update_lease.zig");
const zoneversion_mod = @import("edns/zoneversion.zig");
const mqtype_mod = @import("edns/mqtype.zig");
const expire_mod = @import("edns/expire.zig");
const report_channel_mod = @import("edns/report_channel.zig");
const padding_mod = @import("edns/padding.zig");
const nsid_mod = @import("edns/nsid.zig");
const algorithm_signal_mod = @import("edns/algorithm_signal.zig");
const key_tag_mod = @import("edns/key_tag.zig");

pub const cookie = cookie_mod;
pub const keepalive = keepalive_mod;
pub const ede = ede_mod;
pub const update_lease = update_lease_mod;
pub const zoneversion = zoneversion_mod;
pub const mqtype = mqtype_mod;
pub const expire = expire_mod;
pub const report_channel = report_channel_mod;
pub const padding = padding_mod;
pub const nsid = nsid_mod;
pub const algorithm_signal = algorithm_signal_mod;
pub const key_tag = key_tag_mod;

pub const OptionCode = enum(u16) { UPDATE_LEASE = 2, NSID = 3, DAU = 5, DHU = 6, N3U = 7, ECS = 8, EXPIRE = 9, COOKIE = 10, KEEPALIVE = 11, PADDING = 12, CHAIN = 13, KEY_TAG = 14, EDE = 15, REPORT_CHANNEL = 18, ZONEVERSION = 19, MQTYPE_QUERY = 20, MQTYPE_RESPONSE = 21, _ };
pub const Error = error{ NotOpt, Truncated, InvalidOption, InvalidClientSubnet, InvalidCookie, InvalidKeepalive, MissingCookie, IncorrectClientCookie, MissingServerCookie, InvalidExtendedError, InvalidUpdateLease, InvalidZoneVersion, InvalidMultipleQtype, InvalidExpire, InvalidReportChannel, InvalidPadding, InvalidAlgorithmSignal, InvalidKeyTag };

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

pub const Expire = expire_mod.Expire;
pub fn parseExpire(opt: Option) Error!Expire {
    if (opt.code != .EXPIRE) return error.InvalidOption;
    return expire_mod.parse(opt.data) catch error.InvalidExpire;
}

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

pub const MultipleQtypeList = mqtype_mod.List;
pub const MultipleQtypeScratch = mqtype_mod.Scratch;
pub fn parseMultipleQtypeQuery(opt: Option) Error!MultipleQtypeList {
    if (opt.code != .MQTYPE_QUERY) return error.InvalidOption;
    return mqtype_mod.parseQuery(opt.data) catch error.InvalidMultipleQtype;
}

pub fn parseMultipleQtypeResponse(opt: Option) Error!MultipleQtypeList {
    if (opt.code != .MQTYPE_RESPONSE) return error.InvalidOption;
    return mqtype_mod.parseResponse(opt.data) catch error.InvalidMultipleQtype;
}

pub const Nsid = nsid_mod.Nsid;
pub fn parseNsid(opt: Option, response: bool) Error!Nsid {
    if (opt.code != .NSID) return error.InvalidOption;
    return nsid_mod.parse(opt.data, response);
}

pub const AlgorithmSignalList = algorithm_signal_mod.List;
pub fn parseDau(opt: Option) Error!AlgorithmSignalList {
    if (opt.code != .DAU) return error.InvalidOption;
    return algorithm_signal_mod.parse(opt.data);
}

pub fn parseDhu(opt: Option) Error!AlgorithmSignalList {
    if (opt.code != .DHU) return error.InvalidOption;
    return algorithm_signal_mod.parse(opt.data);
}

pub fn parseN3u(opt: Option) Error!AlgorithmSignalList {
    if (opt.code != .N3U) return error.InvalidOption;
    return algorithm_signal_mod.parse(opt.data);
}

pub const KeyTagList = key_tag_mod.List;
pub fn parseKeyTag(opt: Option) Error!KeyTagList {
    if (opt.code != .KEY_TAG) return error.InvalidOption;
    return key_tag_mod.parse(opt.data) catch error.InvalidKeyTag;
}

pub const Padding = padding_mod.Padding;
pub fn parsePadding(opt: Option) Error!Padding {
    if (opt.code != .PADDING) return error.InvalidOption;
    return padding_mod.parse(opt.data);
}

/// Find the single RFC 7830 Padding option. Duplicate options are invalid.
pub fn paddingOption(opt: ?Opt) Error!?Padding {
    const present = opt orelse return null;
    var iterator = present.iterator();
    var value: ?Padding = null;
    while (try iterator.next()) |option| {
        if (option.code != .PADDING) continue;
        if (value != null) return error.InvalidPadding;
        value = try parsePadding(option);
    }
    return value;
}

pub const ReportChannel = report_channel_mod.ReportChannel;
pub fn parseReportChannel(opt: Option) Error!ReportChannel {
    if (opt.code != .REPORT_CHANNEL) return error.InvalidOption;
    return report_channel_mod.parse(opt.data) catch error.InvalidReportChannel;
}

/// Returns the RFC 9567 agent domain when a response advertises one.
/// Duplicate options are rejected even when the caller did not run strict
/// whole-message validation first.
pub fn reportChannel(opt: ?Opt) Error!?ReportChannel {
    const present = opt orelse return null;
    var iterator = present.iterator();
    var value: ?ReportChannel = null;
    while (try iterator.next()) |option| {
        if (option.code != .REPORT_CHANNEL) continue;
        if (value != null) return error.InvalidReportChannel;
        value = try parseReportChannel(option);
    }
    return value;
}

pub fn validateKnownOption(opt: Option, response: bool) Error!void {
    switch (opt.code) {
        .UPDATE_LEASE => _ = try parseUpdateLease(opt),
        .NSID => _ = try parseNsid(opt, response),
        .DAU => {
            if (!response) _ = try parseDau(opt);
        },
        .DHU => {
            if (!response) _ = try parseDhu(opt);
        },
        .N3U => {
            if (!response) _ = try parseN3u(opt);
        },
        .KEY_TAG => {
            if (!response) _ = try parseKeyTag(opt);
        },
        .ECS => _ = try clientSubnet(opt),
        .EXPIRE => {
            const value = try parseExpire(opt);
            switch (value) {
                .request => if (response) return error.InvalidExpire,
                .remaining_seconds => if (!response) return error.InvalidExpire,
            }
        },
        .COOKIE => _ = try parseCookie(opt),
        .KEEPALIVE => {
            const value = try parseKeepalive(opt);
            switch (value) {
                .request => if (response) return error.InvalidKeepalive,
                .timeout => if (!response) return error.InvalidKeepalive,
            }
        },
        .EDE => _ = try extendedError(opt),
        .REPORT_CHANNEL => {
            if (!response) return error.InvalidReportChannel;
            _ = try parseReportChannel(opt);
        },
        .ZONEVERSION => _ = try parseZoneVersion(opt, response),
        .MQTYPE_QUERY => _ = try parseMultipleQtypeQuery(opt),
        .MQTYPE_RESPONSE => _ = try parseMultipleQtypeResponse(opt),
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

pub const MessageOptionSummary = struct {
    has_zoneversion: bool = false,
    has_key_tag: bool = false,
    has_dau: bool = false,
    has_dhu: bool = false,
    has_n3u: bool = false,
    has_padding: bool = false,
    report_channel: ?Option = null,
    mqtype_query: ?Option = null,
    mqtype_response: ?Option = null,
};

/// Strict option validation plus message-context summary in one EDNS pass.
///
/// Keeping semantic discovery in the same pass as known-option validation
/// avoids repeatedly rescanning every OPT RDATA in the common path where
/// operational extensions are absent.
pub fn validateMessageOptions(opt: Opt, response: bool, opcode: types.Opcode) Error!MessageOptionSummary {
    var summary: MessageOptionSummary = .{};
    var iterator = opt.iterator();
    var seen_cookie = false;
    while (try iterator.next()) |option| {
        // RFC 7873 considers only the first COOKIE. Later instances are
        // framed normally but ignored rather than semantically interpreted.
        if (option.code == .COOKIE) {
            if (seen_cookie) continue;
            seen_cookie = true;
        }

        try validateKnownOption(option, response);
        switch (option.code) {
            .EXPIRE => if (opcode != .query) return error.InvalidExpire,
            .UPDATE_LEASE => if (opcode != .update) return error.InvalidUpdateLease,
            .PADDING => {
                if (summary.has_padding) return error.InvalidPadding;
                summary.has_padding = true;
            },
            .DAU => if (!response) {
                if (summary.has_dau) return error.InvalidAlgorithmSignal;
                summary.has_dau = true;
            },
            .DHU => if (!response) {
                if (summary.has_dhu) return error.InvalidAlgorithmSignal;
                summary.has_dhu = true;
            },
            .N3U => if (!response) {
                if (summary.has_n3u) return error.InvalidAlgorithmSignal;
                summary.has_n3u = true;
            },
            .KEY_TAG => {
                if (!response) summary.has_key_tag = true;
            },
            .REPORT_CHANNEL => {
                if (summary.report_channel != null) return error.InvalidReportChannel;
                summary.report_channel = option;
            },
            .ZONEVERSION => {
                if (opcode != .query) return error.InvalidZoneVersion;
                if (!response and summary.has_zoneversion) return error.InvalidZoneVersion;
                summary.has_zoneversion = true;
            },
            .MQTYPE_QUERY => {
                if (opcode != .query) return error.InvalidMultipleQtype;
                // A request may contain at most one MQTYPE-Query. An echoed
                // request option in a response is retained only as an
                // unsupported-extension marker and is not a FORMERR by itself.
                if (!response and summary.mqtype_query != null) return error.InvalidMultipleQtype;
                if (summary.mqtype_query == null) summary.mqtype_query = option;
            },
            .MQTYPE_RESPONSE => {
                if (opcode != .query or !response) return error.InvalidMultipleQtype;
                if (summary.mqtype_response != null) return error.InvalidMultipleQtype;
                summary.mqtype_response = option;
            },
            else => {},
        }
    }
    return summary;
}

/// RFC 10029 server-side extraction and validation of one MQTYPE-Query.
/// Returns null when the query did not request multiple QTYPEs.
pub fn multipleQtypeQuery(opt: Opt, primary: types.Type, scratch: *MultipleQtypeScratch) Error!?MultipleQtypeList {
    var iterator = opt.iterator();
    var query_option: ?Option = null;
    while (try iterator.next()) |option| {
        switch (option.code) {
            .MQTYPE_QUERY => {
                if (query_option != null) return error.InvalidMultipleQtype;
                query_option = option;
            },
            .MQTYPE_RESPONSE => return error.InvalidMultipleQtype,
            else => {},
        }
    }
    const option = query_option orelse return null;
    const list = try parseMultipleQtypeQuery(option);
    list.validate(primary, scratch) catch return error.InvalidMultipleQtype;
    return list;
}

pub const MultipleQtypeResponse = union(enum) {
    unsupported,
    processed: MultipleQtypeList,
};

/// RFC 10029 client-side interpretation of MQTYPE response signaling.
///
/// An echoed MQTYPE-Query or absent MQTYPE-Response means the extension is
/// unsupported for this transaction. A present MQTYPE-Response is validated
/// against the primary QTYPE with caller-owned exact duplicate scratch.
pub fn multipleQtypeResponse(opt: ?Opt, primary: types.Type, scratch: *MultipleQtypeScratch) Error!MultipleQtypeResponse {
    const present = opt orelse return .unsupported;
    var iterator = present.iterator();
    var response_option: ?Option = null;
    var echoed_query = false;
    while (try iterator.next()) |option| {
        switch (option.code) {
            .MQTYPE_QUERY => echoed_query = true,
            .MQTYPE_RESPONSE => {
                if (response_option != null) return error.InvalidMultipleQtype;
                response_option = option;
            },
            else => {},
        }
    }
    if (echoed_query) return .unsupported;
    const option = response_option orelse return .unsupported;
    const list = try parseMultipleQtypeResponse(option);
    list.validate(primary, scratch) catch return error.InvalidMultipleQtype;
    return .{ .processed = list };
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
    pub fn addExpireRequest(self: *OptionBuilder) error{NoSpace}!void {
        try self.add(.EXPIRE, &.{});
    }

    pub fn addExpireResponse(self: *OptionBuilder, remaining_seconds: u32) error{NoSpace}!void {
        if (self.pos + 8 > self.out.len) return error.NoSpace;
        const start = self.pos;
        std.mem.writeInt(u16, self.out[start..][0..2], @intFromEnum(OptionCode.EXPIRE), .big);
        std.mem.writeInt(u16, self.out[start + 2 ..][0..2], 4, .big);
        std.mem.writeInt(u32, self.out[start + 4 ..][0..4], remaining_seconds, .big);
        self.pos += 8;
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

    pub fn addNsidRequest(self: *OptionBuilder) error{NoSpace}!void {
        try self.add(.NSID, &.{});
    }

    pub fn addNsidResponse(self: *OptionBuilder, identifier: []const u8) error{NoSpace}!void {
        try self.add(.NSID, identifier);
    }

    pub fn addDau(self: *OptionBuilder, algorithms: []const u8) error{NoSpace}!void {
        try self.add(.DAU, algorithms);
    }

    pub fn addDhu(self: *OptionBuilder, algorithms: []const u8) error{NoSpace}!void {
        try self.add(.DHU, algorithms);
    }

    pub fn addN3u(self: *OptionBuilder, algorithms: []const u8) error{NoSpace}!void {
        try self.add(.N3U, algorithms);
    }

    pub fn addKeyTags(self: *OptionBuilder, key_tags: []const u16) error{ NoSpace, InvalidKeyTag }!void {
        if (key_tags.len == 0 or key_tags.len > std.math.maxInt(u16) / 2) return error.InvalidKeyTag;
        const data_len = key_tags.len * 2;
        if (self.pos > self.out.len or data_len + 4 > self.out.len - self.pos) return error.NoSpace;
        const start = self.pos;
        std.mem.writeInt(u16, self.out[start..][0..2], @intFromEnum(OptionCode.KEY_TAG), .big);
        std.mem.writeInt(u16, self.out[start + 2 ..][0..2], @intCast(data_len), .big);
        for (key_tags, 0..) |tag, i| {
            std.mem.writeInt(u16, self.out[start + 4 + i * 2 ..][0..2], tag, .big);
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

    pub fn addMultipleQtypeQuery(self: *OptionBuilder, primary: types.Type, qtypes: []const types.Type) (error{ NoSpace, InvalidMultipleQtype })!void {
        return self.addMultipleQtype(.MQTYPE_QUERY, primary, qtypes, false);
    }

    pub fn addMultipleQtypeResponse(self: *OptionBuilder, primary: types.Type, qtypes: []const types.Type) (error{ NoSpace, InvalidMultipleQtype })!void {
        return self.addMultipleQtype(.MQTYPE_RESPONSE, primary, qtypes, true);
    }

    fn addMultipleQtype(self: *OptionBuilder, code: OptionCode, primary: types.Type, qtypes: []const types.Type, allow_empty: bool) (error{ NoSpace, InvalidMultipleQtype })!void {
        mqtype_mod.validateSlice(qtypes, primary, allow_empty) catch return error.InvalidMultipleQtype;
        const data_len = qtypes.len * 2;
        if (self.pos + 4 + data_len > self.out.len) return error.NoSpace;
        const start = self.pos;
        std.mem.writeInt(u16, self.out[start..][0..2], @intFromEnum(code), .big);
        std.mem.writeInt(u16, self.out[start + 2 ..][0..2], @intCast(data_len), .big);
        for (qtypes, 0..) |rr_type, i| {
            std.mem.writeInt(u16, self.out[start + 4 + i * 2 ..][0..2], @intFromEnum(rr_type), .big);
        }
        self.pos += 4 + data_len;
    }

    pub fn addReportChannel(self: *OptionBuilder, agent_domain: name_mod.Uncompressed) error{ NoSpace, InvalidReportChannel }!void {
        report_channel_mod.validateAgentDomain(agent_domain) catch return error.InvalidReportChannel;
        try self.add(.REPORT_CHANNEL, agent_domain.bytes);
    }

    pub fn addReportChannelPresentation(self: *OptionBuilder, agent_domain: []const u8) error{ NoSpace, InvalidReportChannel }!void {
        var wire: [name_mod.Name.max_wire_len]u8 = undefined;
        const encoded = name_mod.writePresentationWire(agent_domain, &wire) catch return error.InvalidReportChannel;
        const uncompressed = name_mod.Uncompressed.init(encoded) catch return error.InvalidReportChannel;
        try self.addReportChannel(uncompressed);
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

    /// Add one block-length Padding option when it fits within the caller's
    /// selected message-size limit. Returns false without mutation when the
    /// next padded block would exceed that limit.
    pub fn addBlockPadding(self: *OptionBuilder, unpadded_len: usize, block_len: usize, max_len: usize) error{ NoSpace, InvalidPadding }!bool {
        const len = padding_mod.blockLength(unpadded_len, block_len, max_len) catch return error.InvalidPadding;
        const padding_len = len orelse return false;
        try self.addPadding(padding_len);
        return true;
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

test "RFC 10029 MQTYPE builders and client response interpretation" {
    var bytes: [64]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    try builder.addMultipleQtypeQuery(.A, &.{ .AAAA, .HTTPS });

    var it: Iterator = .{ .bytes = builder.bytes() };
    const query = try parseMultipleQtypeQuery((try it.next()).?);
    var scratch: MultipleQtypeScratch = .{};
    try query.validate(.A, &scratch);

    var response_bytes: [64]u8 = undefined;
    var response_builder = OptionBuilder.init(&response_bytes);
    try response_builder.addMultipleQtypeResponse(.A, &.{ .AAAA, .HTTPS });
    const opt: Opt = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .flags = .{}, .options = response_builder.bytes() };
    const interpreted = try multipleQtypeResponse(opt, .A, &scratch);
    try std.testing.expectEqual(@as(usize, 2), interpreted.processed.count());

    var echoed_bytes: [64]u8 = undefined;
    var echoed_builder = OptionBuilder.init(&echoed_bytes);
    try echoed_builder.addMultipleQtypeQuery(.A, &.{.AAAA});
    const echoed: Opt = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .flags = .{}, .options = echoed_builder.bytes() };
    try std.testing.expectEqual(MultipleQtypeResponse.unsupported, try multipleQtypeResponse(echoed, .A, &scratch));
}

test "MQTYPE builders reject invalid and duplicate caller lists transactionally" {
    var bytes: [32]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    const before = builder.pos;
    try std.testing.expectError(error.InvalidMultipleQtype, builder.addMultipleQtypeQuery(.A, &.{}));
    try std.testing.expectError(error.InvalidMultipleQtype, builder.addMultipleQtypeQuery(.A, &.{ .AAAA, .AAAA }));
    try std.testing.expectError(error.InvalidMultipleQtype, builder.addMultipleQtypeQuery(.A, &.{.A}));
    try std.testing.expectError(error.InvalidMultipleQtype, builder.addMultipleQtypeQuery(.ANY, &.{.A}));
    try std.testing.expectEqual(before, builder.pos);

    // RFC 10029 explicitly permits an empty MQTYPE-Response list.
    try builder.addMultipleQtypeResponse(.A, &.{});
}

test "EDNS EXPIRE typed builders preserve query response direction" {
    var bytes: [32]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    try builder.addExpireRequest();
    try builder.addExpireResponse(86_400);

    var it: Iterator = .{ .bytes = builder.bytes() };
    try std.testing.expectEqual(Expire.request, try parseExpire((try it.next()).?));
    const response = try parseExpire((try it.next()).?);
    try std.testing.expectEqual(@as(u32, 86_400), response.remaining_seconds);
}

test "RFC 9567 Report-Channel typed builder round trips" {
    var bytes: [64]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    try builder.addReportChannelPresentation("a01.agent.example.");

    var it: Iterator = .{ .bytes = builder.bytes() };
    const parsed = try parseReportChannel((try it.next()).?);
    const expected = [_]u8{ 3, 'a', '0', '1', 5, 'a', 'g', 'e', 'n', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    try std.testing.expectEqualSlices(u8, &expected, parsed.agent_domain.bytes);
    try std.testing.expect((try it.next()) == null);

    const opt: Opt = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .flags = .{}, .options = builder.bytes() };
    const discovered = (try reportChannel(opt)).?;
    try std.testing.expectEqualSlices(u8, &expected, discovered.agent_domain.bytes);
}

test "RFC 9567 Report-Channel builder rejects root transactionally" {
    var bytes: [16]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    const before = builder.pos;
    const root = try name_mod.Uncompressed.init(&.{0});
    try std.testing.expectError(error.InvalidReportChannel, builder.addReportChannel(root));
    try std.testing.expectEqual(before, builder.pos);
}

test "RFC 8467 block padding builder is bounded and transactional" {
    var bytes: [128]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    try std.testing.expect(try builder.addBlockPadding(59, 128, 128));
    try std.testing.expectEqual(@as(usize, 69), builder.bytes().len);

    var iterator: Iterator = .{ .bytes = builder.bytes() };
    const parsed = try parsePadding((try iterator.next()).?);
    try std.testing.expectEqual(@as(usize, 65), parsed.len());
    try std.testing.expect(std.mem.allEqual(u8, parsed.bytes, 0));

    const before = builder.pos;
    try std.testing.expect(!(try builder.addBlockPadding(125, 128, 128)));
    try std.testing.expectEqual(before, builder.pos);
}

test "RFC 5001 NSID typed builders preserve opaque response bytes" {
    var bytes: [32]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    try builder.addNsidRequest();
    try builder.addNsidResponse(&.{ 0, 0xff, 0x41 });

    var iterator: Iterator = .{ .bytes = builder.bytes() };
    try std.testing.expectEqual(Nsid.request, try parseNsid((try iterator.next()).?, false));
    const response = try parseNsid((try iterator.next()).?, true);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0xff, 0x41 }, response.response);
}

test "RFC 6975 typed algorithm signaling builders preserve opaque registry codes" {
    var bytes: [64]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    try builder.addDau(&.{ 15, 8, 13 });
    try builder.addDhu(&.{ 2, 4 });
    try builder.addN3u(&.{1});

    var it: Iterator = .{ .bytes = builder.bytes() };
    const dau = try parseDau((try it.next()).?);
    try std.testing.expectEqualSlices(u8, &.{ 15, 8, 13 }, dau.algorithms);
    const dhu = try parseDhu((try it.next()).?);
    try std.testing.expectEqualSlices(u8, &.{ 2, 4 }, dhu.algorithms);
    const n3u = try parseN3u((try it.next()).?);
    try std.testing.expectEqualSlices(u8, &.{1}, n3u.algorithms);
}

test "RFC 6975 query rejects duplicate option codes but response values are ignored" {
    var bytes: [32]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    try builder.addDau(&.{8});
    try builder.addDau(&.{13});
    const opt: Opt = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .flags = .{}, .options = builder.bytes() };
    try std.testing.expectError(error.InvalidAlgorithmSignal, validateMessageOptions(opt, false, .query));
    _ = try validateMessageOptions(opt, true, .query);
}

test "RFC 8145 typed key tag builder supports multiple option instances" {
    var bytes: [64]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    try builder.addKeyTags(&.{ 19036, 12345 });
    try builder.addKeyTags(&.{ 19036, 34567 });

    var it: Iterator = .{ .bytes = builder.bytes() };
    const first = try parseKeyTag((try it.next()).?);
    try std.testing.expectEqual(@as(usize, 2), first.count());
    try std.testing.expect(first.contains(19036));
    try std.testing.expect(first.contains(12345));
    const second = try parseKeyTag((try it.next()).?);
    try std.testing.expect(second.contains(34567));

    const before = builder.pos;
    try std.testing.expectError(error.InvalidKeyTag, builder.addKeyTags(&.{}));
    try std.testing.expectEqual(before, builder.pos);
}

test "RFC 8145 response option payload is ignored by strict EDNS validation" {
    var bytes: [16]u8 = undefined;
    var builder = OptionBuilder.init(&bytes);
    // RFC 8145 requires clients to ignore edns-key-tag values in responses,
    // even though this odd-length payload is not a valid query-side list.
    try builder.add(.KEY_TAG, &.{0xff});
    const opt: Opt = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .flags = .{}, .options = builder.bytes() };
    try std.testing.expectError(error.InvalidKeyTag, validateMessageOptions(opt, false, .query));
    _ = try validateMessageOptions(opt, true, .query);
}

const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const builder_mod = @import("../builder.zig");
const record_mod = @import("record.zig");

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const max_mac_len = HmacSha256.mac_length;

const hmac_sha1_name = [_]u8{ 9, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '1', 0 };
const hmac_sha256_name = [_]u8{ 11, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0 };

/// RFC 8945 mandatory-to-implement algorithms. SHA-1 remains available only
/// for protocol compatibility; new deployments should prefer SHA-256.
pub const Algorithm = enum {
    hmac_sha1,
    hmac_sha256,

    pub fn wireName(self: Algorithm) name_mod.Uncompressed {
        return switch (self) {
            .hmac_sha1 => name_mod.Uncompressed.init(&hmac_sha1_name) catch unreachable,
            .hmac_sha256 => name_mod.Uncompressed.init(&hmac_sha256_name) catch unreachable,
        };
    }

    pub fn macLen(self: Algorithm) usize {
        return switch (self) {
            .hmac_sha1 => HmacSha1.mac_length,
            .hmac_sha256 => HmacSha256.mac_length,
        };
    }

    pub fn protocolMinMacLen(self: Algorithm) usize {
        return @max(@as(usize, 10), self.macLen() / 2);
    }
};

pub const Error = record_mod.Error || message.ParseError || error{
    InvalidMessage,
    BadKey,
    BadSignature,
    BadTime,
    InvalidMacLength,
    BadTruncation,
    UnsupportedAlgorithm,
    TooManyUnsignedMessages,
    TimeWentBackward,
    UnexpectedTsigError,
};

/// Borrowed TSIG key. Secret bytes are never copied into persistent library
/// storage; HMAC contexts are zeroized after use where practical.
pub const Key = struct {
    name: name_mod.Uncompressed,
    algorithm: Algorithm = .hmac_sha256,
    secret: []const u8,

    /// Build a SHA-256 TSIG key without allocating. `name_storage` remains
    /// caller-owned and must outlive the Key. Secret bytes are borrowed too.
    pub fn init(presentation_name: []const u8, secret: []const u8, name_storage: []u8) Error!Key {
        return initWithAlgorithm(presentation_name, .hmac_sha256, secret, name_storage);
    }

    pub fn initWithAlgorithm(
        presentation_name: []const u8,
        algorithm: Algorithm,
        secret: []const u8,
        name_storage: []u8,
    ) Error!Key {
        const wire = try name_mod.writePresentationWire(presentation_name, name_storage);
        return .{
            .name = try name_mod.Uncompressed.init(wire),
            .algorithm = algorithm,
            .secret = secret,
        };
    }
};

pub const TruncationPolicy = struct {
    /// Optional local floor in addition to the RFC 8945 protocol minimum.
    /// Values below the protocol floor never weaken the protocol minimum.
    min_mac_len: ?u8 = null,

    pub fn acceptedMin(self: TruncationPolicy, algorithm: Algorithm) usize {
        const protocol_min = algorithm.protocolMinMacLen();
        if (self.min_mac_len) |local| return @max(protocol_min, @as(usize, local));
        return protocol_min;
    }
};

pub const SignOptions = struct {
    time_signed: u64,
    /// DNS ID before forwarding/rewriting. Defaults to the current header ID.
    /// RFC 8945 requires this value to replace the current ID in MAC input.
    original_id: ?u16 = null,
    fudge: u16 = record_mod.recommended_fudge,
    error_code: record_mod.ErrorCode = .no_error,
    other_data: []const u8 = &.{},
    /// Validated request MAC when signing a response or the first response in
    /// a multi-message transaction. The bytes are used exactly as received,
    /// including any valid truncation.
    request_mac: ?[]const u8 = null,
    /// Defaults to the full keyed-hash output. Explicit truncation must still
    /// satisfy the protocol minimum from RFC 8945 section 5.2.2.1.
    mac_len: ?u8 = null,
};

pub const VerifyOptions = struct {
    now: u64,
    /// Required when authenticating a response to a signed request.
    request_mac: ?[]const u8 = null,
    truncation: TruncationPolicy = .{},
};

pub const Mac = struct {
    bytes: [max_mac_len]u8 = undefined,
    len: u8,

    pub fn slice(self: *const Mac) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn deinit(self: *Mac) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.len = 0;
    }
};

const HmacState = union(Algorithm) {
    hmac_sha1: HmacSha1,
    hmac_sha256: HmacSha256,

    fn init(algorithm: Algorithm, secret: []const u8) HmacState {
        return switch (algorithm) {
            .hmac_sha1 => .{ .hmac_sha1 = HmacSha1.init(secret) },
            .hmac_sha256 => .{ .hmac_sha256 = HmacSha256.init(secret) },
        };
    }

    fn update(self: *HmacState, bytes: []const u8) void {
        switch (self.*) {
            inline else => |*ctx| ctx.update(bytes),
        }
    }

    fn final(self: *HmacState, out: *[max_mac_len]u8) usize {
        switch (self.*) {
            .hmac_sha1 => |*ctx| {
                var digest: [HmacSha1.mac_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &digest);
                ctx.final(&digest);
                @memcpy(out[0..digest.len], &digest);
                return digest.len;
            },
            .hmac_sha256 => |*ctx| {
                var digest: [HmacSha256.mac_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &digest);
                ctx.final(&digest);
                @memcpy(out[0..digest.len], &digest);
                return digest.len;
            },
        }
    }

    fn deinit(self: *HmacState) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

/// Compute a request or first-response TSIG MAC over a DNS message that does
/// not yet contain the TSIG RR. No allocation or message copy is performed.
pub fn sign(unsigned_message: []const u8, key: Key, options: SignOptions) Error!Mac {
    if (options.time_signed > record_mod.max_time_signed) return error.TimeSignedOutOfRange;
    if (options.other_data.len > std.math.maxInt(u16)) return error.FieldTooLong;
    if (unsigned_message.len < types.Header.wire_len) return error.InvalidMessage;
    _ = try types.Header.parse(unsigned_message);

    var state = HmacState.init(key.algorithm, key.secret);
    defer state.deinit();
    if (options.request_mac) |prior| try updatePriorMac(&state, prior);
    try updateOutgoingMessage(&state, unsigned_message, options.original_id);
    try updateVariables(&state, key.name, key.algorithm.wireName(), options.time_signed, options.fudge, options.error_code, options.other_data);

    var result: Mac = .{ .len = 0 };
    const full_len = state.final(&result.bytes);
    const wanted = options.mac_len orelse @as(u8, @intCast(full_len));
    try validateGeneratedMacLen(key.algorithm, wanted);
    result.len = wanted;
    return result;
}

/// Convenience composition over Builder: hash the complete unsigned DNS
/// message, then append a final TSIG RR transactionally.
pub fn signBuilder(builder: *builder_mod.Builder, key: Key, options: SignOptions) Error!Mac {
    const unsigned = try builder.finish();
    const header = try types.Header.parse(unsigned);
    var mac = try sign(unsigned, key, options);
    errdefer mac.deinit();
    try record_mod.appendWire(builder, key.name, .{
        .algorithm = key.algorithm.wireName(),
        .time_signed = options.time_signed,
        .fudge = options.fudge,
        .mac = mac.slice(),
        .original_id = options.original_id orelse header.id,
        .error_code = options.error_code,
        .other_data = options.other_data,
    });
    return mac;
}

/// Verify a structurally parsed TSIG on an incoming DNS message. This follows
/// RFC 8945 ordering: key, MAC, time, then local truncation policy.
pub fn verify(m: message.Message, tsig: record_mod.Record, key: Key, options: VerifyOptions) Error!void {
    try checkKey(tsig, key);

    const received_len = tsig.mac.len;
    const full_len = key.algorithm.macLen();
    if (received_len > full_len or received_len < key.algorithm.protocolMinMacLen()) return error.InvalidMacLength;

    var state = HmacState.init(key.algorithm, key.secret);
    defer state.deinit();
    if (options.request_mac) |prior| try updatePriorMac(&state, prior);
    try updateIncomingMessage(&state, m, tsig);
    try updateVariables(&state, key.name, key.algorithm.wireName(), tsig.time_signed, tsig.fudge, tsig.error_code, tsig.other_data);

    var expected: [max_mac_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &expected);
    _ = state.final(&expected);
    if (!timingSafeEql(expected[0..received_len], tsig.mac)) return error.BadSignature;

    if (!timeWithinFudge(options.now, tsig.time_signed, tsig.fudge)) return error.BadTime;
    if (received_len < options.truncation.acceptedMin(key.algorithm)) return error.BadTruncation;
}

fn checkKey(tsig: record_mod.Record, key: Key) Error!void {
    const expected_name = try name_mod.Name.init(key.name.bytes, 0);
    if (!(try tsig.keyName().eqlIgnoreCase(expected_name))) return error.BadKey;
    const received_algorithm = algorithmFromWire(tsig.algorithm) catch |err| switch (err) {
        error.UnsupportedAlgorithm => return error.BadKey,
        else => return err,
    };
    if (received_algorithm != key.algorithm) return error.BadKey;
}

pub fn algorithmFromWire(name: name_mod.Uncompressed) Error!Algorithm {
    const n = try name_mod.Name.init(name.bytes, 0);
    if (try n.eqlPresentationIgnoreCase("hmac-sha1")) return .hmac_sha1;
    if (try n.eqlPresentationIgnoreCase("hmac-sha256")) return .hmac_sha256;
    return error.UnsupportedAlgorithm;
}

fn validateGeneratedMacLen(algorithm: Algorithm, requested: usize) Error!void {
    if (requested > algorithm.macLen() or requested < algorithm.protocolMinMacLen()) return error.InvalidMacLength;
}

fn updatePriorMac(state: *HmacState, prior: []const u8) Error!void {
    if (prior.len > std.math.maxInt(u16)) return error.FieldTooLong;
    var len_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_buf, @intCast(prior.len), .big);
    state.update(&len_buf);
    state.update(prior);
}

fn updateOutgoingMessage(state: *HmacState, wire: []const u8, original_id: ?u16) Error!void {
    if (wire.len < types.Header.wire_len) return error.InvalidMessage;
    const header = try types.Header.parse(wire);
    var id_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &id_buf, original_id orelse header.id, .big);
    state.update(&id_buf);
    state.update(wire[2..]);
}

fn updateIncomingMessage(state: *HmacState, m: message.Message, tsig: record_mod.Record) Error!void {
    if (m.bytes.len < types.Header.wire_len or m.header.additional_count == 0) return error.InvalidMessage;
    const tsig_start: usize = tsig.rr.name.offset;
    if (tsig_start < types.Header.wire_len or tsig_start > m.bytes.len) return error.InvalidMessage;

    // RFC 8945 section 4.3.2: remove TSIG, decrement ARCOUNT, and substitute
    // Original ID. Hashing the replacement ID and the original bytes from
    // offset 2 avoids copying the complete DNS message.
    var u16_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &u16_buf, tsig.original_id, .big);
    state.update(&u16_buf);
    state.update(m.bytes[2..10]);
    std.mem.writeInt(u16, &u16_buf, m.header.additional_count - 1, .big);
    state.update(&u16_buf);
    state.update(m.bytes[12..tsig_start]);
}

fn updateVariables(
    state: *HmacState,
    key_name: name_mod.Uncompressed,
    algorithm_name: name_mod.Uncompressed,
    time_signed: u64,
    fudge: u16,
    error_code: record_mod.ErrorCode,
    other_data: []const u8,
) Error!void {
    if (other_data.len > std.math.maxInt(u16)) return error.FieldTooLong;
    try updateCanonicalName(state, key_name);

    var u16_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &u16_buf, @intFromEnum(types.Class.ANY), .big);
    state.update(&u16_buf);
    const ttl = [_]u8{ 0, 0, 0, 0 };
    state.update(&ttl);

    try updateCanonicalName(state, algorithm_name);
    try updateTimers(state, time_signed, fudge);
    std.mem.writeInt(u16, &u16_buf, @intFromEnum(error_code), .big);
    state.update(&u16_buf);
    std.mem.writeInt(u16, &u16_buf, @intCast(other_data.len), .big);
    state.update(&u16_buf);
    state.update(other_data);
}

fn updateTimers(state: *HmacState, time_signed: u64, fudge: u16) Error!void {
    if (time_signed > record_mod.max_time_signed) return error.TimeSignedOutOfRange;
    var time_buf: [6]u8 = undefined;
    std.mem.writeInt(u48, &time_buf, @intCast(time_signed), .big);
    state.update(&time_buf);
    var fudge_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &fudge_buf, fudge, .big);
    state.update(&fudge_buf);
}

fn updateCanonicalName(state: *HmacState, wire: name_mod.Uncompressed) Error!void {
    const n = try name_mod.Name.init(wire.bytes, 0);
    var canonical: [name_mod.Name.max_wire_len]u8 = undefined;
    const bytes = try n.writeCanonicalWire(&canonical);
    state.update(bytes);
}

fn timeWithinFudge(now: u64, signed: u64, fudge: u16) bool {
    const delta = if (now >= signed) now - signed else signed - now;
    return delta <= @as(u64, fudge);
}

fn timingSafeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

pub const max_unsigned_intermediary_messages: u8 = 99;

pub const ChainOptions = struct {
    time_signed: u64,
    original_id: ?u16 = null,
    fudge: u16 = record_mod.recommended_fudge,
    mac_len: ?u8 = null,
};

/// Stateful RFC 8945 section 5.3.1 MAC chain for the second and subsequent
/// messages of a multi-message response. State size is bounded and independent
/// of transfer length. New senders should sign every message; receivers may
/// absorb up to 99 legacy unsigned intermediary messages.
pub const Chain = struct {
    key: Key,
    state: HmacState,
    prior_mac: [max_mac_len]u8 = undefined,
    prior_mac_len: u8,
    last_time_signed: u64,
    unsigned_messages: u8 = 0,

    pub fn init(key: Key, prior_mac: []const u8, last_time_signed: u64) Error!Chain {
        if (last_time_signed > record_mod.max_time_signed) return error.TimeSignedOutOfRange;
        if (prior_mac.len > key.algorithm.macLen() or prior_mac.len < key.algorithm.protocolMinMacLen()) return error.InvalidMacLength;
        var state = HmacState.init(key.algorithm, key.secret);
        errdefer state.deinit();
        try updatePriorMac(&state, prior_mac);
        var self: Chain = .{
            .key = key,
            .state = state,
            .prior_mac_len = @intCast(prior_mac.len),
            .last_time_signed = last_time_signed,
        };
        @memcpy(self.prior_mac[0..prior_mac.len], prior_mac);
        return self;
    }

    pub fn deinit(self: *Chain) void {
        self.state.deinit();
        std.crypto.secureZero(u8, &self.prior_mac);
        self.prior_mac_len = 0;
        self.last_time_signed = 0;
        self.unsigned_messages = 0;
    }

    pub fn priorMac(self: *const Chain) []const u8 {
        return self.prior_mac[0..self.prior_mac_len];
    }

    /// Absorb a complete unsigned intermediary DNS message for backwards
    /// compatibility. RFC 8945 requires verifiers to accept at most 99 such
    /// messages between TSIG checkpoints.
    pub fn absorbUnsigned(self: *Chain, wire: []const u8) Error!void {
        if (self.unsigned_messages == max_unsigned_intermediary_messages) return error.TooManyUnsignedMessages;
        if (wire.len < types.Header.wire_len) return error.InvalidMessage;
        _ = try types.Header.parse(wire);
        self.state.update(wire);
        self.unsigned_messages += 1;
    }

    /// Sign a continuation message. Only Time Signed and Fudge are added after
    /// the DNS message; the other TSIG variables are intentionally excluded by
    /// RFC 8945 for second and subsequent messages.
    pub fn signBuilder(self: *Chain, builder: *builder_mod.Builder, options: ChainOptions) Error!Mac {
        if (options.time_signed > record_mod.max_time_signed) return error.TimeSignedOutOfRange;
        if (options.time_signed < self.last_time_signed) return error.TimeWentBackward;
        const unsigned = try builder.finish();
        const header = try types.Header.parse(unsigned);

        var candidate = self.state;
        defer candidate.deinit();
        try updateOutgoingMessage(&candidate, unsigned, options.original_id);
        try updateTimers(&candidate, options.time_signed, options.fudge);

        var mac: Mac = .{ .len = 0 };
        const full_len = candidate.final(&mac.bytes);
        const wanted = options.mac_len orelse @as(u8, @intCast(full_len));
        try validateGeneratedMacLen(self.key.algorithm, wanted);
        mac.len = wanted;
        errdefer mac.deinit();

        try record_mod.appendWire(builder, self.key.name, .{
            .algorithm = self.key.algorithm.wireName(),
            .time_signed = options.time_signed,
            .fudge = options.fudge,
            .mac = mac.slice(),
            .original_id = options.original_id orelse header.id,
        });
        self.commit(mac.slice(), options.time_signed);
        return mac;
    }

    /// Verify and commit a signed continuation checkpoint. On failure the
    /// running chain state is left unchanged so the caller can discard the
    /// connection without partially advancing authentication state.
    pub fn verifySigned(self: *Chain, m: message.Message, tsig: record_mod.Record, options: VerifyOptions) Error!void {
        try checkKey(tsig, self.key);
        if (tsig.error_code != .no_error or tsig.other_data.len != 0) return error.UnexpectedTsigError;

        const received_len = tsig.mac.len;
        if (received_len > self.key.algorithm.macLen() or received_len < self.key.algorithm.protocolMinMacLen()) return error.InvalidMacLength;

        var candidate = self.state;
        defer candidate.deinit();
        try updateIncomingMessage(&candidate, m, tsig);
        try updateTimers(&candidate, tsig.time_signed, tsig.fudge);

        var expected: [max_mac_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &expected);
        _ = candidate.final(&expected);
        if (!timingSafeEql(expected[0..received_len], tsig.mac)) return error.BadSignature;
        if (!timeWithinFudge(options.now, tsig.time_signed, tsig.fudge)) return error.BadTime;
        if (tsig.time_signed < self.last_time_signed) return error.TimeWentBackward;
        if (received_len < options.truncation.acceptedMin(self.key.algorithm)) return error.BadTruncation;

        self.commit(tsig.mac, tsig.time_signed);
    }

    fn commit(self: *Chain, mac: []const u8, time_signed: u64) void {
        std.crypto.secureZero(u8, &self.prior_mac);
        @memcpy(self.prior_mac[0..mac.len], mac);
        self.prior_mac_len = @intCast(mac.len);
        self.last_time_signed = time_signed;
        self.unsigned_messages = 0;
        self.state.deinit();
        self.state = HmacState.init(self.key.algorithm, self.key.secret);
        updatePriorMac(&self.state, mac) catch unreachable;
    }
};

fn wireName(presentation: []const u8, out: []u8) !name_mod.Uncompressed {
    return name_mod.Uncompressed.init(try name_mod.writePresentationWire(presentation, out));
}

test "TSIG HMAC-SHA256 request sign and verify" {
    var key_name_buf: [64]u8 = undefined;
    const key: Key = .{
        .name = try wireName("key.example", &key_name_buf),
        .secret = "shared secret bytes",
    };
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 0x1234, .{ .recursion_desired = true });
    try b.addQuestion("example.com", .A, .IN);
    var mac = try signBuilder(&b, key, .{ .time_signed = 1_700_000_000 });
    defer mac.deinit();
    const independent_mac = [_]u8{
        0x97, 0xd6, 0x2a, 0x5d, 0xc3, 0xc4, 0x9a, 0x24,
        0x49, 0xec, 0x72, 0x0b, 0x20, 0x3f, 0xd5, 0xba,
        0x92, 0x69, 0x06, 0xb5, 0xf9, 0xfc, 0x90, 0xe0,
        0xd4, 0x61, 0xdf, 0xac, 0xf3, 0x1e, 0x30, 0x2b,
    };
    try std.testing.expectEqualSlices(u8, &independent_mac, mac.slice());
    const wire = try b.finish();
    const m = try message.Message.init(wire);
    var additional = try m.records(.additional);
    const tsig = try record_mod.parse((try additional.next()).?);
    try verify(m, tsig, key, .{ .now = 1_700_000_000 });

    packet[13] ^= 1;
    const changed = try message.Message.init(wire);
    var changed_additional = try changed.records(.additional);
    const changed_tsig = try record_mod.parse((try changed_additional.next()).?);
    try std.testing.expectError(error.BadSignature, verify(changed, changed_tsig, key, .{ .now = 1_700_000_000 }));
}

test "TSIG supports SHA1 truncation and applies local truncation policy after MAC" {
    var key_name_buf: [64]u8 = undefined;
    const key: Key = .{
        .name = try wireName("legacy-key.example", &key_name_buf),
        .algorithm = .hmac_sha1,
        .secret = "legacy shared secret",
    };
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 7, .{});
    try b.addQuestion("example.com", .AAAA, .IN);
    var mac = try signBuilder(&b, key, .{ .time_signed = 1000, .mac_len = 12 });
    defer mac.deinit();
    const m = try message.Message.init(try b.finish());
    var additional = try m.records(.additional);
    const tsig = try record_mod.parse((try additional.next()).?);
    try verify(m, tsig, key, .{ .now = 1000 });
    try std.testing.expectError(error.BadTruncation, verify(m, tsig, key, .{
        .now = 1000,
        .truncation = .{ .min_mac_len = 20 },
    }));
}

test "TSIG checks MAC before time" {
    var key_name_buf: [64]u8 = undefined;
    const key: Key = .{
        .name = try wireName("key.example", &key_name_buf),
        .secret = "shared secret bytes",
    };
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 3, .{});
    try b.addQuestion("example.com", .A, .IN);
    var mac = try signBuilder(&b, key, .{ .time_signed = 100 });
    defer mac.deinit();
    const wire = try b.finish();
    const m = try message.Message.init(wire);
    var additional = try m.records(.additional);
    const tsig = try record_mod.parse((try additional.next()).?);
    try std.testing.expectError(error.BadTime, verify(m, tsig, key, .{ .now = 401 }));

    packet[13] ^= 1;
    const changed = try message.Message.init(wire);
    var changed_additional = try changed.records(.additional);
    const changed_tsig = try record_mod.parse((try changed_additional.next()).?);
    try std.testing.expectError(error.BadSignature, verify(changed, changed_tsig, key, .{ .now = 401 }));
}

test "TSIG response MAC includes validated request MAC" {
    var key_name_buf: [64]u8 = undefined;
    const key: Key = .{
        .name = try wireName("key.example", &key_name_buf),
        .secret = "shared secret bytes",
    };
    const request_mac = [_]u8{
        0x97, 0xd6, 0x2a, 0x5d, 0xc3, 0xc4, 0x9a, 0x24,
        0x49, 0xec, 0x72, 0x0b, 0x20, 0x3f, 0xd5, 0xba,
        0x92, 0x69, 0x06, 0xb5, 0xf9, 0xfc, 0x90, 0xe0,
        0xd4, 0x61, 0xdf, 0xac, 0xf3, 0x1e, 0x30, 0x2b,
    };
    const expected = [_]u8{
        0x17, 0x52, 0xa6, 0x81, 0x76, 0x7b, 0xdc, 0x46,
        0x3d, 0xaf, 0x4f, 0x99, 0x8e, 0xd2, 0x67, 0xbc,
        0x33, 0xb8, 0xdf, 0xb2, 0xcb, 0xe0, 0xda, 0xf3,
        0x13, 0xfe, 0x20, 0x92, 0x31, 0xc4, 0xb0, 0xbb,
    };

    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 0x1234, .{
        .response = true,
        .recursion_desired = true,
    });
    try b.addQuestion("example.com", .A, .IN);
    try b.addA(.answer, "example.com", 60, .{ 1, 2, 3, 4 });
    var mac = try signBuilder(&b, key, .{
        .time_signed = 1_700_000_001,
        .request_mac = &request_mac,
    });
    defer mac.deinit();
    try std.testing.expectEqualSlices(u8, &expected, mac.slice());

    const m = try message.Message.init(try b.finish());
    var additional = try m.records(.additional);
    const tsig = try record_mod.parse((try additional.next()).?);
    try verify(m, tsig, key, .{
        .now = 1_700_000_001,
        .request_mac = &request_mac,
    });
    try std.testing.expectError(error.BadSignature, verify(m, tsig, key, .{
        .now = 1_700_000_001,
        .request_mac = request_mac[0..16],
    }));
}

test "TSIG continuation chain matches independent HMAC and verifies" {
    var key_name_buf: [64]u8 = undefined;
    const key: Key = .{
        .name = try wireName("key.example", &key_name_buf),
        .secret = "shared secret bytes",
    };
    const prior = [_]u8{
        0x17, 0x52, 0xa6, 0x81, 0x76, 0x7b, 0xdc, 0x46,
        0x3d, 0xaf, 0x4f, 0x99, 0x8e, 0xd2, 0x67, 0xbc,
        0x33, 0xb8, 0xdf, 0xb2, 0xcb, 0xe0, 0xda, 0xf3,
        0x13, 0xfe, 0x20, 0x92, 0x31, 0xc4, 0xb0, 0xbb,
    };
    const expected = [_]u8{
        0xbd, 0xb3, 0x43, 0x06, 0xc9, 0xf7, 0x16, 0x54,
        0x77, 0xe1, 0xce, 0xe2, 0x99, 0xae, 0x8e, 0x73,
        0x12, 0x11, 0xa9, 0x1b, 0x70, 0xbc, 0xdd, 0xad,
        0x8b, 0x7d, 0xc5, 0xa2, 0xb2, 0xf1, 0x93, 0x8b,
    };

    var signer = try Chain.init(key, &prior, 1_700_000_001);
    defer signer.deinit();
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 0x1234, .{ .response = true });
    try b.addA(.answer, "next.example.com", 60, .{ 5, 6, 7, 8 });
    var mac = try signer.signBuilder(&b, .{ .time_signed = 1_700_000_002 });
    defer mac.deinit();
    try std.testing.expectEqualSlices(u8, &expected, mac.slice());

    const m = try message.Message.init(try b.finish());
    var additional = try m.records(.additional);
    const tsig = try record_mod.parse((try additional.next()).?);
    var verifier = try Chain.init(key, &prior, 1_700_000_001);
    defer verifier.deinit();
    try verifier.verifySigned(m, tsig, .{ .now = 1_700_000_002 });
    try std.testing.expectEqualSlices(u8, &expected, verifier.priorMac());
}

test "TSIG continuation chain covers unsigned intermediary messages and bounds them" {
    var key_name_buf: [64]u8 = undefined;
    const key: Key = .{
        .name = try wireName("key.example", &key_name_buf),
        .secret = "shared secret bytes",
    };
    const prior = [_]u8{0xaa} ** 32;
    var chain = try Chain.init(key, &prior, 100);
    defer chain.deinit();
    const empty_dns = [_]u8{ 0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    for (0..max_unsigned_intermediary_messages) |_| try chain.absorbUnsigned(&empty_dns);
    try std.testing.expectError(error.TooManyUnsignedMessages, chain.absorbUnsigned(&empty_dns));
}

test "TSIG signing substitutes explicit Original ID into MAC input" {
    var key_name_buf: [64]u8 = undefined;
    const key: Key = .{
        .name = try wireName("key.example", &key_name_buf),
        .secret = "forwarding secret",
    };
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var builder = try builder_mod.Builder.init(&packet, &compression, 0x2222, .{});
    try builder.addQuestion("example.com", .SOA, .IN);
    var mac = try signBuilder(&builder, key, .{
        .time_signed = 1_700_000_000,
        .original_id = 0x1111,
    });
    defer mac.deinit();

    const m = try message.Message.init(try builder.finish());
    var additional = try m.records(.additional);
    const parsed = try record_mod.parse((try additional.next()).?);
    try std.testing.expectEqual(@as(u16, 0x1111), parsed.original_id);
    try verify(m, parsed, key, .{ .now = 1_700_000_000 });
}

test "TSIG signed BADTIME response carries client and server times" {
    var key_name_buf: [64]u8 = undefined;
    const key: Key = .{
        .name = try wireName("key.example", &key_name_buf),
        .secret = "badtime secret",
    };

    var request_buf: [512]u8 = undefined;
    var request_compression: [16]builder_mod.CompressionEntry = undefined;
    var request = try builder_mod.Builder.init(&request_buf, &request_compression, 0x8080, .{});
    try request.addQuestion("example.com", .SOA, .IN);
    var request_mac = try signBuilder(&request, key, .{ .time_signed = 1_700_000_000, .fudge = 30 });
    defer request_mac.deinit();

    var other: [6]u8 = undefined;
    const server_time = try record_mod.badTimeOtherData(1_700_001_000, &other);
    var response_buf: [512]u8 = undefined;
    var response_compression: [16]builder_mod.CompressionEntry = undefined;
    var response = try builder_mod.Builder.init(&response_buf, &response_compression, 0x8080, .{ .response = true, .rcode_low = @intCast(@intFromEnum(types.Rcode.not_auth)) });
    try response.addQuestion("example.com", .SOA, .IN);
    var response_mac = try signBuilder(&response, key, .{
        .time_signed = 1_700_000_000, // the client's Time Signed
        .fudge = 30,
        .request_mac = request_mac.slice(),
        .error_code = .bad_time,
        .other_data = server_time,
    });
    defer response_mac.deinit();

    const m = try message.Message.init(try response.finish());
    var additional = try m.records(.additional);
    const parsed = try record_mod.parse((try additional.next()).?);
    try record_mod.validateSemantics(parsed, true);
    try verify(m, parsed, key, .{ .now = 1_700_000_000, .request_mac = request_mac.slice() });
    try std.testing.expectEqual(@as(u64, 1_700_001_000), try parsed.badTimeServerTime());
}

test "TSIG Key.init uses caller-owned name storage" {
    var name_storage: [name_mod.Name.max_wire_len]u8 = undefined;
    const key = try Key.init("Key.Example", "borrowed secret", &name_storage);
    try std.testing.expectEqual(Algorithm.hmac_sha256, key.algorithm);
    try std.testing.expectEqualStrings("borrowed secret", key.secret);
    const n = try name_mod.Name.init(key.name.bytes, 0);
    try std.testing.expect(try n.eqlPresentationIgnoreCase("key.example"));
}

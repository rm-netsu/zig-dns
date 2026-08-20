const std = @import("std");

pub const Error = error{
    InvalidCookie,
    UnsupportedVersion,
    Expired,
    FromFuture,
    BadHash,
    AmbiguousTimestamp,
};

pub const client_length = 8;
pub const server_min_length = 8;
pub const server_max_length = 32;
pub const version1_server_length = 16;
pub const version1_option_length = client_length + version1_server_length;

/// Allocation-free view of a COOKIE option.
///
/// RFC 7873 permits either a Client Cookie by itself (8 octets), or a Client
/// Cookie followed by an 8..32-octet Server Cookie (16..40 octets total).
pub const Cookie = struct {
    client: [client_length]u8,
    server: ?[]const u8,
};

pub fn parse(data: []const u8) error{InvalidCookie}!Cookie {
    if (data.len != client_length and (data.len < client_length + server_min_length or data.len > client_length + server_max_length)) {
        return error.InvalidCookie;
    }

    var client: [client_length]u8 = undefined;
    @memcpy(&client, data[0..client_length]);
    return .{
        .client = client,
        .server = if (data.len == client_length) null else data[client_length..],
    };
}

pub fn validateServerLength(server: ?[]const u8) error{InvalidCookie}!usize {
    const bytes = server orelse return client_length;
    if (bytes.len < server_min_length or bytes.len > server_max_length) return error.InvalidCookie;
    return client_length + bytes.len;
}

/// Client address bytes used by the RFC 9018 version-1 server-cookie PRF.
pub const ClientAddress = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,

    fn bytes(self: ClientAddress) []const u8 {
        return switch (self) {
            .ipv4 => |*v| v,
            .ipv6 => |*v| v,
        };
    }
};

pub const Version1 = struct {
    pub const version: u8 = 1;
    pub const Secret = [16]u8;
    pub const Hash = [8]u8;

    reserved: [3]u8,
    timestamp: u32,
    hash: Hash,
};

pub const TimePolicy = struct {
    /// RFC 9018 recommends accepting cookies up to one hour old.
    max_past_seconds: u32 = 3600,
    /// RFC 9018 recommends allowing five minutes of forward clock skew.
    max_future_seconds: u32 = 300,
    /// RFC 9018 recommends refreshing a cookie once it is more than 30 minutes old.
    refresh_after_seconds: u32 = 1800,

    pub fn validate(self: TimePolicy) error{InvalidCookie}!void {
        // RFC 1982 comparisons are only defined inside a half-range window.
        if (self.max_past_seconds >= 0x8000_0000 or
            self.max_future_seconds >= 0x8000_0000 or
            self.refresh_after_seconds >= 0x8000_0000)
        {
            return error.InvalidCookie;
        }
    }
};

pub const Verification = enum {
    valid,
    refresh,
};

pub const SecretMatch = enum {
    generation,
    alternate,
};

pub const RolloverVerification = struct {
    freshness: Verification,
    secret: SecretMatch,
};

/// Caller-owned RFC 9018 secret-rollover view.
///
/// Stage 1 uses the old secret as `generation` and the newly deployed secret
/// as `alternate_verify`. Stage 2 swaps those pointers. Stage 3 clears
/// `alternate_verify`. No secret lifetime or synchronization is owned here.
pub const SecretRoll = struct {
    generation: *const Version1.Secret,
    alternate_verify: ?*const Version1.Secret = null,

    pub fn make(self: SecretRoll, client: [client_length]u8, address: ClientAddress, now: u32) [version1_server_length]u8 {
        return makeVersion1(client, address, self.generation, now);
    }

    pub fn verify(self: SecretRoll, cookie: Cookie, address: ClientAddress, now: u32, policy: TimePolicy) Error!RolloverVerification {
        const primary = verifyVersion1(cookie, address, self.generation, now, policy) catch |err| switch (err) {
            error.BadHash => {
                const alternate = self.alternate_verify orelse return error.BadHash;
                return .{
                    .freshness = try verifyVersion1(cookie, address, alternate, now, policy),
                    .secret = .alternate,
                };
            },
            else => return err,
        };
        return .{ .freshness = primary, .secret = .generation };
    }
};

pub const ResponseError = error{
    IncorrectClientCookie,
    MissingServerCookie,
};

/// Validates the stateful part of RFC 7873 client-side response processing.
/// The caller remains responsible for deciding whether a COOKIE option was
/// expected at all; if present, the echoed Client Cookie must match and a
/// Server Cookie must be available to cache.
pub fn validateResponse(cookie: Cookie, expected_client: [client_length]u8) ResponseError![]const u8 {
    if (!std.crypto.timing_safe.eql([client_length]u8, cookie.client, expected_client)) {
        return error.IncorrectClientCookie;
    }
    return cookie.server orelse error.MissingServerCookie;
}

pub fn parseVersion1(cookie: Cookie) (error{ InvalidCookie, UnsupportedVersion })!Version1 {
    const server = cookie.server orelse return error.InvalidCookie;
    if (server.len != version1_server_length) return error.InvalidCookie;
    if (server[0] != Version1.version) return error.UnsupportedVersion;

    return .{
        .reserved = server[1..4].*,
        .timestamp = std.mem.readInt(u32, server[4..8], .big),
        .hash = server[8..16].*,
    };
}

/// Constructs the 16-octet RFC 9018 version-1 Server Cookie.
///
/// `now` is injected by the caller and is serialized as the unsigned Unix
/// timestamp sub-field. No clock or secret ownership is hidden in this helper.
pub fn makeVersion1(client: [client_length]u8, address: ClientAddress, secret: *const Version1.Secret, now: u32) [version1_server_length]u8 {
    var server: [version1_server_length]u8 = undefined;
    server[0] = Version1.version;
    @memset(server[1..4], 0);
    std.mem.writeInt(u32, server[4..8], now, .big);
    server[8..16].* = computeHash(client, server[0..8].*, address, secret);
    return server;
}

/// Verifies one RFC 9018 version-1 Server Cookie using one caller-owned secret.
///
/// Secret rollover policy is deliberately external: callers may retry with a
/// previous secret after `BadHash`. The received Reserved bytes are included in
/// the PRF and are not required to be zero, as mandated by RFC 9018.
pub fn verifyVersion1(cookie: Cookie, address: ClientAddress, secret: *const Version1.Secret, now: u32, policy: TimePolicy) Error!Verification {
    try policy.validate();
    const parsed = try parseVersion1(cookie);

    const expected = computeHash(cookie.client, .{ Version1.version, parsed.reserved[0], parsed.reserved[1], parsed.reserved[2], @truncate(parsed.timestamp >> 24), @truncate(parsed.timestamp >> 16), @truncate(parsed.timestamp >> 8), @truncate(parsed.timestamp) }, address, secret);
    if (!std.crypto.timing_safe.eql([8]u8, expected, parsed.hash)) return error.BadHash;

    const age = now -% parsed.timestamp;
    if (age == 0) return .valid;
    if (age == 0x8000_0000) return error.AmbiguousTimestamp;

    if (age < 0x8000_0000) {
        if (age > policy.max_past_seconds) return error.Expired;
        return if (age > policy.refresh_after_seconds) .refresh else .valid;
    }

    const future = parsed.timestamp -% now;
    if (future == 0x8000_0000) return error.AmbiguousTimestamp;
    if (future > policy.max_future_seconds) return error.FromFuture;
    return .valid;
}

fn computeHash(client: [client_length]u8, prefix: [8]u8, address: ClientAddress, secret: *const Version1.Secret) Version1.Hash {
    var input: [32]u8 = undefined;
    @memcpy(input[0..8], &client);
    @memcpy(input[8..16], &prefix);
    const ip = address.bytes();
    @memcpy(input[16 .. 16 + ip.len], ip);

    const SipHash24 = std.crypto.auth.siphash.SipHash64(2, 4);
    var result: Version1.Hash = undefined;
    SipHash24.create(&result, input[0 .. 16 + ip.len], secret);
    return result;
}

test "RFC 7873 COOKIE wire lengths" {
    const expectError = std.testing.expectError;

    _ = try parse(&([_]u8{0} ** 8));
    _ = try parse(&([_]u8{0} ** 16));
    _ = try parse(&([_]u8{0} ** 40));
    try expectError(error.InvalidCookie, parse(&([_]u8{0} ** 7)));
    try expectError(error.InvalidCookie, parse(&([_]u8{0} ** 9)));
    try expectError(error.InvalidCookie, parse(&([_]u8{0} ** 15)));
    try expectError(error.InvalidCookie, parse(&([_]u8{0} ** 41)));
}

test "RFC 9018 Appendix A.1 version-1 vector" {
    const secret: Version1.Secret = .{ 0xe5, 0xe9, 0x73, 0xe5, 0xa6, 0xb2, 0xa4, 0x3f, 0x48, 0xe7, 0xdc, 0x84, 0x9e, 0x37, 0xbf, 0xcf };
    const client: [8]u8 = .{ 0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57 };
    const expected_server: [16]u8 = .{ 0x01, 0x00, 0x00, 0x00, 0x5c, 0xf7, 0x9f, 0x11, 0x1f, 0x81, 0x30, 0xc3, 0xee, 0xe2, 0x94, 0x80 };

    const server = makeVersion1(client, .{ .ipv4 = .{ 198, 51, 100, 100 } }, &secret, 1_559_731_985);
    try std.testing.expectEqualSlices(u8, &expected_server, &server);

    var option: [24]u8 = undefined;
    @memcpy(option[0..8], &client);
    @memcpy(option[8..24], &expected_server);
    const result = try verifyVersion1(try parse(&option), .{ .ipv4 = .{ 198, 51, 100, 100 } }, &secret, 1_559_731_985, .{});
    try std.testing.expectEqual(Verification.valid, result);
}

test "RFC 9018 verification includes reserved bytes and serial time policy" {
    const secret: Version1.Secret = .{0x5a} ** 16;
    const client: [8]u8 = .{0xa5} ** 8;
    const address: ClientAddress = .{ .ipv6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12 };

    const server = makeVersion1(client, address, &secret, 1000);
    var option: [24]u8 = undefined;
    @memcpy(option[0..8], &client);
    @memcpy(option[8..24], &server);

    try std.testing.expectEqual(Verification.refresh, try verifyVersion1(try parse(&option), address, &secret, 1000 + 1801, .{}));
    try std.testing.expectError(error.Expired, verifyVersion1(try parse(&option), address, &secret, 1000 + 3601, .{}));
    try std.testing.expectError(error.FromFuture, verifyVersion1(try parse(&option), address, &secret, 699, .{}));

    // Reserved bytes are not constrained to zero during verification, but are
    // authenticated as part of the PRF input.
    option[9] = 1;
    try std.testing.expectError(error.BadHash, verifyVersion1(try parse(&option), address, &secret, 1000, .{}));
}

test "RFC 9018 Appendix A.2 renewed cookie vector" {
    const secret: Version1.Secret = .{ 0xe5, 0xe9, 0x73, 0xe5, 0xa6, 0xb2, 0xa4, 0x3f, 0x48, 0xe7, 0xdc, 0x84, 0x9e, 0x37, 0xbf, 0xcf };
    const client: [8]u8 = .{ 0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57 };
    const expected_server: [16]u8 = .{ 0x01, 0x00, 0x00, 0x00, 0x5c, 0xf7, 0xa8, 0x71, 0xd4, 0xa5, 0x64, 0xa1, 0x44, 0x2a, 0xca, 0x77 };

    const server = makeVersion1(client, .{ .ipv4 = .{ 198, 51, 100, 100 } }, &secret, 1_559_734_385);
    try std.testing.expectEqualSlices(u8, &expected_server, &server);
}

test "RFC 9018 Appendix A.3 verifies authenticated reserved bytes" {
    const secret: Version1.Secret = .{ 0xe5, 0xe9, 0x73, 0xe5, 0xa6, 0xb2, 0xa4, 0x3f, 0x48, 0xe7, 0xdc, 0x84, 0x9e, 0x37, 0xbf, 0xcf };
    const option: [24]u8 = .{
        0xfc, 0x93, 0xfc, 0x62, 0x80, 0x7d, 0xdb, 0x86,
        0x01, 0xab, 0xcd, 0xef, 0x5c, 0xf7, 0x8f, 0x71,
        0xa3, 0x14, 0x22, 0x7b, 0x66, 0x79, 0xeb, 0xf5,
    };
    const cookie = try parse(&option);
    const parsed = try parseVersion1(cookie);
    try std.testing.expectEqual([3]u8{ 0xab, 0xcd, 0xef }, parsed.reserved);

    // The Appendix calls this older cookie valid. Its age is beyond the
    // recommended default one-hour window, so the vector uses an explicit
    // two-hour operator policy while preserving the RFC 1982 checks.
    try std.testing.expectEqual(Verification.refresh, try verifyVersion1(
        cookie,
        .{ .ipv4 = .{ 203, 0, 113, 203 } },
        &secret,
        1_559_734_700,
        .{ .max_past_seconds = 7200 },
    ));

    const expected_fresh: [16]u8 = .{ 0x01, 0x00, 0x00, 0x00, 0x5c, 0xf7, 0xa9, 0xac, 0xf7, 0x3a, 0x78, 0x10, 0xac, 0xa2, 0x38, 0x1e };
    const fresh = makeVersion1(cookie.client, .{ .ipv4 = .{ 203, 0, 113, 203 } }, &secret, 1_559_734_700);
    try std.testing.expectEqualSlices(u8, &expected_fresh, &fresh);
}

test "RFC 9018 Appendix A.4 IPv6 secret rollover vector" {
    const old_secret: Version1.Secret = .{ 0xdd, 0x3b, 0xdf, 0x93, 0x44, 0xb6, 0x78, 0xb1, 0x85, 0xa6, 0xf5, 0xcb, 0x60, 0xfc, 0xa7, 0x15 };
    const new_secret: Version1.Secret = .{ 0x44, 0x55, 0x36, 0xbc, 0xd2, 0x51, 0x32, 0x98, 0x07, 0x5a, 0x5d, 0x37, 0x96, 0x63, 0xc9, 0x62 };
    const address: ClientAddress = .{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0x02, 0x20, 0x00, 0x01, 0x59, 0xde, 0xd0, 0xf4, 0x87, 0x69, 0x82, 0xb8 } };
    const option: [24]u8 = .{
        0x22, 0x68, 0x1a, 0xb9, 0x7d, 0x52, 0xc2, 0x98,
        0x01, 0x00, 0x00, 0x00, 0x5c, 0xf7, 0xc5, 0x79,
        0x26, 0x55, 0x6b, 0xd0, 0x93, 0x4c, 0x72, 0xf8,
    };
    const cookie = try parse(&option);

    // RFC 9018 Stage 2: generate with the new secret but continue accepting
    // cookies produced with the previous secret.
    const roll: SecretRoll = .{ .generation = &new_secret, .alternate_verify = &old_secret };
    const verified = try roll.verify(cookie, address, 1_559_741_961, .{});
    try std.testing.expectEqual(Verification.valid, verified.freshness);
    try std.testing.expectEqual(SecretMatch.alternate, verified.secret);

    const expected_fresh: [16]u8 = .{ 0x01, 0x00, 0x00, 0x00, 0x5c, 0xf7, 0xc6, 0x09, 0xa6, 0xbb, 0x79, 0xd1, 0x66, 0x25, 0x50, 0x7a };
    const fresh = roll.make(cookie.client, address, 1_559_741_961);
    try std.testing.expectEqualSlices(u8, &expected_fresh, &fresh);

    const stage3: SecretRoll = .{ .generation = &new_secret };
    try std.testing.expectError(error.BadHash, stage3.verify(cookie, address, 1_559_741_961, .{}));
}

test "client response validation requires echoed client and server cookie" {
    const expected: [8]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const server: [16]u8 = .{0xaa} ** 16;
    try std.testing.expectEqualSlices(u8, &server, try validateResponse(.{ .client = expected, .server = &server }, expected));

    var wrong = expected;
    wrong[7] ^= 1;
    try std.testing.expectError(error.IncorrectClientCookie, validateResponse(.{ .client = wrong, .server = &server }, expected));
    try std.testing.expectError(error.MissingServerCookie, validateResponse(.{ .client = expected, .server = null }, expected));
}

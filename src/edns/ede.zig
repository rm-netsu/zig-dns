const std = @import("std");

/// Extended DNS Error INFO-CODE registry snapshot.
///
/// Unknown and future values remain representable through the non-exhaustive
/// enum; protocol processing must never depend on EDE alone (RFC 8914 §3/§6).
pub const InfoCode = enum(u16) {
    other_error = 0,
    unsupported_dnskey_algorithm = 1,
    unsupported_ds_digest_type = 2,
    stale_answer = 3,
    forged_answer = 4,
    dnssec_indeterminate = 5,
    dnssec_bogus = 6,
    signature_expired = 7,
    signature_not_yet_valid = 8,
    dnskey_missing = 9,
    rrsigs_missing = 10,
    no_zone_key_bit_set = 11,
    nsec_missing = 12,
    cached_error = 13,
    not_ready = 14,
    blocked = 15,
    censored = 16,
    filtered = 17,
    prohibited = 18,
    stale_nxdomain_answer = 19,
    not_authoritative = 20,
    not_supported = 21,
    no_reachable_authority = 22,
    network_error = 23,
    invalid_data = 24,
    signature_expired_before_valid = 25,
    too_early = 26,
    unsupported_nsec3_iterations = 27,
    unable_to_conform_to_policy = 28,
    synthesized = 29,
    invalid_query_type = 30,
    rate_limited = 31,
    over_quota = 32,
    negative_trust_anchor = 33,
    new_delegation_only = 34,
    blocked_by_upstream_dns_server = 35,
    _,

    pub fn isPrivateUse(self: InfoCode) bool {
        return @intFromEnum(self) >= 49_152;
    }

    /// Objective grouping for diagnostics/telemetry only. It must not be used
    /// as a replacement for RCODE or other protocol-state processing.
    pub fn isDnssecRelated(self: InfoCode) bool {
        return switch (self) {
            .unsupported_dnskey_algorithm,
            .unsupported_ds_digest_type,
            .dnssec_indeterminate,
            .dnssec_bogus,
            .signature_expired,
            .signature_not_yet_valid,
            .dnskey_missing,
            .rrsigs_missing,
            .no_zone_key_bit_set,
            .nsec_missing,
            .invalid_data,
            .signature_expired_before_valid,
            .unsupported_nsec3_iterations,
            .negative_trust_anchor,
            => true,
            else => false,
        };
    }

    pub fn isStale(self: InfoCode) bool {
        return self == .stale_answer or self == .stale_nxdomain_answer;
    }

    pub fn isFilteringPolicy(self: InfoCode) bool {
        return switch (self) {
            .forged_answer,
            .blocked,
            .censored,
            .filtered,
            .prohibited,
            .unable_to_conform_to_policy,
            .blocked_by_upstream_dns_server,
            => true,
            else => false,
        };
    }
};

pub const ExtendedError = struct {
    info_code: u16,
    extra_text: []const u8,

    pub fn code(self: ExtendedError) InfoCode {
        return @enumFromInt(self.info_code);
    }
};

pub const Error = error{InvalidExtendedError};

pub fn parse(data: []const u8) Error!ExtendedError {
    if (data.len < 2) return error.InvalidExtendedError;
    const text = data[2..];
    // RFC 8914 defines EXTRA-TEXT as UTF-8 for human consumption. We validate
    // encoding only; higher-level RFC 5198 normalization/presentation policy
    // remains caller-owned.
    if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidExtendedError;
    return .{
        .info_code = std.mem.readInt(u16, data[0..2], .big),
        .extra_text = text,
    };
}

test "EDE parser preserves known unknown and private-use codes" {
    const known = try parse(&.{ 0x00, 0x06, 'b', 'o', 'g', 'u', 's' });
    try std.testing.expectEqual(InfoCode.dnssec_bogus, known.code());
    try std.testing.expect(known.code().isDnssecRelated());
    try std.testing.expectEqualStrings("bogus", known.extra_text);

    const unknown = try parse(&.{ 0x12, 0x34 });
    try std.testing.expectEqual(@as(u16, 0x1234), @intFromEnum(unknown.code()));
    try std.testing.expect(!unknown.code().isPrivateUse());

    const private = try parse(&.{ 0xc0, 0x00 });
    try std.testing.expect(private.code().isPrivateUse());
}

test "EDE parser rejects malformed UTF-8 but accepts empty text" {
    _ = try parse(&.{ 0x00, 0x00 });
    try std.testing.expectError(error.InvalidExtendedError, parse(&.{0}));
    try std.testing.expectError(error.InvalidExtendedError, parse(&.{ 0x00, 0x00, 0xc0 }));
}

test "EDE diagnostic group helpers do not infer protocol actions" {
    try std.testing.expect(InfoCode.stale_answer.isStale());
    try std.testing.expect(InfoCode.stale_nxdomain_answer.isStale());
    try std.testing.expect(InfoCode.blocked.isFilteringPolicy());
    try std.testing.expect(InfoCode.blocked_by_upstream_dns_server.isFilteringPolicy());
    try std.testing.expect(!InfoCode.network_error.isFilteringPolicy());
}

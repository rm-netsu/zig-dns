pub const Recommendation = enum {
    unknown,
    prohibited,
    may,
    recommended,
};

/// Policy is intentionally independent from cryptographic algorithm support.
/// A backend may understand an algorithm that policy rejects, or policy may
/// allow an algorithm for which the selected backend has no implementation.
pub const AlgorithmPolicy = struct {
    context: ?*const anyopaque = null,
    recommendation_fn: *const fn (?*const anyopaque, u8) Recommendation = registry2026Recommendation,

    pub fn recommendation(self: AlgorithmPolicy, algorithm: u8) Recommendation {
        return self.recommendation_fn(self.context, algorithm);
    }

    pub fn accepts(self: AlgorithmPolicy, algorithm: u8) bool {
        return switch (self.recommendation(algorithm)) {
            .may, .recommended => true,
            .unknown, .prohibited => false,
        };
    }

    /// IANA DNS Security Algorithm Numbers registry snapshot updated
    /// 2026-01-13 (RFC 9904/9905 era). The date in the name is deliberate:
    /// applications with a different policy lifetime should inject their own.
    pub const registry_2026_01_13: AlgorithmPolicy = .{};
};

fn registry2026Recommendation(_: ?*const anyopaque, algorithm: u8) Recommendation {
    return switch (algorithm) {
        1, 3, 6, 12 => .prohibited,
        5, 7, 8, 10, 13, 14, 15, 16 => .recommended,
        17, 23, 253, 254 => .may,
        else => .unknown,
    };
}

test "registry policy separates recommendations from unknown algorithms" {
    const p = AlgorithmPolicy.registry_2026_01_13;
    try @import("std").testing.expect(p.accepts(15));
    try @import("std").testing.expectEqual(Recommendation.prohibited, p.recommendation(3));
    try @import("std").testing.expectEqual(Recommendation.unknown, p.recommendation(200));
}

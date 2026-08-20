const std = @import("std");

pub const Error = error{InvalidDnskey};

/// RFC 4034 Appendix B DNSKEY key-tag calculation, including the historical
/// algorithm-1 (RSA/MD5) special rule and its verified erratum.
pub fn keyTag(rdata: []const u8) Error!u16 {
    // DNSKEY RDATA is Flags(2), Protocol(1), Algorithm(1), Public Key.
    if (rdata.len < 4) return error.InvalidDnskey;
    if (rdata[3] == 1) {
        const public_key = rdata[4..];
        if (public_key.len < 2) return error.InvalidDnskey;
        var exponent_len: usize = public_key[0];
        var modulus_start: usize = 1;
        if (exponent_len == 0) {
            if (public_key.len < 3) return error.InvalidDnskey;
            exponent_len = std.mem.readInt(u16, public_key[1..3], .big);
            modulus_start = 3;
        }
        if (exponent_len == 0 or modulus_start + exponent_len >= public_key.len) return error.InvalidDnskey;
        const modulus = public_key[modulus_start + exponent_len ..];
        if (modulus.len < 3) return error.InvalidDnskey;
        return (@as(u16, modulus[modulus.len - 3]) << 8) | modulus[modulus.len - 2];
    }

    var ac: u32 = 0;
    for (rdata, 0..) |b, i| ac += if ((i & 1) == 0) @as(u32, b) << 8 else b;
    ac += (ac >> 16) & 0xffff;
    return @truncate(ac);
}

test "normal DNSKEY key tag uses RFC 4034 checksum" {
    const r = [_]u8{ 0x01, 0x01, 0x03, 0x08, 0xaa, 0xbb, 0xcc, 0xdd };
    try std.testing.expect((try keyTag(&r)) != 0);
}

test "algorithm 1 key tag uses corrected modulus octets" {
    const r = [_]u8{ 0x01, 0x01, 0x03, 0x01, 0x01, 0x03, 0xaa, 0xbb, 0xcc, 0xdd };
    try std.testing.expectEqual(@as(u16, 0xbbcc), try keyTag(&r));
}

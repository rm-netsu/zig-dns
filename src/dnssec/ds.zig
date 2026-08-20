const std = @import("std");
const name_mod = @import("../name.zig");
const rdata = @import("../rdata.zig");
const key = @import("key.zig");

pub const Error = name_mod.Error || key.Error || error{
    BufferTooSmall,
    UnsupportedDigestAlgorithm,
    InvalidDnskey,
};

pub const Match = enum {
    match,
    key_tag_mismatch,
    algorithm_mismatch,
    digest_mismatch,
};

pub fn digestLength(digest_type: u8) Error!usize {
    return switch (digest_type) {
        1 => std.crypto.hash.Sha1.digest_length,
        2 => std.crypto.hash.sha2.Sha256.digest_length,
        4 => std.crypto.hash.sha2.Sha384.digest_length,
        else => error.UnsupportedDigestAlgorithm,
    };
}

/// Compute a DS digest over canonical owner name | DNSKEY RDATA.
/// Supports the algorithms required/recommended for validation by the
/// current IANA registry that Zig's standard crypto library provides:
/// SHA-1, SHA-256, and SHA-384.
pub fn digestDnskey(owner: name_mod.Name, dnskey_rdata: []const u8, digest_type: u8, out: []u8) Error![]const u8 {
    if (dnskey_rdata.len < 4 or dnskey_rdata[2] != 3) return error.InvalidDnskey;
    var owner_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const canonical_owner = try owner.writeCanonicalWire(&owner_buf);

    return switch (digest_type) {
        1 => hashInto(std.crypto.hash.Sha1, canonical_owner, dnskey_rdata, out),
        2 => hashInto(std.crypto.hash.sha2.Sha256, canonical_owner, dnskey_rdata, out),
        4 => hashInto(std.crypto.hash.sha2.Sha384, canonical_owner, dnskey_rdata, out),
        else => error.UnsupportedDigestAlgorithm,
    };
}

/// Match already-parsed DS fields against a DNSKEY RDATA blob. Unsupported
/// digest algorithms are signaled distinctly rather than treated as a
/// cryptographic mismatch.
pub fn matchDnskey(owner: name_mod.Name, ds: rdata.Ds, dnskey_rdata: []const u8, scratch: []u8) Error!Match {
    if (dnskey_rdata.len < 4 or dnskey_rdata[2] != 3) return error.InvalidDnskey;
    if (try key.keyTag(dnskey_rdata) != ds.key_tag) return .key_tag_mismatch;
    if (dnskey_rdata[3] != ds.algorithm) return .algorithm_mismatch;
    const digest = try digestDnskey(owner, dnskey_rdata, ds.digest_type, scratch);
    if (!std.mem.eql(u8, digest, ds.digest)) return .digest_mismatch;
    return .match;
}

fn hashInto(comptime Hash: type, owner: []const u8, dnskey_rdata: []const u8, out: []u8) Error![]const u8 {
    if (out.len < Hash.digest_length) return error.BufferTooSmall;
    var h = Hash.init(.{});
    h.update(owner);
    h.update(dnskey_rdata);
    h.final(out[0..Hash.digest_length]);
    return out[0..Hash.digest_length];
}

test "RFC 4034 DS example matches DNSKEY" {
    const owner_wire = [_]u8{ 5, 'd', 's', 'k', 'e', 'y', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const owner = try name_mod.Name.init(&owner_wire, 0);
    const public_key = [_]u8{
        0x01, 0x03, 0x9e, 0x8a, 0x24, 0x74, 0x18, 0xe3, 0x18, 0x90, 0x3b, 0x21, 0x5a, 0x84, 0x8a, 0xcf,
        0xd5, 0xf3, 0x7f, 0x02, 0x6b, 0xd4, 0x06, 0x2d, 0xb2, 0x6c, 0x77, 0x4c, 0x69, 0x09, 0x68, 0xd5,
        0xd5, 0x6d, 0xf8, 0xbf, 0xda, 0x91, 0xe6, 0xf3, 0x6d, 0x9a, 0x27, 0x98, 0x88, 0xf4, 0x13, 0x33,
        0x35, 0x7c, 0x5e, 0x60, 0x29, 0x99, 0x0d, 0x10, 0xfd, 0xf5, 0x66, 0x30, 0x62, 0xa5, 0x12, 0x76,
        0x33, 0x26, 0x98, 0x0a, 0x61, 0x5d, 0xdb, 0xf1, 0x7a, 0x05, 0xdd, 0xfc, 0xce, 0x7e, 0x5f, 0xb3,
        0xab, 0xcc, 0xa0, 0x5a, 0x31, 0xb0, 0x95, 0x74, 0x52, 0xd4, 0x52, 0x1e, 0x83, 0x87, 0x07, 0x89,
        0x06, 0x31, 0x15, 0xbf, 0x97, 0xf6, 0xc3, 0x08, 0xcc, 0xf5, 0x7c, 0xdc, 0x9c, 0xe7, 0xfe, 0x10,
        0xf6, 0xed, 0x1b, 0xd0, 0xcc, 0x06, 0x60, 0x03, 0x8c, 0x50, 0xdc, 0xdb, 0x0f, 0xeb, 0x96, 0x3c,
        0x2f, 0x17,
    };
    var dnskey_rdata: [4 + public_key.len]u8 = undefined;
    dnskey_rdata[0..4].* = .{ 0x01, 0x00, 0x03, 0x05 };
    dnskey_rdata[4..].* = public_key;
    try std.testing.expectEqual(@as(u16, 60485), try key.keyTag(&dnskey_rdata));

    const expected = [_]u8{ 0x2b, 0xb1, 0x83, 0xaf, 0x5f, 0x22, 0x58, 0x81, 0x79, 0xa5, 0x3b, 0x0a, 0x98, 0x63, 0x1f, 0xad, 0x1a, 0x29, 0x21, 0x18 };
    const ds: rdata.Ds = .{ .key_tag = 60485, .algorithm = 5, .digest_type = 1, .digest = &expected };
    var scratch: [48]u8 = undefined;
    try std.testing.expectEqual(Match.match, try matchDnskey(owner, ds, &dnskey_rdata, &scratch));
}

test "unsupported DS digest is not reported as mismatch" {
    const owner_wire = [_]u8{0};
    const owner = try name_mod.Name.init(&owner_wire, 0);
    const dnskey = [_]u8{ 0x01, 0x00, 0x03, 0x08, 1 };
    const ds: rdata.Ds = .{ .key_tag = try key.keyTag(&dnskey), .algorithm = 8, .digest_type = 250, .digest = &.{1} };
    var scratch: [64]u8 = undefined;
    try std.testing.expectError(error.UnsupportedDigestAlgorithm, matchDnskey(owner, ds, &dnskey, &scratch));
}

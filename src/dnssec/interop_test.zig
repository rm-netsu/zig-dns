const std = @import("std");
const builder = @import("../builder.zig");
const message = @import("../message.zig");
const name_mod = @import("../name.zig");
const types = @import("../types.zig");
const rrset_mod = @import("rrset.zig");
const verify = @import("verify.zig");

const Vector = struct {
    owner: []const u8,
    signer: []const u8,
    rr_type: types.Type,
    algorithm: u8,
    labels: u8,
    ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    dnskey_flags: u16 = 257,
    public_key_b64: []const u8,
    signature_b64: []const u8,
    rdata: union(enum) {
        a: [4]u8,
        mx: struct { preference: u16, exchange: []const u8 },
    },
};

fn verifyVector(vector: Vector, corrupt_signature: bool) !void {
    var public_key_storage: [512]u8 = undefined;
    const public_key = try decodeBase64(vector.public_key_b64, &public_key_storage);
    var signature_storage: [512]u8 = undefined;
    const signature = try decodeBase64(vector.signature_b64, &signature_storage);
    if (corrupt_signature) signature_storage[0] ^= 1;

    var packet: [2048]u8 = undefined;
    var compression: [64]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 1, .{ .response = true });

    switch (vector.rdata) {
        .a => |address| try b.addA(.answer, vector.owner, vector.ttl, address),
        .mx => |mx| try b.addMx(.answer, vector.owner, vector.ttl, mx.preference, mx.exchange),
    }

    var signer_wire_storage: [name_mod.Name.max_wire_len]u8 = undefined;
    const signer_wire = try presentationToWire(vector.signer, &signer_wire_storage);
    const signer = try name_mod.Uncompressed.init(signer_wire);
    var rrsig = try b.beginRecord(.answer, vector.owner, .RRSIG, .IN, vector.ttl);
    try rrsig.writeU16(@intFromEnum(vector.rr_type));
    try rrsig.writeByte(vector.algorithm);
    try rrsig.writeByte(vector.labels);
    try rrsig.writeU32(vector.ttl);
    try rrsig.writeU32(vector.expiration);
    try rrsig.writeU32(vector.inception);
    try rrsig.writeU16(vector.key_tag);
    try rrsig.writeWireName(signer);
    try rrsig.writeBytes(signature);
    try rrsig.finish();

    try b.addDnskey(.additional, vector.signer, vector.ttl, vector.dnskey_flags, vector.algorithm, public_key);
    const wire = try b.finish();

    const m = try message.Message.init(wire);
    var answers = try m.records(.answer);
    var records: [1]message.Record = undefined;
    records[0] = (try answers.next()).?;
    const rrsig_rr = (try answers.next()).?;
    var additional = try m.records(.additional);
    const dnskey_rr = (try additional.next()).?;
    const rrset = try rrset_mod.Rrset.init(&records);

    var signed_data: [2048]u8 = undefined;
    var order: [1]u16 = undefined;
    var compare: [512]u8 = undefined;
    try verify.verifyRrset(rrsig_rr, dnskey_rr, rrset, vector.inception, .{
        .signed_data = &signed_data,
        .order = &order,
        .compare = &compare,
    }, .{});
}

fn decodeBase64(encoded: []const u8, out: []u8) ![]const u8 {
    const len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    if (len > out.len) return error.NoSpaceLeft;
    try std.base64.standard.Decoder.decode(out[0..len], encoded);
    return out[0..len];
}

fn presentationToWire(presentation: []const u8, out: []u8) ![]const u8 {
    if (presentation.len == 0) return error.InvalidName;
    var in_pos: usize = 0;
    var out_pos: usize = 0;
    while (in_pos < presentation.len) {
        const dot = std.mem.indexOfScalarPos(u8, presentation, in_pos, '.') orelse presentation.len;
        const label = presentation[in_pos..dot];
        if (label.len == 0 or label.len > 63) return error.InvalidName;
        if (out.len - out_pos < 1 + label.len) return error.NoSpaceLeft;
        out[out_pos] = @intCast(label.len);
        out_pos += 1;
        @memcpy(out[out_pos..][0..label.len], label);
        out_pos += label.len;
        in_pos = dot + 1;
    }
    if (out_pos == out.len) return error.NoSpaceLeft;
    out[out_pos] = 0;
    return out[0 .. out_pos + 1];
}

test "RFC 8080 erratum 4935 Ed25519 RRSIG verifies" {
    try verifyVector(.{
        .owner = "example.com",
        .signer = "example.com",
        .rr_type = .MX,
        .algorithm = 15,
        .labels = 2,
        .ttl = 3600,
        .expiration = 1440021600,
        .inception = 1438207200,
        .key_tag = 3613,
        .public_key_b64 = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
        .signature_b64 = "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==",
        .rdata = .{ .mx = .{ .preference = 10, .exchange = "mail.example.com" } },
    }, false);
}

test "RFC 6605 P-256 RRSIG verifies" {
    try verifyVector(.{
        .owner = "www.example.net",
        .signer = "example.net",
        .rr_type = .A,
        .algorithm = 13,
        .labels = 3,
        .ttl = 3600,
        .expiration = 1284026679,
        .inception = 1281607479,
        .key_tag = 55648,
        .public_key_b64 = "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
        .signature_b64 = "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==",
        .rdata = .{ .a = .{ 192, 0, 2, 1 } },
    }, false);
}

test "RFC 6605 P-384 RRSIG verifies" {
    try verifyVector(.{
        .owner = "www.example.net",
        .signer = "example.net",
        .rr_type = .A,
        .algorithm = 14,
        .labels = 3,
        .ttl = 3600,
        .expiration = 1284027625,
        .inception = 1281608425,
        .key_tag = 10771,
        .public_key_b64 = "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40",
        .signature_b64 = "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm",
        .rdata = .{ .a = .{ 192, 0, 2, 1 } },
    }, false);
}

test "RFC 5702 RSA-SHA256 RRSIG verifies" {
    try verifyVector(.{
        .owner = "www.example.net",
        .signer = "example.net",
        .rr_type = .A,
        .algorithm = 8,
        .labels = 3,
        .ttl = 3600,
        .expiration = 1893456000,
        .inception = 946684800,
        .key_tag = 9033,
        .dnskey_flags = 256,
        .public_key_b64 = "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=",
        .signature_b64 = "kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg==",
        .rdata = .{ .a = .{ 192, 0, 2, 91 } },
    }, false);
}

test "RFC 5702 RSA-SHA512 RRSIG verifies" {
    try verifyVector(.{
        .owner = "www.example.net",
        .signer = "example.net",
        .rr_type = .A,
        .algorithm = 10,
        .labels = 3,
        .ttl = 3600,
        .expiration = 1893456000,
        .inception = 946684800,
        .key_tag = 3740,
        .dnskey_flags = 256,
        .public_key_b64 = "AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL",
        .signature_b64 = "tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw=",
        .rdata = .{ .a = .{ 192, 0, 2, 91 } },
    }, false);
}

test "corrupted independent RRSIG fails full validation" {
    try std.testing.expectError(error.InvalidSignature, verifyVector(.{
        .owner = "example.com",
        .signer = "example.com",
        .rr_type = .MX,
        .algorithm = 15,
        .labels = 2,
        .ttl = 3600,
        .expiration = 1440021600,
        .inception = 1438207200,
        .key_tag = 3613,
        .public_key_b64 = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
        .signature_b64 = "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==",
        .rdata = .{ .mx = .{ .preference = 10, .exchange = "mail.example.com" } },
    }, true));
}

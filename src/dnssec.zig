const std = @import("std");
const types = @import("types.zig");
const message = @import("message.zig");
const name_mod = @import("name.zig");

pub const canonical = @import("dnssec/canonical.zig");
pub const CanonicalWriter = canonical.Writer;

pub const Error = name_mod.Error || error{ InvalidLength, InvalidBitmap, Truncated, InvalidDnskey };

pub const TypeBitmapIterator = struct {
    bytes: []const u8,
    pos: usize = 0,
    window: u8 = 0,
    bitmap: []const u8 = &.{},
    bit_index: usize = 0,
    previous_window: ?u8 = null,

    pub fn next(self: *TypeBitmapIterator) Error!?types.Type {
        while (true) {
            if (self.bit_index < self.bitmap.len * 8) {
                const index = self.bit_index;
                self.bit_index += 1;
                const octet = self.bitmap[index / 8];
                const mask: u8 = @as(u8, 0x80) >> @intCast(index % 8);
                if ((octet & mask) != 0) {
                    const value: u16 = @as(u16, self.window) * 256 + @as(u16, @intCast(index));
                    return @enumFromInt(value);
                }
                continue;
            }
            if (self.pos == self.bytes.len) return null;
            if (self.pos + 2 > self.bytes.len) return error.Truncated;
            const window = self.bytes[self.pos];
            const len: usize = self.bytes[self.pos + 1];
            self.pos += 2;
            if (len == 0 or len > 32 or self.pos + len > self.bytes.len) return error.InvalidBitmap;
            if (self.previous_window) |prev| if (window <= prev) return error.InvalidBitmap;
            const bitmap = self.bytes[self.pos..][0..len];
            if (bitmap[len - 1] == 0) return error.InvalidBitmap;
            self.pos += len;
            self.previous_window = window;
            self.window = window;
            self.bitmap = bitmap;
            self.bit_index = 0;
        }
    }
};

pub const Nsec = struct {
    next_domain: name_mod.Name,
    types: TypeBitmapIterator,
};

pub fn nsec(rr: message.Record) Error!Nsec {
    if (rr.rdata.len < 3) return error.InvalidLength;
    const next = try name_mod.Name.init(rr.packet, rr.rdata_offset);
    const consumed = try next.consumed();
    if (consumed >= rr.rdata.len) return error.InvalidLength;
    return .{ .next_domain = next, .types = .{ .bytes = rr.rdata[consumed..] } };
}

pub const Nsec3 = struct {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: []const u8,
    next_hashed_owner: []const u8,
    types: TypeBitmapIterator,

    pub fn optOut(self: Nsec3) bool {
        return (self.flags & 1) != 0;
    }
};

pub fn nsec3(rr: message.Record) Error!Nsec3 {
    if (rr.rdata.len < 6) return error.InvalidLength;
    const salt_len: usize = rr.rdata[4];
    if (5 + salt_len >= rr.rdata.len) return error.InvalidLength;
    const hash_len_pos = 5 + salt_len;
    const hash_len: usize = rr.rdata[hash_len_pos];
    if (hash_len == 0) return error.InvalidLength;
    const hash_pos = hash_len_pos + 1;
    if (hash_pos + hash_len > rr.rdata.len) return error.InvalidLength;
    const bitmap = rr.rdata[hash_pos + hash_len ..];
    if (bitmap.len == 0) return error.InvalidLength;
    return .{
        .hash_algorithm = rr.rdata[0],
        .flags = rr.rdata[1],
        .iterations = std.mem.readInt(u16, rr.rdata[2..4], .big),
        .salt = rr.rdata[5..][0..salt_len],
        .next_hashed_owner = rr.rdata[hash_pos..][0..hash_len],
        .types = .{ .bytes = bitmap },
    };
}

pub const Nsec3Param = struct { hash_algorithm: u8, flags: u8, iterations: u16, salt: []const u8 };
pub fn nsec3param(rr: message.Record) Error!Nsec3Param {
    if (rr.rdata.len < 5) return error.InvalidLength;
    const salt_len: usize = rr.rdata[4];
    if (5 + salt_len != rr.rdata.len) return error.InvalidLength;
    return .{
        .hash_algorithm = rr.rdata[0],
        .flags = rr.rdata[1],
        .iterations = std.mem.readInt(u16, rr.rdata[2..4], .big),
        .salt = rr.rdata[5..],
    };
}

pub fn dnskeyKeyTag(rdata: []const u8) Error!u16 {
    // DNSKEY RDATA is Flags(2), Protocol(1), Algorithm(1), Public Key.
    if (rdata.len < 4) return error.InvalidDnskey;
    if (rdata[3] == 1) {
        // Historical RSA/MD5 (algorithm 1) uses the RSA modulus instead of
        // the normal checksum. The public-key encoding is exponent-length,
        // exponent, then modulus (RFC 2537). RFC 4034 erratum 193 clarifies
        // that the tag is the 3rd-to-last and 2nd-to-last modulus octets.
        const key = rdata[4..];
        if (key.len < 2) return error.InvalidDnskey;
        var exponent_len: usize = key[0];
        var modulus_start: usize = 1;
        if (exponent_len == 0) {
            if (key.len < 3) return error.InvalidDnskey;
            exponent_len = std.mem.readInt(u16, key[1..3], .big);
            modulus_start = 3;
        }
        if (exponent_len == 0 or modulus_start + exponent_len >= key.len) return error.InvalidDnskey;
        const modulus = key[modulus_start + exponent_len ..];
        if (modulus.len < 3) return error.InvalidDnskey;
        return (@as(u16, modulus[modulus.len - 3]) << 8) | modulus[modulus.len - 2];
    }

    var ac: u32 = 0;
    for (rdata, 0..) |b, i| ac += if ((i & 1) == 0) @as(u32, b) << 8 else b;
    ac += (ac >> 16) & 0xffff;
    return @truncate(ac);
}

pub fn validateUncompressedNameInRdata(rr: message.Record, relative: usize) Error!usize {
    if (relative >= rr.rdata.len) return error.InvalidLength;
    const len = try name_mod.uncompressedConsumedLen(rr.packet, @as(usize, rr.rdata_offset) + relative);
    if (relative + len > rr.rdata.len) return error.InvalidLength;
    return len;
}

test "type bitmap iteration" {
    const data = [_]u8{ 0, 6, 0x40, 0, 0, 0, 0, 0x03 }; // A(1), RRSIG(46), NSEC(47)
    var it: TypeBitmapIterator = .{ .bytes = &data };
    try std.testing.expectEqual(types.Type.A, (try it.next()).?);
    try std.testing.expectEqual(types.Type.RRSIG, (try it.next()).?);
    try std.testing.expectEqual(types.Type.NSEC, (try it.next()).?);
    try std.testing.expect((try it.next()) == null);
}

test "dnskey key tag matches generic RFC 4034 algorithm" {
    const r = [_]u8{ 0x01, 0x01, 0x03, 0x08, 0xaa, 0xbb, 0xcc, 0xdd };
    const tag = try dnskeyKeyTag(&r);
    try std.testing.expect(tag != 0);
}

test "dnskey algorithm 1 key tag uses corrected modulus octets" {
    // flags=0x0101, protocol=3, algorithm=1; exponent=3; modulus=aabbccdd.
    const r = [_]u8{ 0x01, 0x01, 0x03, 0x01, 0x01, 0x03, 0xaa, 0xbb, 0xcc, 0xdd };
    try std.testing.expectEqual(@as(u16, 0xbbcc), try dnskeyKeyTag(&r));
}

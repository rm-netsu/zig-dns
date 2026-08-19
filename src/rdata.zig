const std = @import("std");
const name_mod = @import("name.zig");
const message = @import("message.zig");

pub const Error = name_mod.Error || error{ InvalidLength, Truncated, InvalidField };

pub fn a(rr: message.Record) Error![4]u8 {
    if (rr.rdata.len != 4) return error.InvalidLength;
    return rr.rdata[0..4].*;
}

pub fn aaaa(rr: message.Record) Error![16]u8 {
    if (rr.rdata.len != 16) return error.InvalidLength;
    return rr.rdata[0..16].*;
}

pub fn targetName(rr: message.Record) Error!name_mod.Name {
    return nameAt(rr, 0);
}

fn nameAt(rr: message.Record, relative: usize) Error!name_mod.Name {
    if (relative >= rr.rdata.len) return error.InvalidLength;
    const absolute: usize = rr.rdata_offset + relative;
    const n = try name_mod.Name.init(rr.packet, absolute);
    const consumed = try n.consumed();
    if (relative + consumed > rr.rdata.len) return error.InvalidLength;
    return n;
}

pub const Mx = struct { preference: u16, exchange: name_mod.Name };
pub fn mx(rr: message.Record) Error!Mx {
    if (rr.rdata.len < 3) return error.InvalidLength;
    return .{ .preference = std.mem.readInt(u16, rr.rdata[0..2], .big), .exchange = try nameAt(rr, 2) };
}

pub const Srv = struct { priority: u16, weight: u16, port: u16, target: name_mod.Name };
pub fn srv(rr: message.Record) Error!Srv {
    if (rr.rdata.len < 7) return error.InvalidLength;
    return .{
        .priority = std.mem.readInt(u16, rr.rdata[0..2], .big),
        .weight = std.mem.readInt(u16, rr.rdata[2..4], .big),
        .port = std.mem.readInt(u16, rr.rdata[4..6], .big),
        .target = try nameAt(rr, 6),
    };
}

pub const Soa = struct {
    mname: name_mod.Name,
    rname: name_mod.Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
};
pub fn soa(rr: message.Record) Error!Soa {
    const mname = try nameAt(rr, 0);
    const mlen = try mname.consumed();
    const rname_off = @as(usize, rr.rdata_offset) + mlen;
    const rname_rel = rname_off - rr.rdata_offset;
    const rname = try nameAt(rr, rname_rel);
    const rlen = try rname.consumed();
    const p = rname_off + rlen;
    if (p + 20 != @as(usize, rr.rdata_offset) + rr.rdata.len) return error.InvalidLength;
    return .{
        .mname = mname,
        .rname = rname,
        .serial = std.mem.readInt(u32, rr.packet[p..][0..4], .big),
        .refresh = std.mem.readInt(u32, rr.packet[p + 4 ..][0..4], .big),
        .retry = std.mem.readInt(u32, rr.packet[p + 8 ..][0..4], .big),
        .expire = std.mem.readInt(u32, rr.packet[p + 12 ..][0..4], .big),
        .minimum = std.mem.readInt(u32, rr.packet[p + 16 ..][0..4], .big),
    };
}

pub const TxtIterator = struct {
    bytes: []const u8,
    pos: usize = 0,
    pub fn next(self: *TxtIterator) Error!?[]const u8 {
        if (self.pos == self.bytes.len) return null;
        const len: usize = self.bytes[self.pos];
        self.pos += 1;
        if (self.pos + len > self.bytes.len) return error.Truncated;
        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }
};
pub fn txt(rr: message.Record) TxtIterator {
    return .{ .bytes = rr.rdata };
}

pub const Caa = struct { flags: u8, tag: []const u8, value: []const u8 };
pub fn caa(rr: message.Record) Error!Caa {
    if (rr.rdata.len < 2) return error.InvalidLength;
    const tag_len: usize = rr.rdata[1];
    if (2 + tag_len > rr.rdata.len or tag_len == 0) return error.InvalidLength;
    return .{ .flags = rr.rdata[0], .tag = rr.rdata[2..][0..tag_len], .value = rr.rdata[2 + tag_len ..] };
}

pub const Ds = struct { key_tag: u16, algorithm: u8, digest_type: u8, digest: []const u8 };
pub fn ds(rr: message.Record) Error!Ds {
    if (rr.rdata.len < 4) return error.InvalidLength;
    return .{ .key_tag = std.mem.readInt(u16, rr.rdata[0..2], .big), .algorithm = rr.rdata[2], .digest_type = rr.rdata[3], .digest = rr.rdata[4..] };
}

pub const Dnskey = struct { flags: u16, protocol: u8, algorithm: u8, public_key: []const u8 };
pub fn dnskey(rr: message.Record) Error!Dnskey {
    if (rr.rdata.len < 4) return error.InvalidLength;
    return .{ .flags = std.mem.readInt(u16, rr.rdata[0..2], .big), .protocol = rr.rdata[2], .algorithm = rr.rdata[3], .public_key = rr.rdata[4..] };
}

pub const Rrsig = struct {
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer_name: name_mod.Name,
    signature: []const u8,
};
pub fn rrsig(rr: message.Record) Error!Rrsig {
    if (rr.rdata.len < 19) return error.InvalidLength;
    const signer_off: usize = rr.rdata_offset + 18;
    const signer = try nameAt(rr, 18);
    const consumed = try signer.consumed();
    const sig_off = signer_off + consumed;
    const end = @as(usize, rr.rdata_offset) + rr.rdata.len;
    if (sig_off > end) return error.InvalidLength;
    return .{
        .type_covered = std.mem.readInt(u16, rr.rdata[0..2], .big),
        .algorithm = rr.rdata[2],
        .labels = rr.rdata[3],
        .original_ttl = std.mem.readInt(u32, rr.rdata[4..8], .big),
        .expiration = std.mem.readInt(u32, rr.rdata[8..12], .big),
        .inception = std.mem.readInt(u32, rr.rdata[12..16], .big),
        .key_tag = std.mem.readInt(u16, rr.rdata[16..18], .big),
        .signer_name = signer,
        .signature = rr.packet[sig_off..end],
    };
}

pub const Tlsa = struct { usage: u8, selector: u8, matching_type: u8, association_data: []const u8 };
pub fn tlsa(rr: message.Record) Error!Tlsa {
    if (rr.rdata.len < 3) return error.InvalidLength;
    return .{ .usage = rr.rdata[0], .selector = rr.rdata[1], .matching_type = rr.rdata[2], .association_data = rr.rdata[3..] };
}

pub const SvcParam = struct { key: u16, value: []const u8 };
pub const SvcParamIterator = struct {
    bytes: []const u8,
    pos: usize = 0,
    last_key: ?u16 = null,
    pub fn next(self: *SvcParamIterator) Error!?SvcParam {
        if (self.pos == self.bytes.len) return null;
        if (self.pos + 4 > self.bytes.len) return error.Truncated;
        const key = std.mem.readInt(u16, self.bytes[self.pos..][0..2], .big);
        const len = std.mem.readInt(u16, self.bytes[self.pos + 2 ..][0..2], .big);
        self.pos += 4;
        if (self.pos + len > self.bytes.len) return error.Truncated;
        if (self.last_key) |prev| if (key <= prev) return error.InvalidField;
        self.last_key = key;
        const value = self.bytes[self.pos..][0..len];
        self.pos += len;
        return .{ .key = key, .value = value };
    }
};
pub const Svcb = struct { priority: u16, target: name_mod.Name, params: SvcParamIterator };
pub fn svcb(rr: message.Record) Error!Svcb {
    if (rr.rdata.len < 3) return error.InvalidLength;
    const target_off: usize = rr.rdata_offset + 2;
    const target = try nameAt(rr, 2);
    const consumed = try target.consumed();
    const param_off = target_off + consumed;
    const end: usize = rr.rdata_offset + rr.rdata.len;
    if (param_off > end) return error.InvalidLength;
    return .{ .priority = std.mem.readInt(u16, rr.rdata[0..2], .big), .target = target, .params = .{ .bytes = rr.packet[param_off..end] } };
}

pub const Sshfp = struct { algorithm: u8, fingerprint_type: u8, fingerprint: []const u8 };
pub fn sshfp(rr: message.Record) Error!Sshfp {
    if (rr.rdata.len < 3) return error.InvalidLength;
    return .{ .algorithm = rr.rdata[0], .fingerprint_type = rr.rdata[1], .fingerprint = rr.rdata[2..] };
}

pub const Uri = struct { priority: u16, weight: u16, target: []const u8 };
pub fn uri(rr: message.Record) Error!Uri {
    if (rr.rdata.len < 5) return error.InvalidLength;
    return .{
        .priority = std.mem.readInt(u16, rr.rdata[0..2], .big),
        .weight = std.mem.readInt(u16, rr.rdata[2..4], .big),
        .target = rr.rdata[4..],
    };
}

pub const Zonemd = struct { serial: u32, scheme: u8, hash_algorithm: u8, digest: []const u8 };
pub fn zonemd(rr: message.Record) Error!Zonemd {
    if (rr.rdata.len < 18) return error.InvalidLength; // fixed 6 octets + >=96-bit digest
    const scheme = rr.rdata[4];
    const hash_algorithm = rr.rdata[5];
    const digest = rr.rdata[6..];
    if ((hash_algorithm == 1 and digest.len != 48) or (hash_algorithm == 2 and digest.len != 64)) return error.InvalidLength;
    return .{
        .serial = std.mem.readInt(u32, rr.rdata[0..4], .big),
        .scheme = scheme,
        .hash_algorithm = hash_algorithm,
        .digest = digest,
    };
}

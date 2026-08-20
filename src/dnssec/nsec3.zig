const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const records_mod = @import("records.zig");
const proof_name = @import("proof_name.zig");

pub const Hash = [std.crypto.hash.Sha1.digest_length]u8;
pub const hash_label_len = 32;

pub const Error = records_mod.Error || proof_name.Error || error{
    NoNsec3Records,
    UnsupportedHashAlgorithm,
    InvalidFlags,
    IterationLimitExceeded,
    ParameterMismatch,
    InvalidOwnerHash,
    WrongZone,
    InvalidClosestEncloser,
};

pub const Parameters = struct {
    hash_algorithm: u8,
    iterations: u16,
    salt: []const u8,
};

pub const NoDataProof = enum {
    exact,
    opt_out,
};

pub const ClosestEncloserProof = struct {
    matching: message.Record,
    covering: message.Record,
    opt_out: bool,
};

/// A zero-allocation view over one selected, already-authenticated NSEC3 proof
/// chain. Callers explicitly provide an iteration limit; the protocol core
/// does not impose a hidden resolver policy.
pub const ProofSet = struct {
    zone: name_mod.Name,
    records: []const message.Record,
    parameters: Parameters,
    max_iterations: u16,

    pub fn init(zone: name_mod.Name, proof_records: []const message.Record, max_iterations: u16) Error!ProofSet {
        var parameters: ?Parameters = null;
        for (proof_records) |rr| {
            if (rr.rr_type != .NSEC3) continue;
            const view = try records_mod.nsec3(rr);
            if (view.hash_algorithm != 1) return error.UnsupportedHashAlgorithm;
            if (view.flags > 1) return error.InvalidFlags;
            if (view.iterations > max_iterations) return error.IterationLimitExceeded;
            _ = try ownerHash(rr, zone);

            if (parameters) |expected| {
                if (view.hash_algorithm != expected.hash_algorithm or
                    view.iterations != expected.iterations or
                    !std.mem.eql(u8, view.salt, expected.salt)) return error.ParameterMismatch;
            } else {
                parameters = .{
                    .hash_algorithm = view.hash_algorithm,
                    .iterations = view.iterations,
                    .salt = view.salt,
                };
            }
        }
        return .{
            .zone = zone,
            .records = proof_records,
            .parameters = parameters orelse return error.NoNsec3Records,
            .max_iterations = max_iterations,
        };
    }

    pub fn matchingRecord(self: ProofSet, candidate: name_mod.Name) Error!?message.Record {
        try self.requireInZone(candidate);
        const candidate_hash = try hashName(candidate, self.parameters, self.max_iterations);
        for (self.records) |rr| {
            if (rr.rr_type != .NSEC3) continue;
            if (std.mem.eql(u8, &(try ownerHash(rr, self.zone)), &candidate_hash)) return rr;
        }
        return null;
    }

    pub fn coveringRecord(self: ProofSet, candidate: name_mod.Name) Error!?message.Record {
        try self.requireInZone(candidate);
        const candidate_hash = try hashName(candidate, self.parameters, self.max_iterations);
        for (self.records) |rr| {
            if (rr.rr_type != .NSEC3) continue;
            const view = try records_mod.nsec3(rr);
            const owner_hash = try ownerHash(rr, self.zone);
            if (view.next_hashed_owner.len != Hash.len) return error.InvalidOwnerHash;
            var next_hash: Hash = undefined;
            @memcpy(&next_hash, view.next_hashed_owner);
            if (hashCovers(owner_hash, next_hash, candidate_hash)) return rr;
        }
        return null;
    }

    /// Verify RFC 5155's closest-encloser proof for a caller-selected
    /// candidate. The matching NSEC3 establishes the encloser's existence;
    /// the covering NSEC3 establishes that the next-closer name does not.
    pub fn provesClosestEncloser(self: ProofSet, qname: name_mod.Name, closest_encloser: name_mod.Name) Error!?ClosestEncloserProof {
        var q_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        var ce_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        var next_closer_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const q_wire = try qname.writeCanonicalWire(&q_wire_buf);
        const ce_wire = try closest_encloser.writeCanonicalWire(&ce_wire_buf);
        const next_closer = try proof_name.nextCloserName(q_wire, ce_wire, &next_closer_buf);

        const matching = (try self.matchingRecord(closest_encloser)) orelse return null;
        const matching_view = try records_mod.nsec3(matching);
        if (try matching_view.types.contains(.DNAME)) return error.InvalidClosestEncloser;
        if (try matching_view.types.contains(.NS) and !(try matching_view.types.contains(.SOA))) return error.InvalidClosestEncloser;

        const covering = (try self.coveringRecord(next_closer)) orelse return null;
        const covering_view = try records_mod.nsec3(covering);
        return .{ .matching = matching, .covering = covering, .opt_out = covering_view.optOut() };
    }

    /// RFC 5155 section 8.4: closest-encloser proof plus denial of the
    /// wildcard at that encloser.
    pub fn provesNameError(self: ProofSet, qname: name_mod.Name, closest_encloser: name_mod.Name) Error!bool {
        _ = (try self.provesClosestEncloser(qname, closest_encloser)) orelse return false;
        var ce_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        var wildcard_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const ce_wire = try closest_encloser.writeCanonicalWire(&ce_wire_buf);
        const wildcard = try proof_name.wildcardName(ce_wire, &wildcard_buf);
        return (try self.coveringRecord(wildcard)) != null;
    }

    /// Validate NODATA. A direct NSEC3 match proves exact absence. If there
    /// is no matching hash, a caller-supplied closest encloser may establish
    /// the verified RFC 5155 erratum's Opt-Out case.
    pub fn provesNoData(self: ProofSet, qname: name_mod.Name, qtype: types.Type, closest_encloser: ?name_mod.Name) Error!?NoDataProof {
        if (try self.matchingRecord(qname)) |matching| {
            const view = try records_mod.nsec3(matching);
            if (try view.types.contains(qtype)) return null;
            if (qtype != .CNAME and try view.types.contains(.CNAME)) return null;
            return .exact;
        }

        const ce = closest_encloser orelse return null;
        const closest = (try self.provesClosestEncloser(qname, ce)) orelse return null;
        return if (closest.opt_out) .opt_out else null;
    }

    /// RFC 5155 section 8.7: prove the closest encloser and an existing
    /// wildcard whose bitmap lacks QTYPE and CNAME.
    pub fn provesWildcardNoData(self: ProofSet, qname: name_mod.Name, qtype: types.Type, closest_encloser: name_mod.Name) Error!bool {
        _ = (try self.provesClosestEncloser(qname, closest_encloser)) orelse return false;
        var ce_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        var wildcard_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const ce_wire = try closest_encloser.writeCanonicalWire(&ce_wire_buf);
        const wildcard = try proof_name.wildcardName(ce_wire, &wildcard_buf);
        const matching = (try self.matchingRecord(wildcard)) orelse return false;
        const view = try records_mod.nsec3(matching);
        if (try view.types.contains(qtype)) return false;
        if (qtype != .CNAME and try view.types.contains(.CNAME)) return false;
        return true;
    }

    /// RFC 5155 section 8.8. The already-verified wildcard answer supplies
    /// the candidate closest encloser, so only the next-closer denial is
    /// required from NSEC3.
    pub fn provesWildcardAnswer(self: ProofSet, qname: name_mod.Name, closest_encloser: name_mod.Name) Error!bool {
        var q_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        var ce_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        var next_closer_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const q_wire = try qname.writeCanonicalWire(&q_wire_buf);
        const ce_wire = try closest_encloser.writeCanonicalWire(&ce_wire_buf);
        const next_closer = try proof_name.nextCloserName(q_wire, ce_wire, &next_closer_buf);
        return (try self.coveringRecord(next_closer)) != null;
    }

    fn requireInZone(self: ProofSet, candidate: name_mod.Name) Error!void {
        var candidate_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        var zone_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const candidate_wire = try candidate.writeCanonicalWire(&candidate_buf);
        const zone_wire = try self.zone.writeCanonicalWire(&zone_buf);
        if (!proof_name.isEqualOrSubdomain(candidate_wire, zone_wire)) return error.WrongZone;
    }
};

/// RFC 5155 NSEC3 hashing. `iterations` counts additional hashes after the
/// first. Only SHA-1 (algorithm 1) is currently defined for NSEC3.
pub fn hashName(name: name_mod.Name, parameters: Parameters, max_iterations: u16) Error!Hash {
    if (parameters.hash_algorithm != 1) return error.UnsupportedHashAlgorithm;
    if (parameters.iterations > max_iterations) return error.IterationLimitExceeded;

    var wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const canonical = try name.writeCanonicalWire(&wire_buf);
    var digest: Hash = undefined;
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(canonical);
    h.update(parameters.salt);
    h.final(&digest);

    var i: u16 = 0;
    while (i < parameters.iterations) : (i += 1) {
        var next: Hash = undefined;
        var round = std.crypto.hash.Sha1.init(.{});
        round.update(&digest);
        round.update(parameters.salt);
        round.final(&next);
        digest = next;
    }
    return digest;
}

pub fn encodeHash(hash: Hash, out: []u8) Error![]const u8 {
    if (out.len < hash_label_len) return error.BufferTooSmall;
    const alphabet = "0123456789abcdefghijklmnopqrstuv";
    var accumulator: u32 = 0;
    var bits: u8 = 0;
    var pos: usize = 0;
    for (hash) |byte| {
        accumulator = (accumulator << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[pos] = alphabet[@as(usize, @intCast((accumulator >> @intCast(bits)) & 0x1f))];
            pos += 1;
            accumulator &= if (bits == 0) 0 else (@as(u32, 1) << @intCast(bits)) - 1;
        }
    }
    std.debug.assert(bits == 0 and pos == hash_label_len);
    return out[0..pos];
}

pub fn decodeHash(label: []const u8) Error!Hash {
    if (label.len != hash_label_len) return error.InvalidOwnerHash;
    var out: Hash = undefined;
    var accumulator: u32 = 0;
    var bits: u8 = 0;
    var pos: usize = 0;
    for (label) |raw| {
        const c = std.ascii.toLower(raw);
        const value: u8 = if (c >= '0' and c <= '9')
            c - '0'
        else if (c >= 'a' and c <= 'v')
            c - 'a' + 10
        else
            return error.InvalidOwnerHash;
        accumulator = (accumulator << 5) | value;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            if (pos >= out.len) return error.InvalidOwnerHash;
            out[pos] = @truncate(accumulator >> @intCast(bits));
            pos += 1;
            accumulator &= if (bits == 0) 0 else (@as(u32, 1) << @intCast(bits)) - 1;
        }
    }
    if (bits != 0 or pos != out.len) return error.InvalidOwnerHash;
    return out;
}

fn ownerHash(rr: message.Record, zone: name_mod.Name) Error!Hash {
    var owner_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var zone_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const owner = try rr.name.writeCanonicalWire(&owner_buf);
    const zone_wire = try zone.writeCanonicalWire(&zone_buf);
    const label_len: usize = owner[0];
    if (label_len != hash_label_len or 1 + label_len >= owner.len) return error.InvalidOwnerHash;
    if (!std.mem.eql(u8, owner[1 + label_len ..], zone_wire)) return error.WrongZone;
    return decodeHash(owner[1..][0..label_len]);
}

fn hashCovers(owner: Hash, next: Hash, candidate: Hash) bool {
    const owner_to_next = std.mem.order(u8, &owner, &next);
    const owner_to_candidate = std.mem.order(u8, &owner, &candidate);
    if (owner_to_candidate == .eq) return false;
    const candidate_to_next = std.mem.order(u8, &candidate, &next);
    if (candidate_to_next == .eq) return false;
    return switch (owner_to_next) {
        .lt => owner_to_candidate == .lt and candidate_to_next == .lt,
        .gt => owner_to_candidate == .lt or candidate_to_next == .lt,
        .eq => true,
    };
}

fn parsedName(presentation: []const u8, out: []u8) !name_mod.Name {
    const wire = try name_mod.writePresentationWire(presentation, out);
    return name_mod.Name.init(wire, 0);
}

fn appendNsec3(
    builder: anytype,
    owner_hash: []const u8,
    next_hash_label: []const u8,
    flags: u8,
    bitmap: []const u8,
) !void {
    const next_hash = try decodeHash(next_hash_label);
    var owner_buf: [96]u8 = undefined;
    const owner = try std.fmt.bufPrint(&owner_buf, "{s}.example", .{owner_hash});
    var w = try builder.beginRecord(.authority, owner, .NSEC3, .IN, 3600);
    errdefer w.abort();
    try w.writeByte(1);
    try w.writeByte(flags);
    try w.writeU16(12);
    try w.writeByte(4);
    try w.writeBytes(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    try w.writeByte(Hash.len);
    try w.writeBytes(&next_hash);
    try w.writeBytes(bitmap);
    try w.finish();
}

const bitmap_a_rrsig = [_]u8{ 0, 6, 0x40, 0, 0, 0, 0, 0x02 };
const bitmap_cname_rrsig = [_]u8{ 0, 6, 0x04, 0, 0, 0, 0, 0x02 };

test "NSEC3 hashing matches RFC 5155 Appendix A" {
    var name_buf: [64]u8 = undefined;
    const example = try parsedName("ExAmPlE", &name_buf);
    const parameters: Parameters = .{ .hash_algorithm = 1, .iterations = 12, .salt = &.{ 0xaa, 0xbb, 0xcc, 0xdd } };
    const digest = try hashName(example, parameters, 12);
    var label: [hash_label_len]u8 = undefined;
    try std.testing.expectEqualStrings("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", try encodeHash(digest, &label));
    try std.testing.expectEqualSlices(u8, &digest, &(try decodeHash(&label)));
    try std.testing.expectError(error.IterationLimitExceeded, hashName(example, parameters, 11));
}

test "NSEC3 validates RFC 5155 name-error proof" {
    const builder_mod = @import("../builder.zig");
    var packet: [1024]u8 = undefined;
    var compression: [32]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 1, .{ .response = true });
    try appendNsec3(&b, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", "2t7b4g4vsa5smi47k61mv5bv1a22bojr", 1, &bitmap_a_rrsig);
    try appendNsec3(&b, "b4um86eghhds6nea196smvmlo4ors995", "gjeqe526plbf1g8mklp59enfd789njgi", 1, &bitmap_a_rrsig);
    try appendNsec3(&b, "35mthgpgcu1qg68fab165klnsnk3dpvl", "b4um86eghhds6nea196smvmlo4ors995", 1, &bitmap_a_rrsig);
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    var it = try m.records(.authority);
    var proof: [3]message.Record = undefined;
    for (&proof) |*rr| rr.* = (try it.next()).?;

    var zone_buf: [32]u8 = undefined;
    var q_buf: [96]u8 = undefined;
    var ce_buf: [64]u8 = undefined;
    const zone = try parsedName("example", &zone_buf);
    const qname = try parsedName("a.c.x.w.example", &q_buf);
    const closest = try parsedName("x.w.example", &ce_buf);
    const set = try ProofSet.init(zone, &proof, 12);
    try std.testing.expect(try set.provesNameError(qname, closest));
    try std.testing.expect(try set.provesWildcardAnswer(qname, closest));
    try std.testing.expectError(error.IterationLimitExceeded, ProofSet.init(zone, &proof, 11));
}

test "NSEC3 validates exact NODATA and rejects CNAME stripping" {
    const builder_mod = @import("../builder.zig");
    var packet: [768]u8 = undefined;
    var compression: [32]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 1, .{ .response = true });
    try appendNsec3(&b, "2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2vptu5timamqttgl4luu9kg21e0aor3s", 0, &bitmap_a_rrsig);
    try appendNsec3(&b, "gjeqe526plbf1g8mklp59enfd789njgi", "ji6neoaepv8b5o6k4ev33abha8ht9fgc", 0, &bitmap_cname_rrsig);
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    var it = try m.records(.authority);
    var proof: [2]message.Record = undefined;
    for (&proof) |*rr| rr.* = (try it.next()).?;

    var zone_buf: [32]u8 = undefined;
    var ns_buf: [64]u8 = undefined;
    var ai_buf: [64]u8 = undefined;
    const zone = try parsedName("example", &zone_buf);
    const ns1 = try parsedName("ns1.example", &ns_buf);
    const ai = try parsedName("ai.example", &ai_buf);
    const set = try ProofSet.init(zone, &proof, 12);
    try std.testing.expectEqual(NoDataProof.exact, (try set.provesNoData(ns1, .MX, null)).?);
    try std.testing.expect((try set.provesNoData(ns1, .A, null)) == null);
    try std.testing.expect((try set.provesNoData(ai, .MX, null)) == null);
}

test "NSEC3 exposes Opt-Out NODATA proof separately" {
    const builder_mod = @import("../builder.zig");
    var packet: [768]u8 = undefined;
    var compression: [32]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 1, .{ .response = true });
    // H(example) matches the closest encloser. 35m... -> b4um... covers
    // H(c.example)=4g6p9u5gvfshp30pqecj98b3maqbn1ck and is Opt-Out.
    try appendNsec3(&b, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", "2t7b4g4vsa5smi47k61mv5bv1a22bojr", 1, &bitmap_a_rrsig);
    try appendNsec3(&b, "35mthgpgcu1qg68fab165klnsnk3dpvl", "b4um86eghhds6nea196smvmlo4ors995", 1, &bitmap_a_rrsig);
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    var it = try m.records(.authority);
    var proof: [2]message.Record = undefined;
    for (&proof) |*rr| rr.* = (try it.next()).?;

    var zone_buf: [32]u8 = undefined;
    var q_buf: [64]u8 = undefined;
    var ce_buf: [32]u8 = undefined;
    const zone = try parsedName("example", &zone_buf);
    const qname = try parsedName("c.example", &q_buf);
    const closest = try parsedName("example", &ce_buf);
    const set = try ProofSet.init(zone, &proof, 12);
    try std.testing.expectEqual(NoDataProof.opt_out, (try set.provesNoData(qname, .DS, closest)).?);
}

const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const records = @import("records.zig");
const proof_name = @import("proof_name.zig");

pub const nsec3 = @import("nsec3.zig");

pub const Error = records.Error || proof_name.Error || error{NotNsec};

/// Returns whether an authenticated NSEC RR covers `candidate` in RFC 4034
/// canonical name order. The caller remains responsible for authenticating the
/// NSEC RRset and ensuring that the candidate belongs to the intended zone.
pub fn nsecCovers(rr: message.Record, candidate: name_mod.Name) Error!bool {
    if (rr.rr_type != .NSEC) return error.NotNsec;
    const view = try records.nsec(rr);
    const owner_to_next = try rr.name.canonicalCompare(view.next_domain);
    const owner_to_candidate = try rr.name.canonicalCompare(candidate);
    if (owner_to_candidate == .eq) return false;
    const candidate_to_next = try candidate.canonicalCompare(view.next_domain);
    if (candidate_to_next == .eq) return false;

    return switch (owner_to_next) {
        .lt => owner_to_candidate == .lt and candidate_to_next == .lt,
        .gt => owner_to_candidate == .lt or candidate_to_next == .lt,
        // A one-name NSEC chain wraps from the owner back to itself and covers
        // every other name.
        .eq => true,
    };
}

/// Validate an authenticated NSEC proof for NOERROR/NODATA at an exact owner.
/// RFC 6840 requires checking CNAME in addition to QTYPE.
pub fn nsecProvesNoData(rr: message.Record, qname: name_mod.Name, qtype: types.Type) Error!bool {
    if (rr.rr_type != .NSEC) return error.NotNsec;
    if (!(try rr.name.eqlIgnoreCase(qname))) return false;
    const view = try records.nsec(rr);
    if (try view.types.contains(qtype)) return false;
    if (qtype != .CNAME and try view.types.contains(.CNAME)) return false;
    return true;
}

/// Validate the NSEC coverage portion of an NXDOMAIN proof.
///
/// `closest_encloser` must have been independently authenticated by the caller.
/// The proof requires one authenticated NSEC covering QNAME and one covering
/// `*.<closest_encloser>`; one RR may satisfy both conditions.
pub fn nsecProvesNameError(qname: name_mod.Name, closest_encloser: name_mod.Name, proof: []const message.Record) Error!bool {
    var q_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var ce_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const q_wire = try qname.writeCanonicalWire(&q_wire_buf);
    const ce_wire = try closest_encloser.writeCanonicalWire(&ce_wire_buf);
    _ = try proof_name.strictSuffixOffset(q_wire, ce_wire);

    var wildcard_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const wildcard = try proof_name.wildcardName(ce_wire, &wildcard_buf);
    return (try anyNsecCovers(proof, qname)) and (try anyNsecCovers(proof, wildcard));
}

/// Validate the NSEC proof that a positive wildcard answer did not bypass a
/// closer matching name. `closest_encloser` is authenticated externally.
pub fn nsecProvesWildcardAnswer(qname: name_mod.Name, closest_encloser: name_mod.Name, proof: []const message.Record) Error!bool {
    var q_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var ce_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var next_closer_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const q_wire = try qname.writeCanonicalWire(&q_wire_buf);
    const ce_wire = try closest_encloser.writeCanonicalWire(&ce_wire_buf);
    const next_closer = try proof_name.nextCloserName(q_wire, ce_wire, &next_closer_buf);
    return anyNsecCovers(proof, next_closer);
}

/// Validate NSEC proofs for wildcard NODATA: the wildcard owner exists but
/// lacks both QTYPE and CNAME, and no closer name can match QNAME.
pub fn nsecProvesWildcardNoData(qname: name_mod.Name, qtype: types.Type, closest_encloser: name_mod.Name, proof: []const message.Record) Error!bool {
    var q_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var ce_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var wildcard_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var next_closer_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const q_wire = try qname.writeCanonicalWire(&q_wire_buf);
    const ce_wire = try closest_encloser.writeCanonicalWire(&ce_wire_buf);
    const wildcard = try proof_name.wildcardName(ce_wire, &wildcard_buf);
    const next_closer = try proof_name.nextCloserName(q_wire, ce_wire, &next_closer_buf);

    var wildcard_nodata = false;
    for (proof) |rr| {
        if (rr.rr_type != .NSEC) continue;
        if (try nsecProvesNoData(rr, wildcard, qtype)) {
            wildcard_nodata = true;
            break;
        }
    }
    return wildcard_nodata and (try anyNsecCovers(proof, next_closer));
}

fn anyNsecCovers(proof: []const message.Record, candidate: name_mod.Name) Error!bool {
    for (proof) |rr| {
        if (rr.rr_type != .NSEC) continue;
        if (try nsecCovers(rr, candidate)) return true;
    }
    return false;
}

fn appendNsec(builder: anytype, owner: []const u8, next: []const u8, bitmap: []const u8) !void {
    var next_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const next_wire = try name_mod.writePresentationWire(next, &next_buf);
    var w = try builder.beginRecord(.authority, owner, .NSEC, .IN, 300);
    errdefer w.abort();
    try w.writeWireName(try name_mod.Uncompressed.init(next_wire));
    try w.writeBytes(bitmap);
    try w.finish();
}

fn parsedName(presentation: []const u8, out: []u8) !name_mod.Name {
    const wire = try name_mod.writePresentationWire(presentation, out);
    return name_mod.Name.init(wire, 0);
}

const bitmap_a_rrsig_nsec = [_]u8{ 0, 6, 0x40, 0, 0, 0, 0, 0x03 };
const bitmap_cname_rrsig_nsec = [_]u8{ 0, 6, 0x04, 0, 0, 0, 0, 0x03 };

test "NSEC canonical interval handles ordinary and wrap-around coverage" {
    const builder_mod = @import("../builder.zig");
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 1, .{ .response = true });
    try appendNsec(&b, "a.example", "d.example", &bitmap_a_rrsig_nsec);
    try appendNsec(&b, "z.example", "a.example", &bitmap_a_rrsig_nsec);
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    var it = try m.records(.authority);
    const ordinary = (try it.next()).?;
    const wrap = (try it.next()).?;

    var q1_buf: [64]u8 = undefined;
    var q2_buf: [64]u8 = undefined;
    var q3_buf: [64]u8 = undefined;
    const q1 = try parsedName("b.example", &q1_buf);
    const q2 = try parsedName("zz.example", &q2_buf);
    const q3 = try parsedName("a.example", &q3_buf);
    try std.testing.expect(try nsecCovers(ordinary, q1));
    try std.testing.expect(try nsecCovers(wrap, q2));
    try std.testing.expect(!(try nsecCovers(ordinary, q3)));
}

test "NSEC NODATA rejects CNAME stripping" {
    const builder_mod = @import("../builder.zig");
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 1, .{ .response = true });
    try appendNsec(&b, "host.example", "next.example", &bitmap_a_rrsig_nsec);
    try appendNsec(&b, "alias.example", "host.example", &bitmap_cname_rrsig_nsec);
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    var it = try m.records(.authority);
    const host = (try it.next()).?;
    const alias = (try it.next()).?;

    var host_buf: [64]u8 = undefined;
    var alias_buf: [64]u8 = undefined;
    const host_name = try parsedName("HOST.EXAMPLE", &host_buf);
    const alias_name = try parsedName("alias.example", &alias_buf);
    try std.testing.expect(try nsecProvesNoData(host, host_name, .AAAA));
    try std.testing.expect(!(try nsecProvesNoData(alias, alias_name, .AAAA)));
}

test "NSEC validates NXDOMAIN wildcard and wildcard NODATA proof pieces" {
    const builder_mod = @import("../builder.zig");
    var packet: [768]u8 = undefined;
    var compression: [32]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 1, .{ .response = true });
    try appendNsec(&b, "example", "a.example", &bitmap_a_rrsig_nsec);
    try appendNsec(&b, "a.example", "d.example", &bitmap_a_rrsig_nsec);
    try appendNsec(&b, "*.example", "example", &bitmap_a_rrsig_nsec);
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    var it = try m.records(.authority);
    var proof: [3]message.Record = undefined;
    for (&proof) |*rr| rr.* = (try it.next()).?;

    var q_buf: [64]u8 = undefined;
    var ce_buf: [64]u8 = undefined;
    const qname = try parsedName("x.b.example", &q_buf);
    const closest = try parsedName("example", &ce_buf);
    try std.testing.expect(try nsecProvesNameError(qname, closest, &proof));
    try std.testing.expect(try nsecProvesWildcardAnswer(qname, closest, &proof));
    try std.testing.expect(try nsecProvesWildcardNoData(qname, .AAAA, closest, &proof));

    var bad_ce_buf: [64]u8 = undefined;
    const bad_ce = try parsedName("other.example", &bad_ce_buf);
    try std.testing.expectError(error.NotSubdomain, nsecProvesNameError(qname, bad_ce, &proof));
}

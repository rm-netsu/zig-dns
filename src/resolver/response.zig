const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const client = @import("../client.zig");
const builder = @import("../builder.zig");
const referral_mod = @import("referral.zig");

pub const Error = referral_mod.Error;

/// Transport-neutral semantic classification of a transaction-matched QUERY
/// response. `cname`/`dname` borrow the corresponding RR from `Message`.
///
/// The caller is expected to validate transaction identity/question matching
/// first (for example through `client.validateResponse` or
/// `resolver.FixedTransactions.match`).
pub const Outcome = union(enum) {
    answer,
    cname: message.Record,
    dname: message.Record,
    referral,
    nodata,
    nxdomain,
    servfail,
    formerr,
    truncated,
    failure: types.Rcode,
};

/// Classify a response without allocation or transport ownership.
///
/// RFC 2308 makes NXDOMAIN authoritative from RCODE regardless of NS/SOA
/// contents. For NOERROR/no relevant answer, SOA means NODATA while NS without
/// SOA means referral. An empty Authority section is also NODATA.
pub fn classify(m: message.Message, q: client.QuestionKey) Error!Outcome {
    var qname_storage: [name_mod.Name.max_wire_len]u8 = undefined;
    const qname_wire = try name_mod.writePresentationWire(q.name, &qname_storage);
    return classifyName(m, try name_mod.Name.init(qname_wire, 0), q.qtype, q.qclass);
}

/// Wire-name form of `classify`, preserving arbitrary label octets.
pub fn classifyWire(m: message.Message, q: client.WireQuestionKey) Error!Outcome {
    return classifyName(m, try name_mod.Name.init(q.name.bytes, 0), q.qtype, q.qclass);
}

fn classifyName(m: message.Message, qname: name_mod.Name, qtype: types.Type, qclass: types.Class) Error!Outcome {
    if (m.header.flags.truncated) return .truncated;

    const rcode = try m.rcode();
    switch (rcode) {
        .no_error => {},
        .format_error => return .formerr,
        .server_failure => return .servfail,
        .name_error => return .nxdomain,
        else => return .{ .failure = rcode },
    }

    var cname: ?message.Record = null;
    var dname: ?message.Record = null;
    var answers = try m.records(.answer);
    while (try answers.next()) |rr| {
        if (rr.class != qclass) continue;

        const owner_matches = try rr.name.eqlIgnoreCase(qname);
        if (owner_matches and (rr.rr_type == qtype or qtype == .ANY)) return .answer;

        if (rr.rr_type == .DNAME and qtype != .DNAME and !owner_matches and dname == null) {
            if (try qname.isSubdomainOf(rr.name)) dname = rr;
        }
        if (rr.rr_type == .CNAME and qtype != .CNAME and owner_matches and cname == null) cname = rr;
    }

    if (dname) |rr| return .{ .dname = rr };
    if (cname) |rr| return .{ .cname = rr };

    var has_soa = false;
    var has_ns = false;
    var authority = try m.records(.authority);
    while (try authority.next()) |rr| {
        if (rr.class != qclass) continue;
        switch (rr.rr_type) {
            .SOA => has_soa = true,
            .NS => has_ns = true,
            else => {},
        }
    }

    if (has_ns and !has_soa) {
        _ = try referral_mod.Referral.initName(m, qname, qclass);
        return .referral;
    }
    return .nodata;
}

fn messageFromBuilder(b: *builder.Builder) !message.Message {
    return message.Message.init(try b.finish());
}

fn expectTag(expected: std.meta.Tag(Outcome), actual: Outcome) !void {
    try std.testing.expectEqual(expected, std.meta.activeTag(actual));
}

test "classifies direct answer" {
    var buf: [256]u8 = undefined;
    var compression: [16]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&buf, &compression, 1, .{ .response = true });
    try b.addQuestion("www.example", .A, .IN);
    try b.addA(.answer, "www.example", 60, .{ 192, 0, 2, 1 });
    try expectTag(.answer, try classify(try messageFromBuilder(&b), .{ .name = "www.example", .qtype = .A }));
}

test "classifies CNAME redirect unless CNAME was requested" {
    var buf: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;

    var b = try builder.Builder.init(&buf, &compression, 2, .{ .response = true });
    try b.addQuestion("www.example", .A, .IN);
    try b.addNameRecord(.answer, "www.example", .CNAME, 60, "target.example");
    const redirected = try classify(try messageFromBuilder(&b), .{ .name = "www.example", .qtype = .A });
    try expectTag(.cname, redirected);
    try std.testing.expect(try redirected.cname.name.eqlPresentationIgnoreCase("www.example"));

    var b2 = try builder.Builder.init(&buf, &compression, 3, .{ .response = true });
    try b2.addQuestion("www.example", .CNAME, .IN);
    try b2.addNameRecord(.answer, "www.example", .CNAME, 60, "target.example");
    try expectTag(.answer, try classify(try messageFromBuilder(&b2), .{ .name = "www.example", .qtype = .CNAME }));
}

test "DNAME outranks synthesized CNAME but exact DNAME is a direct answer" {
    var buf: [768]u8 = undefined;
    var compression: [32]builder.CompressionEntry = undefined;

    var b = try builder.Builder.init(&buf, &compression, 4, .{ .response = true });
    try b.addQuestion("host.old.example", .A, .IN);
    try b.addNameRecord(.answer, "old.example", .DNAME, 300, "new.example");
    try b.addNameRecord(.answer, "host.old.example", .CNAME, 300, "host.new.example");
    const redirected = try classify(try messageFromBuilder(&b), .{ .name = "host.old.example", .qtype = .A });
    try expectTag(.dname, redirected);
    try std.testing.expect(try redirected.dname.name.eqlPresentationIgnoreCase("old.example"));

    var b2 = try builder.Builder.init(&buf, &compression, 5, .{ .response = true });
    try b2.addQuestion("old.example", .DNAME, .IN);
    try b2.addNameRecord(.answer, "old.example", .DNAME, 300, "new.example");
    try expectTag(.answer, try classify(try messageFromBuilder(&b2), .{ .name = "old.example", .qtype = .DNAME }));
}

test "classifies referral and RFC 2308 NODATA forms" {
    var buf: [768]u8 = undefined;
    var compression: [32]builder.CompressionEntry = undefined;

    var referral = try builder.Builder.init(&buf, &compression, 6, .{ .response = true });
    try referral.addQuestion("host.child.example", .A, .IN);
    try referral.addNameRecord(.authority, "child.example", .NS, 300, "ns.child.example");
    try referral.addA(.additional, "ns.child.example", 300, .{ 192, 0, 2, 53 });
    try expectTag(.referral, try classify(try messageFromBuilder(&referral), .{ .name = "host.child.example", .qtype = .A }));

    var nodata = try builder.Builder.init(&buf, &compression, 7, .{ .response = true, .authoritative = true });
    try nodata.addQuestion("host.example", .AAAA, .IN);
    try nodata.addSoa(.authority, "example", 60, "ns.example", "hostmaster.example", 1, 3600, 600, 86400, 60);
    try nodata.addNameRecord(.authority, "example", .NS, 60, "ns.example");
    try expectTag(.nodata, try classify(try messageFromBuilder(&nodata), .{ .name = "host.example", .qtype = .AAAA }));

    var empty = try builder.Builder.init(&buf, &compression, 8, .{ .response = true });
    try empty.addQuestion("host.example", .AAAA, .IN);
    try expectTag(.nodata, try classify(try messageFromBuilder(&empty), .{ .name = "host.example", .qtype = .AAAA }));
}

test "terminal RCODE and truncation take precedence over section hints" {
    var buf: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;

    var nx = try builder.Builder.init(&buf, &compression, 9, .{ .response = true, .rcode_low = 3 });
    try nx.addQuestion("missing.example", .A, .IN);
    try nx.addNameRecord(.answer, "missing.example", .CNAME, 60, "also-missing.example");
    try nx.addNameRecord(.authority, "example", .NS, 60, "ns.example");
    try expectTag(.nxdomain, try classify(try messageFromBuilder(&nx), .{ .name = "missing.example", .qtype = .A }));

    var fail = try builder.Builder.init(&buf, &compression, 10, .{ .response = true, .rcode_low = 2 });
    try fail.addQuestion("example", .A, .IN);
    try expectTag(.servfail, try classify(try messageFromBuilder(&fail), .{ .name = "example", .qtype = .A }));

    var formerr = try builder.Builder.init(&buf, &compression, 11, .{ .response = true, .rcode_low = 1 });
    try formerr.addQuestion("example", .A, .IN);
    try expectTag(.formerr, try classify(try messageFromBuilder(&formerr), .{ .name = "example", .qtype = .A }));

    var refused = try builder.Builder.init(&buf, &compression, 12, .{ .response = true, .rcode_low = 5 });
    try refused.addQuestion("example", .A, .IN);
    const other = try classify(try messageFromBuilder(&refused), .{ .name = "example", .qtype = .A });
    try expectTag(.failure, other);
    try std.testing.expectEqual(types.Rcode.refused, other.failure);

    var tc = try builder.Builder.init(&buf, &compression, 13, .{ .response = true, .truncated = true, .rcode_low = 2 });
    try tc.addQuestion("example", .A, .IN);
    try expectTag(.truncated, try classify(try messageFromBuilder(&tc), .{ .name = "example", .qtype = .A }));
}

test "class mismatch and unrelated aliases do not fabricate an answer" {
    var buf: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&buf, &compression, 14, .{ .response = true });
    try b.addQuestion("wanted.example", .A, .IN);
    try b.addNameRecord(.answer, "other.example", .CNAME, 60, "target.example");
    try b.addRawRecord(.answer, "wanted.example", .A, @enumFromInt(3), 60, &.{ 192, 0, 2, 1 });
    try expectTag(.nodata, try classify(try messageFromBuilder(&b), .{ .name = "wanted.example", .qtype = .A }));
}

test "wire classification preserves arbitrary label octets" {
    const wire_name = [_]u8{ 3, 'a', 0, 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    const qname = try name_mod.Uncompressed.init(&wire_name);
    var buf: [256]u8 = undefined;
    var compression: [12]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&buf, &compression, 16, .{ .response = true });
    try b.addQuestionWire(qname, .A, .IN);
    try b.addA(.answer, "other.example", 60, .{ 192, 0, 2, 1 });
    const m = try messageFromBuilder(&b);
    try expectTag(.nodata, try classifyWire(m, .{ .name = qname, .qtype = .A }));
}

test "does not classify unrelated authority NS as referral" {
    var buf: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&buf, &compression, 15, .{ .response = true });
    try b.addQuestion("wanted.example", .A, .IN);
    try b.addNameRecord(.authority, "unrelated.test", .NS, 60, "ns.unrelated.test");
    try std.testing.expectError(
        error.NotReferral,
        classify(try messageFromBuilder(&b), .{ .name = "wanted.example", .qtype = .A }),
    );
}

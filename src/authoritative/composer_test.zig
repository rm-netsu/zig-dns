const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const builder = @import("../builder.zig");
const edns = @import("../edns.zig");
const api = @import("types.zig");
const composer_mod = @import("composer.zig");
const store_mod = @import("store.zig");
const h = @import("name_helpers.zig");

const ZoneRecord = api.ZoneRecord;
const Options = api.Options;
const ProofKind = api.ProofKind;
const Kind = api.Kind;
const Composer = composer_mod.Composer;
const SliceStore = store_mod.SliceStore;

fn wire(comptime presentation: []const u8) [presentation.len + 2]u8 {
    var out: [presentation.len + 2]u8 = undefined;
    const value = name_mod.writePresentationWire(presentation, &out) catch unreachable;
    std.debug.assert(value.len == out.len);
    return out;
}

const TestStore = struct {
    pub const Error = error{};

    const Item = struct { rr: ZoneRecord };
    pub const RecordIterator = struct {
        items: []const Item,
        owner: name_mod.Uncompressed,
        rr_type: types.Type,
        pos: usize = 0,
        match_all: bool = false,

        pub fn next(self: *RecordIterator) Error!?ZoneRecord {
            while (self.pos < self.items.len) {
                const rr = self.items[self.pos].rr;
                self.pos += 1;
                if (self.match_all or (rr.rr_type == self.rr_type and (h.namesEqual(rr.owner, self.owner) catch false))) return rr;
            }
            return null;
        }
    };

    items: []const Item,
    proof_items: []const Item = &.{},
    apex_name: name_mod.Uncompressed,
    delegation: ?name_mod.Uncompressed = null,
    dname_owner: ?name_mod.Uncompressed = null,
    wildcard_owner: ?name_mod.Uncompressed = null,

    pub fn apex(self: *TestStore) name_mod.Uncompressed {
        return self.apex_name;
    }

    pub fn lookup(self: *TestStore, owner: name_mod.Uncompressed, rr_type: types.Type) Error!?RecordIterator {
        const it: RecordIterator = .{ .items = self.items, .owner = owner, .rr_type = rr_type };
        var probe = it;
        if ((try probe.next()) == null) return null;
        return it;
    }

    pub fn nameExists(self: *TestStore, owner: name_mod.Uncompressed) Error!bool {
        for (self.items) |item| if (h.namesEqual(item.rr.owner, owner) catch false) return true;
        return false;
    }

    pub fn findDelegation(self: *TestStore, qname: name_mod.Uncompressed) Error!?name_mod.Uncompressed {
        if (self.delegation) |cut| if (h.isSubdomain(qname, cut) catch false) return cut;
        return null;
    }

    pub fn findDname(self: *TestStore, qname: name_mod.Uncompressed) Error!?name_mod.Uncompressed {
        if (self.dname_owner) |owner| {
            if (!(h.namesEqual(qname, owner) catch false) and (h.isSubdomain(qname, owner) catch false)) return owner;
        }
        return null;
    }

    pub fn findWildcard(self: *TestStore, qname: name_mod.Uncompressed) Error!?name_mod.Uncompressed {
        _ = qname;
        return self.wildcard_owner;
    }

    pub fn dnssecProof(self: *TestStore, kind: ProofKind, qname: name_mod.Uncompressed, qtype: types.Type) Error!?RecordIterator {
        _ = kind;
        _ = qname;
        _ = qtype;
        if (self.proof_items.len == 0) return null;
        return .{ .items = self.proof_items, .owner = self.apex_name, .rr_type = .NSEC, .match_all = true };
    }
};

fn makeQuery(out: []u8, compression: []builder.CompressionEntry, qname: []const u8, qtype: types.Type, with_edns: bool) !message.Message {
    var b = try builder.Builder.init(out, compression, 0x1234, .{ .recursion_desired = true });
    try b.addQuestion(qname, qtype, .IN);
    if (with_edns) try b.addOpt(1232, 0, 0, .{}, &.{});
    return message.Message.init(try b.finish());
}

fn firstRecord(m: message.Message, section: types.Section) !message.Record {
    var it = try m.records(section);
    return (try it.next()).?;
}

const apex_wire_storage = wire("example");
const www_wire_storage = wire("www.example");
const alias_wire_storage = wire("alias.example");
const missing_wire_storage = wire("missing.example");
const wildcard_wire_storage = wire("*.example");
const child_wire_storage = wire("child.example");
const ns_child_wire_storage = wire("ns.child.example");
const old_wire_storage = wire("old.example");
const new_wire_storage = wire("new.example");
const ent_wire_storage = wire("ent.example");
const host_ent_wire_storage = wire("host.ent.example");
const missing_ent_wire_storage = wire("missing.ent.example");
const host_child_wire_storage = wire("host.child.example");
const x_old_wire_storage = wire("x.old.example");
const ns_wire_storage = wire("ns.example");
const hostmaster_wire_storage = wire("hostmaster.example");
const apex_wire: []const u8 = &apex_wire_storage;
const www_wire: []const u8 = &www_wire_storage;
const alias_wire: []const u8 = &alias_wire_storage;
const missing_wire: []const u8 = &missing_wire_storage;
const wildcard_wire: []const u8 = &wildcard_wire_storage;
const child_wire: []const u8 = &child_wire_storage;
const ns_child_wire: []const u8 = &ns_child_wire_storage;
const old_wire: []const u8 = &old_wire_storage;
const new_wire: []const u8 = &new_wire_storage;
const ent_wire: []const u8 = &ent_wire_storage;
const host_ent_wire: []const u8 = &host_ent_wire_storage;
const missing_ent_wire: []const u8 = &missing_ent_wire_storage;
const host_child_wire: []const u8 = &host_child_wire_storage;
const x_old_wire: []const u8 = &x_old_wire_storage;
const ns_wire: []const u8 = &ns_wire_storage;
const hostmaster_wire: []const u8 = &hostmaster_wire_storage;

fn soaRdata() [wire("ns.example").len + wire("hostmaster.example").len + 20]u8 {
    var out: [wire("ns.example").len + wire("hostmaster.example").len + 20]u8 = undefined;
    var pos: usize = 0;
    @memcpy(out[pos..][0..ns_wire.len], ns_wire);
    pos += ns_wire.len;
    @memcpy(out[pos..][0..hostmaster_wire.len], hostmaster_wire);
    pos += hostmaster_wire.len;
    inline for (.{ @as(u32, 1), 3600, 600, 86400, 60 }) |v| {
        std.mem.writeInt(u32, out[pos..][0..4], v, .big);
        pos += 4;
    }
    return out;
}

const soa_rdata = soaRdata();

fn rrsigRdata(comptime covered: types.Type) [18 + apex_wire.len + 64]u8 {
    var out: [18 + apex_wire.len + 64]u8 = [_]u8{0} ** (18 + apex_wire.len + 64);
    std.mem.writeInt(u16, out[0..2], @intFromEnum(covered), .big);
    out[2] = 15; // Ed25519 algorithm number; signature bytes are fixture-only.
    out[3] = 1;
    std.mem.writeInt(u32, out[4..8], 300, .big);
    std.mem.writeInt(u32, out[8..12], 2_000_000_000, .big);
    std.mem.writeInt(u32, out[12..16], 1_000_000_000, .big);
    std.mem.writeInt(u16, out[16..18], 0x1234, .big);
    @memcpy(out[18..][0..apex_wire.len], apex_wire);
    @memset(out[18 + apex_wire.len ..], 0x5a);
    return out;
}

const rrsig_a_rdata = rrsigRdata(.A);
const rrsig_soa_rdata = rrsigRdata(.SOA);
const rrsig_nsec_rdata = rrsigRdata(.NSEC);
const nsec_next_storage = wire("zzz.example");
const nsec_bitmap = [_]u8{ 0, 6, 0x40, 0, 0, 0, 0, 0x03 };
fn nsecRdata() [nsec_next_storage.len + nsec_bitmap.len]u8 {
    var out: [nsec_next_storage.len + nsec_bitmap.len]u8 = undefined;
    @memcpy(out[0..nsec_next_storage.len], &nsec_next_storage);
    @memcpy(out[nsec_next_storage.len..], &nsec_bitmap);
    return out;
}
const nsec_rdata = nsecRdata();

const base_items = [_]TestStore.Item{
    .{ .rr = .{ .owner = .{ .bytes = apex_wire }, .rr_type = .SOA, .class = .IN, .ttl = 60, .rdata = &soa_rdata } },
    .{ .rr = .{ .owner = .{ .bytes = www_wire }, .rr_type = .A, .class = .IN, .ttl = 300, .rdata = &.{ 192, 0, 2, 1 } } },
    .{ .rr = .{ .owner = .{ .bytes = alias_wire }, .rr_type = .CNAME, .class = .IN, .ttl = 300, .rdata = www_wire } },
    .{ .rr = .{ .owner = .{ .bytes = wildcard_wire }, .rr_type = .A, .class = .IN, .ttl = 120, .rdata = &.{ 192, 0, 2, 99 } } },
    .{ .rr = .{ .owner = .{ .bytes = child_wire }, .rr_type = .NS, .class = .IN, .ttl = 600, .rdata = ns_child_wire } },
    .{ .rr = .{ .owner = .{ .bytes = ns_child_wire }, .rr_type = .A, .class = .IN, .ttl = 600, .rdata = &.{ 192, 0, 2, 53 } } },
    .{ .rr = .{ .owner = .{ .bytes = old_wire }, .rr_type = .DNAME, .class = .IN, .ttl = 300, .rdata = new_wire } },
};

test "SliceStore resolves empty non-terminals closest wildcard delegation and DNAME" {
    const records = [_]ZoneRecord{
        .{ .owner = .{ .bytes = apex_wire }, .rr_type = .SOA, .class = .IN, .ttl = 60, .rdata = &soa_rdata },
        .{ .owner = .{ .bytes = wildcard_wire }, .rr_type = .A, .class = .IN, .ttl = 60, .rdata = &.{ 192, 0, 2, 44 } },
        .{ .owner = .{ .bytes = host_ent_wire }, .rr_type = .A, .class = .IN, .ttl = 60, .rdata = &.{ 192, 0, 2, 45 } },
        .{ .owner = .{ .bytes = child_wire }, .rr_type = .NS, .class = .IN, .ttl = 60, .rdata = ns_child_wire },
        .{ .owner = .{ .bytes = ns_child_wire }, .rr_type = .A, .class = .IN, .ttl = 60, .rdata = &.{ 192, 0, 2, 53 } },
        .{ .owner = .{ .bytes = old_wire }, .rr_type = .DNAME, .class = .IN, .ttl = 60, .rdata = new_wire },
    };
    var store = SliceStore.init(.{ .bytes = apex_wire }, &records);

    try std.testing.expect(try store.nameExists(.{ .bytes = ent_wire })); // empty non-terminal
    const wildcard = (try store.findWildcard(.{ .bytes = missing_wire })).?;
    try std.testing.expect(try h.namesEqual(wildcard, .{ .bytes = wildcard_wire }));
    try std.testing.expect((try store.findWildcard(.{ .bytes = missing_ent_wire })) == null);

    const cut = (try store.findDelegation(.{ .bytes = host_child_wire })).?;
    try std.testing.expect(try h.namesEqual(cut, .{ .bytes = child_wire }));
    const dname_owner = (try store.findDname(.{ .bytes = x_old_wire })).?;
    try std.testing.expect(try h.namesEqual(dname_owner, .{ .bytes = old_wire }));
}

test "SliceStore composes wildcard and empty-nonterminal NODATA without custom glue code" {
    const records = [_]ZoneRecord{
        .{ .owner = .{ .bytes = apex_wire }, .rr_type = .SOA, .class = .IN, .ttl = 60, .rdata = &soa_rdata },
        .{ .owner = .{ .bytes = wildcard_wire }, .rr_type = .A, .class = .IN, .ttl = 60, .rdata = &.{ 192, 0, 2, 77 } },
        .{ .owner = .{ .bytes = host_ent_wire }, .rr_type = .A, .class = .IN, .ttl = 60, .rdata = &.{ 192, 0, 2, 78 } },
    };
    var store = SliceStore.init(.{ .bytes = apex_wire }, &records);
    var composer = Composer(SliceStore).init(&store);
    var qbuf: [512]u8 = undefined;
    var qcomp: [24]builder.CompressionEntry = undefined;
    var out: [1024]u8 = undefined;
    var comp: [48]builder.CompressionEntry = undefined;

    const wildcard = try composer.compose(try makeQuery(&qbuf, &qcomp, "missing.example", .A, false), &out, &comp, .{});
    try std.testing.expectEqual(Kind.wildcard, wildcard.kind);

    const ent = try composer.compose(try makeQuery(&qbuf, &qcomp, "ent.example", .AAAA, false), &out, &comp, .{});
    try std.testing.expectEqual(Kind.nodata, ent.kind);
    try std.testing.expectEqual(types.Rcode.no_error, (try message.Message.init(ent.bytes)).header.flags.rcode());
}

test "authoritative composer answers exact CNAME wildcard and negative queries" {
    var store: TestStore = .{ .items = &base_items, .apex_name = .{ .bytes = apex_wire } };
    var composer = Composer(TestStore).init(&store);
    var qbuf: [512]u8 = undefined;
    var qcomp: [24]builder.CompressionEntry = undefined;
    var out: [1232]u8 = undefined;
    var comp: [64]builder.CompressionEntry = undefined;

    const direct = try composer.compose(try makeQuery(&qbuf, &qcomp, "www.example", .A, true), &out, &comp, .{});
    try std.testing.expectEqual(Kind.answer, direct.kind);
    const dm = try message.Message.init(direct.bytes);
    try std.testing.expect(dm.header.flags.authoritative);
    try std.testing.expectEqual(@as(u16, 1), dm.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), dm.header.additional_count); // OPT

    const cname = try composer.compose(try makeQuery(&qbuf, &qcomp, "alias.example", .A, false), &out, &comp, .{});
    try std.testing.expectEqual(Kind.cname, cname.kind);
    try std.testing.expectEqual(types.Type.CNAME, (try firstRecord(try message.Message.init(cname.bytes), .answer)).rr_type);

    store.wildcard_owner = .{ .bytes = wildcard_wire };
    const wildcard = try composer.compose(try makeQuery(&qbuf, &qcomp, "missing.example", .A, false), &out, &comp, .{});
    try std.testing.expectEqual(Kind.wildcard, wildcard.kind);
    const wr = try firstRecord(try message.Message.init(wildcard.bytes), .answer);
    try std.testing.expect(try wr.name.eqlPresentationIgnoreCase("missing.example"));

    store.wildcard_owner = null;
    const nx = try composer.compose(try makeQuery(&qbuf, &qcomp, "missing.example", .A, false), &out, &comp, .{});
    try std.testing.expectEqual(Kind.nxdomain, nx.kind);
    const nxm = try message.Message.init(nx.bytes);
    try std.testing.expectEqual(types.Rcode.name_error, nxm.header.flags.rcode());
    try std.testing.expectEqual(types.Type.SOA, (try firstRecord(nxm, .authority)).rr_type);
}

test "authoritative referral adds only in-zone glue and clears AA" {
    var store: TestStore = .{
        .items = &base_items,
        .apex_name = .{ .bytes = apex_wire },
        .delegation = .{ .bytes = child_wire },
    };
    var composer = Composer(TestStore).init(&store);
    var qbuf: [512]u8 = undefined;
    var qcomp: [24]builder.CompressionEntry = undefined;
    var out: [1232]u8 = undefined;
    var comp: [64]builder.CompressionEntry = undefined;

    const result = try composer.compose(try makeQuery(&qbuf, &qcomp, "host.child.example", .A, false), &out, &comp, .{});
    try std.testing.expectEqual(Kind.referral, result.kind);
    const m = try message.Message.init(result.bytes);
    try std.testing.expect(!m.header.flags.authoritative);
    try std.testing.expectEqual(types.Type.NS, (try firstRecord(m, .authority)).rr_type);
    try std.testing.expectEqual(types.Type.A, (try firstRecord(m, .additional)).rr_type);
}

test "authoritative DNAME emits DNAME and synthesized CNAME" {
    var store: TestStore = .{
        .items = &base_items,
        .apex_name = .{ .bytes = apex_wire },
        .dname_owner = .{ .bytes = old_wire },
    };
    var composer = Composer(TestStore).init(&store);
    var qbuf: [512]u8 = undefined;
    var qcomp: [24]builder.CompressionEntry = undefined;
    var out: [1232]u8 = undefined;
    var comp: [64]builder.CompressionEntry = undefined;

    const result = try composer.compose(try makeQuery(&qbuf, &qcomp, "host.old.example", .A, false), &out, &comp, .{});
    try std.testing.expectEqual(Kind.dname, result.kind);
    const m = try message.Message.init(result.bytes);
    var answers = try m.records(.answer);
    const dname_rr = (try answers.next()).?;
    const cname_rr = (try answers.next()).?;
    try std.testing.expectEqual(types.Type.DNAME, dname_rr.rr_type);
    try std.testing.expectEqual(types.Type.CNAME, cname_rr.rr_type);
    const target = try cname_rr.rdataName();
    try std.testing.expect(try target.eqlPresentationIgnoreCase("host.new.example"));
}

test "authoritative DS at a delegation is answered or returns parent NODATA" {
    const ds_rdata = [_]u8{ 0x12, 0x34, 15, 2, 0xaa, 0xbb, 0xcc, 0xdd };
    const with_ds = [_]TestStore.Item{
        .{ .rr = .{ .owner = .{ .bytes = apex_wire }, .rr_type = .SOA, .class = .IN, .ttl = 60, .rdata = &soa_rdata } },
        .{ .rr = .{ .owner = .{ .bytes = child_wire }, .rr_type = .NS, .class = .IN, .ttl = 600, .rdata = ns_child_wire } },
        .{ .rr = .{ .owner = .{ .bytes = child_wire }, .rr_type = .DS, .class = .IN, .ttl = 600, .rdata = &ds_rdata } },
    };
    var store: TestStore = .{ .items = &with_ds, .apex_name = .{ .bytes = apex_wire }, .delegation = .{ .bytes = child_wire } };
    var composer = Composer(TestStore).init(&store);
    var qbuf: [512]u8 = undefined;
    var qcomp: [24]builder.CompressionEntry = undefined;
    var out: [1024]u8 = undefined;
    var comp: [48]builder.CompressionEntry = undefined;

    const answered = try composer.compose(try makeQuery(&qbuf, &qcomp, "child.example", .DS, false), &out, &comp, .{});
    try std.testing.expectEqual(Kind.answer, answered.kind);
    try std.testing.expect((try message.Message.init(answered.bytes)).header.flags.authoritative);

    const without_ds = [_]TestStore.Item{
        .{ .rr = .{ .owner = .{ .bytes = apex_wire }, .rr_type = .SOA, .class = .IN, .ttl = 60, .rdata = &soa_rdata } },
        .{ .rr = .{ .owner = .{ .bytes = child_wire }, .rr_type = .NS, .class = .IN, .ttl = 600, .rdata = ns_child_wire } },
    };
    store.items = &without_ds;
    const nodata = try composer.compose(try makeQuery(&qbuf, &qcomp, "child.example", .DS, false), &out, &comp, .{});
    try std.testing.expectEqual(Kind.nodata, nodata.kind);
    try std.testing.expectEqual(types.Type.SOA, (try firstRecord(try message.Message.init(nodata.bytes), .authority)).rr_type);
}

test "authoritative EDNS BADVERS uses extended RCODE and clamps UDP payload floor" {
    var store: TestStore = .{ .items = &base_items, .apex_name = .{ .bytes = apex_wire } };
    var composer = Composer(TestStore).init(&store);
    var qbuf: [512]u8 = undefined;
    var qcomp: [24]builder.CompressionEntry = undefined;
    var qb = try builder.Builder.init(&qbuf, &qcomp, 0x9999, .{});
    try qb.addQuestion("www.example", .A, .IN);
    try qb.addOpt(128, 0, 1, .{ .dnssec_ok = true }, &.{});
    const query = try message.Message.init(try qb.finish());

    var out: [1024]u8 = undefined;
    var comp: [48]builder.CompressionEntry = undefined;
    const result = try composer.compose(query, &out, &comp, .{ .max_udp_payload = 128 });
    try std.testing.expectEqual(Kind.bad_edns_version, result.kind);
    const response = try message.Message.init(result.bytes);
    try std.testing.expectEqual(types.Rcode.bad_version_or_signature, try response.rcode());
    try std.testing.expectEqual(@as(u16, 1), response.header.additional_count);
    var additional = try response.records(.additional);
    const opt = try edns.Opt.fromRecord((try additional.next()).?);
    try std.testing.expectEqual(@as(u16, 512), opt.udp_payload_size);
    try std.testing.expectEqual(@as(u8, 0), opt.version);
    try std.testing.expect(opt.flags.dnssec_ok);
}

test "authoritative ANY policy is explicit and store-selected" {
    var store: TestStore = .{ .items = &base_items, .apex_name = .{ .bytes = apex_wire } };
    var composer = Composer(TestStore).init(&store);
    var qbuf: [512]u8 = undefined;
    var qcomp: [24]builder.CompressionEntry = undefined;
    var out: [1024]u8 = undefined;
    var comp: [48]builder.CompressionEntry = undefined;

    const refused = try composer.compose(try makeQuery(&qbuf, &qcomp, "www.example", .ANY, false), &out, &comp, .{});
    try std.testing.expectEqual(Kind.refused, refused.kind);

    const selected = try composer.compose(try makeQuery(&qbuf, &qcomp, "www.example", .ANY, false), &out, &comp, .{ .any_policy = .{ .rr_type = .A } });
    try std.testing.expectEqual(Kind.answer, selected.kind);
    try std.testing.expectEqual(types.Type.A, (try firstRecord(try message.Message.init(selected.bytes), .answer)).rr_type);
}

test "authoritative responses remain structurally strict" {
    const validate = @import("../validate.zig");
    var store: TestStore = .{ .items = &base_items, .apex_name = .{ .bytes = apex_wire }, .delegation = .{ .bytes = child_wire } };
    var composer = Composer(TestStore).init(&store);
    var qbuf: [512]u8 = undefined;
    var qcomp: [24]builder.CompressionEntry = undefined;
    var out: [1232]u8 = undefined;
    var comp: [64]builder.CompressionEntry = undefined;

    const referral = try composer.compose(try makeQuery(&qbuf, &qcomp, "host.child.example", .AAAA, true), &out, &comp, .{});
    _ = try validate.messageStrict(try message.Message.init(referral.bytes), .{});
    store.delegation = null;
    const negative = try composer.compose(try makeQuery(&qbuf, &qcomp, "missing.example", .AAAA, true), &out, &comp, .{});
    _ = try validate.messageStrict(try message.Message.init(negative.bytes), .{});
}

test "authoritative signed responses add matching RRSIG and denial proof only for DO" {
    const signed_items = [_]TestStore.Item{
        .{ .rr = .{ .owner = .{ .bytes = apex_wire }, .rr_type = .SOA, .class = .IN, .ttl = 60, .rdata = &soa_rdata } },
        .{ .rr = .{ .owner = .{ .bytes = apex_wire }, .rr_type = .RRSIG, .class = .IN, .ttl = 60, .rdata = &rrsig_soa_rdata } },
        .{ .rr = .{ .owner = .{ .bytes = www_wire }, .rr_type = .A, .class = .IN, .ttl = 300, .rdata = &.{ 192, 0, 2, 1 } } },
        .{ .rr = .{ .owner = .{ .bytes = www_wire }, .rr_type = .RRSIG, .class = .IN, .ttl = 300, .rdata = &rrsig_a_rdata } },
    };
    const proof_items = [_]TestStore.Item{
        .{ .rr = .{ .owner = .{ .bytes = apex_wire }, .rr_type = .NSEC, .class = .IN, .ttl = 60, .rdata = &nsec_rdata } },
        .{ .rr = .{ .owner = .{ .bytes = apex_wire }, .rr_type = .RRSIG, .class = .IN, .ttl = 60, .rdata = &rrsig_nsec_rdata } },
    };
    var store: TestStore = .{ .items = &signed_items, .proof_items = &proof_items, .apex_name = .{ .bytes = apex_wire } };
    var composer = Composer(TestStore).init(&store);
    var qbuf: [512]u8 = undefined;
    var qcomp: [24]builder.CompressionEntry = undefined;
    var out: [1232]u8 = undefined;
    var comp: [96]builder.CompressionEntry = undefined;

    var qb = try builder.Builder.init(&qbuf, &qcomp, 0x7001, .{});
    try qb.addQuestion("www.example", .A, .IN);
    try qb.addOpt(1232, 0, 0, .{ .dnssec_ok = true }, &.{});
    const direct = try composer.compose(try message.Message.init(try qb.finish()), &out, &comp, .{ .signed_zone = true });
    const direct_m = try message.Message.init(direct.bytes);
    try std.testing.expectEqual(@as(u16, 2), direct_m.header.answer_count);
    var direct_answers = try direct_m.records(.answer);
    try std.testing.expectEqual(types.Type.A, (try direct_answers.next()).?.rr_type);
    try std.testing.expectEqual(types.Type.RRSIG, (try direct_answers.next()).?.rr_type);

    var nxq = try builder.Builder.init(&qbuf, &qcomp, 0x7002, .{});
    try nxq.addQuestion("missing.example", .A, .IN);
    try nxq.addOpt(1232, 0, 0, .{ .dnssec_ok = true }, &.{});
    const negative = try composer.compose(try message.Message.init(try nxq.finish()), &out, &comp, .{ .signed_zone = true });
    const negative_m = try message.Message.init(negative.bytes);
    try std.testing.expectEqual(Kind.nxdomain, negative.kind);
    try std.testing.expectEqual(@as(u16, 4), negative_m.header.authority_count); // SOA, RRSIG(SOA), NSEC, RRSIG(NSEC)
    _ = try @import("../validate.zig").messageStrict(negative_m, .{});

    var no_do_q = try builder.Builder.init(&qbuf, &qcomp, 0x7003, .{});
    try no_do_q.addQuestion("www.example", .A, .IN);
    try no_do_q.addOpt(1232, 0, 0, .{}, &.{});
    const no_do = try composer.compose(try message.Message.init(try no_do_q.finish()), &out, &comp, .{ .signed_zone = true });
    try std.testing.expectEqual(@as(u16, 1), (try message.Message.init(no_do.bytes)).header.answer_count);
}

test "authoritative signed zone fails closed when signatures or proofs are unavailable" {
    var store: TestStore = .{ .items = &base_items, .apex_name = .{ .bytes = apex_wire } };
    var composer = Composer(TestStore).init(&store);
    var qbuf: [512]u8 = undefined;
    var qcomp: [24]builder.CompressionEntry = undefined;
    var out: [1232]u8 = undefined;
    var comp: [64]builder.CompressionEntry = undefined;

    var qb = try builder.Builder.init(&qbuf, &qcomp, 0x7010, .{});
    try qb.addQuestion("www.example", .A, .IN);
    try qb.addOpt(1232, 0, 0, .{ .dnssec_ok = true }, &.{});
    try std.testing.expectError(error.MissingRrsig, composer.compose(try message.Message.init(try qb.finish()), &out, &comp, .{ .signed_zone = true }));

    const proofless_items = [_]TestStore.Item{
        .{ .rr = .{ .owner = .{ .bytes = apex_wire }, .rr_type = .SOA, .class = .IN, .ttl = 60, .rdata = &soa_rdata } },
        .{ .rr = .{ .owner = .{ .bytes = apex_wire }, .rr_type = .RRSIG, .class = .IN, .ttl = 60, .rdata = &rrsig_soa_rdata } },
    };
    store.items = &proofless_items;
    var nxq = try builder.Builder.init(&qbuf, &qcomp, 0x7011, .{});
    try nxq.addQuestion("missing.example", .A, .IN);
    try nxq.addOpt(1232, 0, 0, .{ .dnssec_ok = true }, &.{});
    try std.testing.expectError(error.MissingDnssecProof, composer.compose(try message.Message.init(try nxq.finish()), &out, &comp, .{ .signed_zone = true }));
}

test "authoritative response honors 512-byte UDP fallback and truncates whole rrset" {
    const huge = [_]u8{0xaa} ** 240;
    const items = [_]TestStore.Item{
        .{ .rr = .{ .owner = .{ .bytes = apex_wire }, .rr_type = .SOA, .class = .IN, .ttl = 60, .rdata = &soa_rdata } },
        .{ .rr = .{ .owner = .{ .bytes = www_wire }, .rr_type = .TXT, .class = .IN, .ttl = 60, .rdata = &huge } },
        .{ .rr = .{ .owner = .{ .bytes = www_wire }, .rr_type = .TXT, .class = .IN, .ttl = 60, .rdata = &huge } },
        .{ .rr = .{ .owner = .{ .bytes = www_wire }, .rr_type = .TXT, .class = .IN, .ttl = 60, .rdata = &huge } },
    };
    var store: TestStore = .{ .items = &items, .apex_name = .{ .bytes = apex_wire } };
    var composer = Composer(TestStore).init(&store);
    var qbuf: [512]u8 = undefined;
    var qcomp: [24]builder.CompressionEntry = undefined;
    var out: [2048]u8 = undefined;
    var comp: [128]builder.CompressionEntry = undefined;

    const result = try composer.compose(try makeQuery(&qbuf, &qcomp, "www.example", .TXT, false), &out, &comp, .{});
    try std.testing.expect(result.truncated);
    try std.testing.expect(result.bytes.len <= 512);
    const m = try message.Message.init(result.bytes);
    try std.testing.expect(m.header.flags.truncated);
    try std.testing.expectEqual(@as(u16, 0), m.header.answer_count);
}

test "authoritative response composes with exact TSIG tail reservation" {
    const tsig_auth = @import("../tsig/auth.zig");
    const tsig_record = @import("../tsig/record.zig");
    const validate = @import("../validate.zig");

    var key_name_storage: [64]u8 = undefined;
    const key = try tsig_auth.Key.init("auth-key.example", "authoritative shared secret", &key_name_storage);

    var store: TestStore = .{ .items = &base_items, .apex_name = .{ .bytes = apex_wire } };
    var composer = Composer(TestStore).init(&store);

    var qbuf: [512]u8 = undefined;
    var qcomp: [32]builder.CompressionEntry = undefined;
    var qb = try builder.Builder.init(&qbuf, &qcomp, 0x8a01, .{});
    try qb.addQuestion("www.example", .A, .IN);
    try qb.addOpt(512, 0, 0, .{}, &.{});
    var request_mac = try tsig_auth.signBuilder(&qb, key, .{ .time_signed = 1_700_100_000 });
    defer request_mac.deinit();
    const query = try message.Message.init(try qb.finish());
    _ = try validate.messageStrict(query, .{});
    var query_additional = try query.records(.additional);
    _ = try query_additional.next(); // OPT
    const request_tsig = try tsig_record.parse((try query_additional.next()).?);
    try tsig_auth.verify(query, request_tsig, key, .{ .now = 1_700_100_000 });

    const sign_options: tsig_auth.SignOptions = .{
        .time_signed = 1_700_100_001,
        .request_mac = request_mac.slice(),
    };
    const reserve = try tsig_auth.signedRecordWireSize(key, sign_options, true);

    var out: [512]u8 = undefined;
    var comp: [64]builder.CompressionEntry = undefined;
    const response = try composer.compose(query, &out, &comp, .{ .max_udp_payload = 512, .tail_reserve = reserve });
    var signed = try tsig_auth.signInPlace(&out, response.bytes.len, key, sign_options);
    defer signed.deinit();
    try std.testing.expect(signed.bytes.len <= 512);
    try std.testing.expectEqual(response.bytes.len + reserve, signed.bytes.len);

    const m = try message.Message.init(signed.bytes);
    _ = try validate.messageStrict(m, .{});
    try std.testing.expectEqual(@as(u16, 2), m.header.additional_count); // OPT + TSIG
    var additional = try m.records(.additional);
    try std.testing.expectEqual(types.Type.OPT, (try additional.next()).?.rr_type);
    const response_tsig = try tsig_record.parse((try additional.next()).?);
    try std.testing.expect((try additional.next()) == null);
    try tsig_auth.verify(m, response_tsig, key, .{ .now = 1_700_100_001, .request_mac = request_mac.slice() });
}

test "authoritative TSIG reservation truncates a whole RRset before signing" {
    const tsig_auth = @import("../tsig/auth.zig");
    const validate = @import("../validate.zig");

    const large_txt = comptime blk: {
        var data: [402]u8 = undefined;
        data[0] = 255;
        @memset(data[1..256], 'x');
        data[256] = 145;
        @memset(data[257..402], 'y');
        break :blk data;
    };
    const items = [_]TestStore.Item{
        .{ .rr = .{ .owner = .{ .bytes = apex_wire }, .rr_type = .SOA, .class = .IN, .ttl = 60, .rdata = &soa_rdata } },
        .{ .rr = .{ .owner = .{ .bytes = www_wire }, .rr_type = .TXT, .class = .IN, .ttl = 60, .rdata = &large_txt } },
    };
    var store: TestStore = .{ .items = &items, .apex_name = .{ .bytes = apex_wire } };
    var composer = Composer(TestStore).init(&store);

    var key_name_storage: [64]u8 = undefined;
    const key = try tsig_auth.Key.init("auth-key.example", "authoritative shared secret", &key_name_storage);
    var qbuf: [512]u8 = undefined;
    var qcomp: [32]builder.CompressionEntry = undefined;
    var qb = try builder.Builder.init(&qbuf, &qcomp, 0x8a02, .{});
    try qb.addQuestion("www.example", .TXT, .IN);
    var request_mac = try tsig_auth.signBuilder(&qb, key, .{ .time_signed = 1_700_100_100 });
    defer request_mac.deinit();
    const query = try message.Message.init(try qb.finish());

    var out: [512]u8 = undefined;
    var comp: [64]builder.CompressionEntry = undefined;
    const unreserved = try composer.compose(query, &out, &comp, .{ .max_udp_payload = 512 });
    try std.testing.expect(!unreserved.truncated);
    try std.testing.expectEqual(@as(u16, 1), (try message.Message.init(unreserved.bytes)).header.answer_count);

    const sign_options: tsig_auth.SignOptions = .{
        .time_signed = 1_700_100_101,
        .request_mac = request_mac.slice(),
    };
    const reserve = try tsig_auth.signedRecordWireSize(key, sign_options, true);
    const reserved = try composer.compose(query, &out, &comp, .{ .max_udp_payload = 512, .tail_reserve = reserve });
    try std.testing.expect(reserved.truncated);
    const unsigned = try message.Message.init(reserved.bytes);
    try std.testing.expect(unsigned.header.flags.truncated);
    try std.testing.expectEqual(@as(u16, 0), unsigned.header.answer_count);

    var signed = try tsig_auth.signInPlace(&out, reserved.bytes.len, key, sign_options);
    defer signed.deinit();
    try std.testing.expect(signed.bytes.len <= 512);
    _ = try validate.messageStrict(try message.Message.init(signed.bytes), .{});
}

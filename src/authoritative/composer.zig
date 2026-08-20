const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const builder = @import("../builder.zig");
const server = @import("../server.zig");
const edns = @import("../edns.zig");
const api = @import("types.zig");
const h = @import("name_helpers.zig");

const ZoneRecord = api.ZoneRecord;
const Options = api.Options;
const ProofKind = api.ProofKind;
const Kind = api.Kind;
const Result = api.Result;
const CoreError = api.CoreError;

const QueryInfo = struct {
    question: message.Question,
    opt: ?edns.Opt,
};

/// Generic authoritative response composer over a caller-defined zone store.
///
/// `Store` is structural and must expose:
///
/// ```text
/// pub const Error = error{...};
/// pub const RecordIterator = ...; // next() Error!?dns.authoritative.ZoneRecord
/// fn apex(*Store) dns.name.Uncompressed
/// fn lookup(*Store, owner: Uncompressed, rr_type: Type) Error!?RecordIterator
/// fn nameExists(*Store, owner: Uncompressed) Error!bool
/// fn findDelegation(*Store, qname: Uncompressed) Error!?Uncompressed
/// fn findDname(*Store, qname: Uncompressed) Error!?Uncompressed
/// fn findWildcard(*Store, qname: Uncompressed) Error!?Uncompressed
/// // Required only when Options.signed_zone can be true:
/// fn dnssecProof(*Store, kind: ProofKind, qname: Uncompressed, qtype: Type) Error!?RecordIterator
/// ```
///
/// `findDelegation` returns the nearest zone cut below the apex. `findDname`
/// returns the nearest strict ancestor carrying DNAME. `findWildcard` performs
/// RFC 4592 closest-encloser selection and returns the wildcard source owner.
/// All iterators must be restartable by calling `lookup` again.
pub fn Composer(comptime Store: type) type {
    return struct {
        store: *Store,

        const Self = @This();
        pub const Error = CoreError || Store.Error;

        const PendingRrset = struct {
            owner: name_mod.Uncompressed,
            rr_type: types.Type,
            first: ZoneRecord,
            rest: Store.RecordIterator,
        };

        const Selection = union(enum) {
            answer: PendingRrset,
            cname: PendingRrset,
            dname: PendingRrset,
            wildcard: struct { source: name_mod.Uncompressed, rrset: PendingRrset },
            referral: name_mod.Uncompressed,
            nodata,
            nxdomain,
            refused,
            not_implemented,
            bad_edns_version,
        };

        pub fn init(store: *Store) Self {
            return .{ .store = store };
        }

        /// Compose one ordinary authoritative QUERY response into caller-owned
        /// output. AXFR/IXFR remain in `dns.transfer`; TSIG remains caller-owned
        /// and can be applied after this response is composed.
        pub fn compose(self: *Self, query: message.Message, out: []u8, compression: []builder.CompressionEntry, options: Options) Error!Result {
            const qi = try inspectQuery(query);

            var qname_buf: [name_mod.Name.max_wire_len]u8 = undefined;
            const qname_wire = try qi.question.name.writeWire(&qname_buf);
            const qname = try name_mod.Uncompressed.init(qname_wire);

            const selection = if (qi.opt != null and qi.opt.?.version != 0)
                Selection.bad_edns_version
            else
                try self.select(qname, qi.question.qtype, qi.question.qclass, options);

            const want_dnssec = options.signed_zone and if (qi.opt) |opt| opt.dnssecOk() else false;

            const kind: Kind = switch (selection) {
                .answer => .answer,
                .cname => .cname,
                .dname => .dname,
                .wildcard => .wildcard,
                .referral => .referral,
                .nodata => .nodata,
                .nxdomain => .nxdomain,
                .refused => .refused,
                .not_implemented => .not_implemented,
                .bad_edns_version => .bad_edns_version,
            };

            const rcode: types.Rcode = switch (selection) {
                .nxdomain => .name_error,
                .refused => .refused,
                .not_implemented => .not_implemented,
                else => .no_error,
            };
            const authoritative = switch (selection) {
                .referral, .refused, .not_implemented, .bad_edns_version => false,
                else => true,
            };

            const limit = responseLimit(out.len, qi.opt, options);
            const needs_opt = qi.opt != null;
            const opt_wire_len: usize = if (needs_opt) 11 else 0;
            if (options.tail_reserve > limit) return error.NoSpace;
            const content_limit = limit - options.tail_reserve;
            if (content_limit < types.Header.wire_len + opt_wire_len) return error.NoSpace;
            const builder_limit = content_limit - opt_wire_len;

            var b = try server.beginResponse(out[0..builder_limit], compression, query, .{
                .authoritative = authoritative,
                .recursion_available = options.recursion_available,
                .rcode = rcode,
            });

            var truncated = false;
            switch (selection) {
                .answer => |rrset| truncated = !(try self.emitSignedRrset(&b, rrset, .answer, null, true, want_dnssec, options)),
                .cname => |rrset| truncated = !(try self.emitSignedRrset(&b, rrset, .answer, null, true, want_dnssec, options)),
                .dname => |rrset| {
                    const snapshot = b;
                    if (!(try self.emitSignedRrset(&b, rrset, .answer, null, true, want_dnssec, options))) {
                        truncated = true;
                    } else if (!(try self.emitSynthesizedCname(&b, qname, rrset.first, options))) {
                        b = snapshot;
                        b.setTruncated(true);
                        truncated = true;
                    }
                },
                .wildcard => |w| {
                    if (!(try self.emitSignedRrset(&b, w.rrset, .answer, qname, true, want_dnssec, options))) {
                        truncated = true;
                    } else if (want_dnssec and !(try self.emitProof(&b, .wildcard, qname, qi.question.qtype, options))) {
                        truncated = true;
                    }
                },
                .referral => |cut| {
                    const ns = (try self.lookupSet(cut, .NS, options.zone_class)) orelse return error.MissingDelegationNs;
                    if (!(try self.emitRrset(&b, ns, .authority, null, true, options))) {
                        truncated = true;
                    } else {
                        if (want_dnssec) {
                            if (try self.lookupSet(cut, .DS, options.zone_class)) |ds| {
                                if (!(try self.emitSignedRrset(&b, ds, .authority, null, true, true, options))) truncated = true;
                            } else if (!(try self.emitProof(&b, .insecure_delegation, qname, qi.question.qtype, options))) {
                                truncated = true;
                            }
                        }
                        if (!truncated and options.include_glue) try self.emitGlue(&b, cut, options);
                    }
                },
                .nodata, .nxdomain => {
                    const apex = self.store.apex();
                    const soa = (try self.lookupSet(apex, .SOA, options.zone_class)) orelse return error.MissingSoa;
                    const negative_ttl = try negativeSoaTtl(soa.first);
                    if (!(try self.emitSignedRrsetWithTtl(&b, soa, .authority, null, true, want_dnssec, options, negative_ttl))) {
                        truncated = true;
                    } else if (want_dnssec) {
                        const proof_kind: ProofKind = switch (selection) {
                            .nodata => .nodata,
                            .nxdomain => .nxdomain,
                            else => unreachable,
                        };
                        if (!(try self.emitProof(&b, proof_kind, qname, qi.question.qtype, options))) truncated = true;
                    }
                },
                .refused, .not_implemented, .bad_edns_version => {},
            }
            if (truncated) b.setTruncated(true);

            const base = try b.finish();
            const final = if (qi.opt) |request_opt|
                try appendResponseOpt(
                    out[0..content_limit],
                    base.len,
                    @max(@as(u16, 512), options.max_udp_payload),
                    if (kind == .bad_edns_version) .bad_version_or_signature else rcode,
                    request_opt.flags.dnssec_ok,
                )
            else
                out[0..base.len];

            return .{ .bytes = final, .kind = kind, .truncated = truncated, .used_edns = needs_opt };
        }

        fn select(self: *Self, qname: name_mod.Uncompressed, qtype: types.Type, qclass: types.Class, options: Options) Error!Selection {
            if (qclass != options.zone_class) return .refused;

            const apex = self.store.apex();
            if (!(try h.isSubdomain(qname, apex))) return .refused;

            var lookup_type = qtype;
            switch (qtype) {
                .AXFR, .IXFR, .OPT, .TKEY, .TSIG => return .not_implemented,
                .ANY => switch (options.any_policy) {
                    .refuse => return .refused,
                    .rr_type => |rr_type| lookup_type = rr_type,
                },
                else => {},
            }

            if (try self.store.findDelegation(qname)) |cut| {
                if (!(try h.isSubdomain(qname, cut)) or try h.namesEqual(cut, apex) or !(try h.isSubdomain(cut, apex))) return error.StoreContract;
                const exact_cut = try h.namesEqual(qname, cut);
                if (!(qtype == .DS and exact_cut)) return .{ .referral = cut };
            }

            if (try self.store.findDname(qname)) |owner| {
                if (try h.namesEqual(qname, owner) or !(try h.isSubdomain(qname, owner)) or !(try h.isSubdomain(owner, apex))) return error.StoreContract;
                const set = (try self.lookupSet(owner, .DNAME, options.zone_class)) orelse return error.StoreContract;
                return .{ .dname = set };
            }

            if (try self.lookupSet(qname, lookup_type, options.zone_class)) |set| return .{ .answer = set };
            if (qtype != .ANY and qtype != .CNAME) {
                if (try self.lookupSet(qname, .CNAME, options.zone_class)) |set| return .{ .cname = set };
            }

            if (try self.store.nameExists(qname)) return .nodata;

            if (try self.store.findWildcard(qname)) |source| {
                if (!(try h.validWildcardSource(qname, source, apex))) return error.StoreContract;
                if (try self.lookupSet(source, lookup_type, options.zone_class)) |set| return .{ .wildcard = .{ .source = source, .rrset = set } };
                if (qtype != .ANY and qtype != .CNAME) {
                    if (try self.lookupSet(source, .CNAME, options.zone_class)) |set| return .{ .wildcard = .{ .source = source, .rrset = set } };
                }
                return .nodata;
            }
            return .nxdomain;
        }

        fn lookupSet(self: *Self, owner: name_mod.Uncompressed, rr_type: types.Type, class: types.Class) Error!?PendingRrset {
            var it = (try self.store.lookup(owner, rr_type)) orelse return null;
            const first = (try it.next()) orelse return null;
            try validateStoreRecord(first, owner, rr_type, class);
            return .{ .owner = owner, .rr_type = rr_type, .first = first, .rest = it };
        }

        fn emitSignedRrset(self: *Self, b: *builder.Builder, set: PendingRrset, section: types.Section, owner_override: ?name_mod.Uncompressed, required: bool, want_dnssec: bool, options: Options) Error!bool {
            return self.emitSignedRrsetWithTtl(b, set, section, owner_override, required, want_dnssec, options, null);
        }

        fn emitSignedRrsetWithTtl(self: *Self, b: *builder.Builder, set: PendingRrset, section: types.Section, owner_override: ?name_mod.Uncompressed, required: bool, want_dnssec: bool, options: Options, ttl_override: ?u32) Error!bool {
            if (!want_dnssec or set.rr_type == .RRSIG) return self.emitRrsetWithTtl(b, set, section, owner_override, required, options, ttl_override);

            const snapshot = b.*;
            if (!(try self.emitRrsetWithTtl(b, set, section, owner_override, false, options, ttl_override))) {
                b.* = snapshot;
                if (required) b.setTruncated(true);
                return false;
            }
            if (!(try self.emitSignatures(b, set.owner, set.rr_type, section, owner_override, options, ttl_override))) {
                b.* = snapshot;
                if (required) b.setTruncated(true);
                return false;
            }
            return true;
        }

        fn emitSignatures(self: *Self, b: *builder.Builder, owner: name_mod.Uncompressed, covered: types.Type, section: types.Section, owner_override: ?name_mod.Uncompressed, options: Options, ttl_override: ?u32) Error!bool {
            var it = (try self.store.lookup(owner, .RRSIG)) orelse return error.MissingRrsig;
            const snapshot = b.*;
            const output_owner = owner_override orelse owner;
            var emitted: usize = 0;
            while (true) {
                const maybe = it.next() catch |err| {
                    b.* = snapshot;
                    return err;
                };
                const rr = maybe orelse break;
                try validateStoreRecord(rr, owner, .RRSIG, options.zone_class);
                if (rr.rdata.len < 2) {
                    b.* = snapshot;
                    return error.StoreContract;
                }
                const type_covered: types.Type = @enumFromInt(std.mem.readInt(u16, rr.rdata[0..2], .big));
                if (type_covered != covered) continue;
                b.addRawRecordWire(section, output_owner, .RRSIG, rr.class, ttl_override orelse rr.ttl, rr.rdata) catch |err| switch (err) {
                    error.NoSpace => {
                        b.* = snapshot;
                        return false;
                    },
                    else => return err,
                };
                emitted += 1;
            }
            if (emitted == 0) {
                b.* = snapshot;
                return error.MissingRrsig;
            }
            return true;
        }

        fn emitProof(self: *Self, b: *builder.Builder, kind: ProofKind, qname: name_mod.Uncompressed, qtype: types.Type, options: Options) Error!bool {
            if (comptime !@hasDecl(Store, "dnssecProof")) return error.MissingDnssecProof;
            var it = (try self.store.dnssecProof(kind, qname, qtype)) orelse return error.MissingDnssecProof;
            const snapshot = b.*;
            const apex = self.store.apex();
            var emitted: usize = 0;
            while (true) {
                const maybe = it.next() catch |err| {
                    b.* = snapshot;
                    return err;
                };
                const rr = maybe orelse break;
                if (rr.class != options.zone_class or !(try h.isSubdomain(rr.owner, apex))) {
                    b.* = snapshot;
                    return error.StoreContract;
                }
                switch (rr.rr_type) {
                    .NSEC, .NSEC3, .RRSIG => {},
                    else => {
                        b.* = snapshot;
                        return error.StoreContract;
                    },
                }
                b.addRawRecordWire(.authority, rr.owner, rr.rr_type, rr.class, rr.ttl, rr.rdata) catch |err| switch (err) {
                    error.NoSpace => {
                        b.* = snapshot;
                        b.setTruncated(true);
                        return false;
                    },
                    else => return err,
                };
                emitted += 1;
            }
            if (emitted == 0) {
                b.* = snapshot;
                return error.MissingDnssecProof;
            }
            return true;
        }

        fn emitRrset(self: *Self, b: *builder.Builder, set: PendingRrset, section: types.Section, owner_override: ?name_mod.Uncompressed, required: bool, options: Options) Error!bool {
            return self.emitRrsetWithTtl(b, set, section, owner_override, required, options, null);
        }

        fn emitRrsetWithTtl(self: *Self, b: *builder.Builder, set: PendingRrset, section: types.Section, owner_override: ?name_mod.Uncompressed, required: bool, options: Options, ttl_override: ?u32) Error!bool {
            _ = self;
            const snapshot = b.*;
            const owner = owner_override orelse set.owner;

            if (!try emitRecord(b, set.first, set.owner, set.rr_type, section, owner, options.zone_class, ttl_override)) {
                b.* = snapshot;
                if (required) b.setTruncated(true);
                return false;
            }

            var it = set.rest;
            while (true) {
                const maybe = it.next() catch |err| {
                    b.* = snapshot;
                    return err;
                };
                const rr = maybe orelse break;
                if (!try emitRecord(b, rr, set.owner, set.rr_type, section, owner, options.zone_class, ttl_override)) {
                    b.* = snapshot;
                    if (required) b.setTruncated(true);
                    return false;
                }
            }
            return true;
        }

        fn emitSynthesizedCname(self: *Self, b: *builder.Builder, qname: name_mod.Uncompressed, dname_rr: ZoneRecord, options: Options) Error!bool {
            _ = self;
            try validateStoreRecord(dname_rr, dname_rr.owner, .DNAME, options.zone_class);
            const target = name_mod.Uncompressed.init(dname_rr.rdata) catch return error.InvalidDname;
            var target_buf: [name_mod.Name.max_wire_len]u8 = undefined;
            const synthesized = h.substituteDname(qname, dname_rr.owner, target, &target_buf) catch return error.InvalidDname;

            const snapshot = b.*;
            b.addRawRecordWire(.answer, qname, .CNAME, options.zone_class, dname_rr.ttl, synthesized) catch |err| switch (err) {
                error.NoSpace => {
                    b.* = snapshot;
                    b.setTruncated(true);
                    return false;
                },
                else => return err,
            };
            return true;
        }

        fn emitGlue(self: *Self, b: *builder.Builder, cut: name_mod.Uncompressed, options: Options) Error!void {
            const apex = self.store.apex();
            var ns_it = (try self.store.lookup(cut, .NS)) orelse return;
            while (try ns_it.next()) |ns_rr| {
                try validateStoreRecord(ns_rr, cut, .NS, options.zone_class);
                const target = name_mod.Uncompressed.init(ns_rr.rdata) catch return error.StoreContract;
                if (!(try h.isSubdomain(target, apex))) continue;

                inline for (.{ types.Type.A, types.Type.AAAA }) |addr_type| {
                    if (try self.lookupSet(target, addr_type, options.zone_class)) |set| {
                        _ = try self.emitRrset(b, set, .additional, null, false, options);
                    }
                }
            }
        }
    };
}

fn inspectQuery(query: message.Message) CoreError!QueryInfo {
    if (query.header.flags.response or query.header.flags.opcode != .query) return error.ExpectedQuery;
    if (query.header.question_count != 1) return error.ExpectedOneQuestion;
    if (query.header.answer_count != 0 or query.header.authority_count != 0) return error.UnexpectedQuerySections;
    try query.validate();

    var questions = query.questions();
    const q = (try questions.next()).?;

    var found_opt: ?edns.Opt = null;
    var additional = try query.records(.additional);
    while (try additional.next()) |rr| {
        if (rr.rr_type != .OPT) continue;
        if (found_opt != null) return error.DuplicateOpt;
        var root_buf: [1]u8 = undefined;
        const owner = try rr.name.writeWire(&root_buf);
        if (owner.len != 1 or owner[0] != 0) return error.InvalidOptOwner;
        const opt = try edns.Opt.fromRecord(rr);
        var options = opt.iterator();
        while (try options.next()) |_| {}
        found_opt = opt;
    }
    return .{ .question = q, .opt = found_opt };
}

fn responseLimit(out_len: usize, opt: ?edns.Opt, options: Options) usize {
    if (options.transport == .stream) return @min(out_len, message.Message.max_wire_len);
    const request_payload: usize = if (opt) |o| @max(@as(usize, 512), o.udp_payload_size) else 512;
    const local_payload: usize = @max(@as(usize, 512), options.max_udp_payload);
    return @min(out_len, @min(request_payload, local_payload));
}

fn appendResponseOpt(out: []u8, pos: usize, advertised_payload: u16, rcode: types.Rcode, request_do: bool) CoreError![]const u8 {
    if (pos + 11 > out.len) return error.NoSpace;
    var p = pos;
    out[p] = 0;
    p += 1;
    std.mem.writeInt(u16, out[p..][0..2], @intFromEnum(types.Type.OPT), .big);
    p += 2;
    std.mem.writeInt(u16, out[p..][0..2], advertised_payload, .big);
    p += 2;
    const ext: u8 = server.extendedRcodeHigh(rcode);
    const flags: edns.Flags = .{ .dnssec_ok = request_do };
    const ttl: u32 = (@as(u32, ext) << 24) | @as(u32, flags.toInt());
    std.mem.writeInt(u32, out[p..][0..4], ttl, .big);
    p += 4;
    std.mem.writeInt(u16, out[p..][0..2], 0, .big);
    p += 2;

    var header = try types.Header.parse(out);
    header.additional_count = std.math.add(u16, header.additional_count, 1) catch return error.TooManyRecords;
    try header.write(out);
    return out[0..p];
}

fn negativeSoaTtl(rr: ZoneRecord) CoreError!u32 {
    if (rr.rr_type != .SOA) return error.StoreContract;
    var pos = name_mod.uncompressedConsumedLen(rr.rdata, 0) catch return error.StoreContract;
    const second = name_mod.uncompressedConsumedLen(rr.rdata, pos) catch return error.StoreContract;
    pos += second;
    if (rr.rdata.len - pos != 20) return error.StoreContract;
    const minimum = std.mem.readInt(u32, rr.rdata[pos + 16 ..][0..4], .big);
    return @min(rr.ttl, minimum);
}

fn validateStoreRecord(rr: ZoneRecord, owner: name_mod.Uncompressed, rr_type: types.Type, class: types.Class) CoreError!void {
    if (rr.rr_type != rr_type or rr.class != class or !(try h.namesEqual(rr.owner, owner))) return error.StoreContract;
}

fn emitRecord(b: *builder.Builder, rr: ZoneRecord, expected_owner: name_mod.Uncompressed, expected_type: types.Type, section: types.Section, output_owner: name_mod.Uncompressed, class: types.Class, ttl_override: ?u32) CoreError!bool {
    try validateStoreRecord(rr, expected_owner, expected_type, class);
    b.addRawRecordWire(section, output_owner, rr.rr_type, rr.class, ttl_override orelse rr.ttl, rr.rdata) catch |err| switch (err) {
        error.NoSpace => return false,
        else => return err,
    };
    return true;
}

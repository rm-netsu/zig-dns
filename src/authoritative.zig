const std = @import("std");
const types = @import("types.zig");
const name_mod = @import("name.zig");
const message = @import("message.zig");
const builder = @import("builder.zig");
const server = @import("server.zig");
const edns = @import("edns.zig");

/// Uncompressed, store-owned zone record view.
///
/// `rdata` must be wire-format RDATA that is independent of any DNS message.
/// In particular, embedded domain names must not contain compression pointers.
/// The authoritative composer borrows all fields only for the duration of the
/// current call and never owns zone storage.
pub const ZoneRecord = struct {
    owner: name_mod.Uncompressed,
    rr_type: types.Type,
    class: types.Class,
    ttl: u32,
    rdata: []const u8,
};

pub const Transport = enum { datagram, stream };
pub const AnyPolicy = union(enum) { refuse, rr_type: types.Type };

pub const Options = struct {
    zone_class: types.Class = .IN,
    transport: Transport = .datagram,
    max_udp_payload: u16 = 1232,
    recursion_available: bool = false,
    include_glue: bool = true,
    any_policy: AnyPolicy = .refuse,
    /// The caller owns signing policy. When true, DO=1 responses require the
    /// store to provide matching RRSIGs and authenticated denial proofs.
    signed_zone: bool = false,
};

pub const ProofKind = enum { nodata, nxdomain, wildcard, insecure_delegation };

pub const Kind = enum {
    answer,
    cname,
    dname,
    wildcard,
    referral,
    nodata,
    nxdomain,
    refused,
    not_implemented,
    bad_edns_version,
};

pub const Result = struct {
    bytes: []const u8,
    kind: Kind,
    truncated: bool,
    used_edns: bool,
};

pub const CoreError = message.ParseError || name_mod.Error || builder.Error || edns.Error || server.Error || error{
    ExpectedQuery,
    ExpectedOneQuestion,
    UnexpectedQuerySections,
    DuplicateOpt,
    InvalidOptOwner,
    StoreContract,
    MissingSoa,
    MissingDelegationNs,
    InvalidDname,
    MissingRrsig,
    MissingDnssecProof,
};

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
            if (limit < types.Header.wire_len + opt_wire_len) return error.NoSpace;
            const builder_limit = limit - opt_wire_len;

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
                    if (!(try self.emitSignedRrset(&b, soa, .authority, null, true, want_dnssec, options))) {
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
                    out[0..limit],
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
            if (!(try isSubdomain(qname, apex))) return .refused;

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
                if (!(try isSubdomain(qname, cut)) or try namesEqual(cut, apex) or !(try isSubdomain(cut, apex))) return error.StoreContract;
                const exact_cut = try namesEqual(qname, cut);
                if (!(qtype == .DS and exact_cut)) return .{ .referral = cut };
            }

            if (try self.store.findDname(qname)) |owner| {
                if (try namesEqual(qname, owner) or !(try isSubdomain(qname, owner)) or !(try isSubdomain(owner, apex))) return error.StoreContract;
                const set = (try self.lookupSet(owner, .DNAME, options.zone_class)) orelse return error.StoreContract;
                return .{ .dname = set };
            }

            if (try self.lookupSet(qname, lookup_type, options.zone_class)) |set| return .{ .answer = set };
            if (qtype != .ANY and qtype != .CNAME) {
                if (try self.lookupSet(qname, .CNAME, options.zone_class)) |set| return .{ .cname = set };
            }

            if (try self.store.nameExists(qname)) return .nodata;

            if (try self.store.findWildcard(qname)) |source| {
                if (!(try validWildcardSource(qname, source, apex))) return error.StoreContract;
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
            if (!want_dnssec or set.rr_type == .RRSIG) return self.emitRrset(b, set, section, owner_override, required, options);

            const snapshot = b.*;
            if (!(try self.emitRrset(b, set, section, owner_override, false, options))) {
                b.* = snapshot;
                if (required) b.setTruncated(true);
                return false;
            }
            if (!(try self.emitSignatures(b, set.owner, set.rr_type, section, owner_override, options))) {
                b.* = snapshot;
                if (required) b.setTruncated(true);
                return false;
            }
            return true;
        }

        fn emitSignatures(self: *Self, b: *builder.Builder, owner: name_mod.Uncompressed, covered: types.Type, section: types.Section, owner_override: ?name_mod.Uncompressed, options: Options) Error!bool {
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
                b.addRawRecordWire(section, output_owner, .RRSIG, rr.class, rr.ttl, rr.rdata) catch |err| switch (err) {
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
                if (rr.class != options.zone_class or !(try isSubdomain(rr.owner, apex))) {
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
            _ = self;
            const snapshot = b.*;
            const owner = owner_override orelse set.owner;

            if (!try emitRecord(b, set.first, set.owner, set.rr_type, section, owner, options.zone_class)) {
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
                if (!try emitRecord(b, rr, set.owner, set.rr_type, section, owner, options.zone_class)) {
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
            const synthesized = substituteDname(qname, dname_rr.owner, target, &target_buf) catch return error.InvalidDname;

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
                if (!(try isSubdomain(target, apex))) continue;

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

fn validateStoreRecord(rr: ZoneRecord, owner: name_mod.Uncompressed, rr_type: types.Type, class: types.Class) CoreError!void {
    if (rr.rr_type != rr_type or rr.class != class or !(try namesEqual(rr.owner, owner))) return error.StoreContract;
}

fn emitRecord(b: *builder.Builder, rr: ZoneRecord, expected_owner: name_mod.Uncompressed, expected_type: types.Type, section: types.Section, output_owner: name_mod.Uncompressed, class: types.Class) CoreError!bool {
    try validateStoreRecord(rr, expected_owner, expected_type, class);
    b.addRawRecordWire(section, output_owner, rr.rr_type, rr.class, rr.ttl, rr.rdata) catch |err| switch (err) {
        error.NoSpace => return false,
        else => return err,
    };
    return true;
}

fn namesEqual(a: name_mod.Uncompressed, b: name_mod.Uncompressed) name_mod.Error!bool {
    return (try name_mod.Name.init(a.bytes, 0)).eqlIgnoreCase(try name_mod.Name.init(b.bytes, 0));
}

fn isSubdomain(child: name_mod.Uncompressed, parent: name_mod.Uncompressed) name_mod.Error!bool {
    return (try name_mod.Name.init(child.bytes, 0)).isSubdomainOf(try name_mod.Name.init(parent.bytes, 0));
}

fn validWildcardSource(qname: name_mod.Uncompressed, source: name_mod.Uncompressed, apex: name_mod.Uncompressed) name_mod.Error!bool {
    if (source.bytes.len < 3 or source.bytes[0] != 1 or source.bytes[1] != '*') return false;
    const suffix = try name_mod.Uncompressed.init(source.bytes[2..]);
    return try isSubdomain(qname, suffix) and try isSubdomain(suffix, apex);
}

fn substituteDname(source: name_mod.Uncompressed, owner: name_mod.Uncompressed, target: name_mod.Uncompressed, out: []u8) name_mod.Error![]const u8 {
    var source_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var owner_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var target_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const source_wire = try (try name_mod.Name.init(source.bytes, 0)).writeCanonicalWire(&source_buf);
    const owner_wire = try (try name_mod.Name.init(owner.bytes, 0)).writeCanonicalWire(&owner_buf);
    const target_wire = try (try name_mod.Name.init(target.bytes, 0)).writeCanonicalWire(&target_buf);

    var pos: usize = 0;
    var prefix_len: ?usize = null;
    while (pos < source_wire.len) {
        if (pos != 0 and std.mem.eql(u8, source_wire[pos..], owner_wire)) {
            prefix_len = pos;
            break;
        }
        const label_len: usize = source_wire[pos];
        if (label_len == 0) break;
        pos += 1 + label_len;
    }
    const prefix = prefix_len orelse return error.InvalidPresentation;
    const needed = prefix + target_wire.len;
    if (needed > name_mod.Name.max_wire_len) return error.NameTooLong;
    if (needed > out.len) return error.BufferTooSmall;
    @memcpy(out[0..prefix], source_wire[0..prefix]);
    @memcpy(out[prefix..][0..target_wire.len], target_wire);
    return out[0..needed];
}

fn wire(comptime presentation: []const u8) [presentation.len + 2]u8 {
    var out: [presentation.len + 2]u8 = undefined;
    const value = name_mod.writePresentationWire(presentation, &out) catch unreachable;
    std.debug.assert(value.len == out.len);
    return out;
}

const TestStore = struct {
    pub const Error = error{};

    const Item = struct { rr: ZoneRecord };
    const RecordIterator = struct {
        items: []const Item,
        owner: name_mod.Uncompressed,
        rr_type: types.Type,
        pos: usize = 0,
        match_all: bool = false,

        pub fn next(self: *RecordIterator) Error!?ZoneRecord {
            while (self.pos < self.items.len) {
                const rr = self.items[self.pos].rr;
                self.pos += 1;
                if (self.match_all or (rr.rr_type == self.rr_type and (namesEqual(rr.owner, self.owner) catch false))) return rr;
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
        for (self.items) |item| if (namesEqual(item.rr.owner, owner) catch false) return true;
        return false;
    }

    pub fn findDelegation(self: *TestStore, qname: name_mod.Uncompressed) Error!?name_mod.Uncompressed {
        if (self.delegation) |cut| if (isSubdomain(qname, cut) catch false) return cut;
        return null;
    }

    pub fn findDname(self: *TestStore, qname: name_mod.Uncompressed) Error!?name_mod.Uncompressed {
        if (self.dname_owner) |owner| {
            if (!(namesEqual(qname, owner) catch false) and (isSubdomain(qname, owner) catch false)) return owner;
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
const wildcard_wire_storage = wire("*.example");
const child_wire_storage = wire("child.example");
const ns_child_wire_storage = wire("ns.child.example");
const old_wire_storage = wire("old.example");
const new_wire_storage = wire("new.example");
const ns_wire_storage = wire("ns.example");
const hostmaster_wire_storage = wire("hostmaster.example");
const apex_wire: []const u8 = &apex_wire_storage;
const www_wire: []const u8 = &www_wire_storage;
const alias_wire: []const u8 = &alias_wire_storage;
const wildcard_wire: []const u8 = &wildcard_wire_storage;
const child_wire: []const u8 = &child_wire_storage;
const ns_child_wire: []const u8 = &ns_child_wire_storage;
const old_wire: []const u8 = &old_wire_storage;
const new_wire: []const u8 = &new_wire_storage;
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
    const validate = @import("validate.zig");
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
    _ = try @import("validate.zig").messageStrict(negative_m, .{});

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

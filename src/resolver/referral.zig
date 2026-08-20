const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const rdata = @import("../rdata.zig");
const client = @import("../client.zig");
const builder = @import("../builder.zig");

pub const Error = message.ParseError || name_mod.Error || rdata.Error || error{
    NotReferral,
    MixedDelegations,
    InvalidNsRdata,
    InvalidDsRdata,
    ParentNotAncestor,
};

pub const NameServer = struct {
    record: message.Record,
    target: name_mod.Name,
    in_domain: bool,
};

pub const Ds = struct {
    record: message.Record,
    data: rdata.Ds,
};

pub const GlueScope = enum {
    /// The name server is at or below the delegated child name.
    in_domain,
    /// The name server is elsewhere below the current parent zone.
    sibling,
    /// Additional address data lies outside the current server's bailiwick.
    out_of_bailiwick,

    pub fn usable(self: GlueScope) bool {
        return self != .out_of_bailiwick;
    }
};

pub const Address = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,
};

pub const Glue = struct {
    record: message.Record,
    nameserver: name_mod.Name,
    scope: GlueScope,
    address: Address,

    pub fn usable(self: Glue) bool {
        return self.scope.usable();
    }
};

/// Zero-copy view of one referral response.
///
/// The DNS packet remains caller-owned. Iterators borrow records directly from
/// it; no NS, DS, or address arrays are materialized. `init` intentionally
/// does not accept a parent zone because that information cannot be inferred
/// reliably from a referral. It is supplied only when classifying glue.
pub const Referral = struct {
    msg: message.Message,
    delegation: name_mod.Name,
    class: types.Class,

    pub fn init(msg: message.Message, q: client.QuestionKey) Error!Referral {
        var qwire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const qwire = try name_mod.writePresentationWire(q.name, &qwire_buf);
        return initName(msg, try name_mod.Name.init(qwire, 0), q.qclass);
    }

    /// Wire-name form of `init`, suitable for arbitrary-octet labels.
    pub fn initWire(msg: message.Message, q: client.WireQuestionKey) Error!Referral {
        return initName(msg, try name_mod.Name.init(q.name.bytes, 0), q.qclass);
    }

    /// Low-level form used when the caller already has a parsed query name.
    pub fn initName(msg: message.Message, qname: name_mod.Name, qclass: types.Class) Error!Referral {
        if (!msg.header.flags.response or msg.header.flags.opcode != .query or msg.header.flags.truncated) return error.NotReferral;
        if (try msg.rcode() != .no_error or msg.header.answer_count != 0) return error.NotReferral;

        var first_ns: ?message.Record = null;
        var authority = try msg.records(.authority);
        while (try authority.next()) |rr| {
            if (rr.class != qclass) continue;
            if (rr.rr_type == .SOA) return error.NotReferral;
            if (rr.rr_type != .NS) continue;

            _ = try strictNsTarget(rr);
            if (first_ns) |first| {
                if (!try rr.name.eqlIgnoreCase(first.name)) return error.MixedDelegations;
            } else {
                first_ns = rr;
            }
        }

        const first = first_ns orelse return error.NotReferral;
        if (!try qname.isSubdomainOf(first.name)) return error.NotReferral;
        return .{ .msg = msg, .delegation = first.name, .class = qclass };
    }

    pub fn nameServers(self: Referral) Error!NameServerIterator {
        return .{
            .records = try self.msg.records(.authority),
            .delegation = self.delegation,
            .class = self.class,
        };
    }

    pub fn ds(self: Referral) Error!DsIterator {
        return .{
            .records = try self.msg.records(.authority),
            .delegation = self.delegation,
            .class = self.class,
        };
    }

    /// Iterate Additional A/AAAA records that actually correspond to one of
    /// the referral's NS targets, classifying each relative to `parent_zone`.
    pub fn gluePresentation(self: Referral, parent_zone: []const u8) Error!GlueIterator {
        var wire: [name_mod.Name.max_wire_len]u8 = undefined;
        const encoded = try name_mod.writePresentationWire(parent_zone, &wire);
        const parent = try name_mod.Uncompressed.init(encoded);
        return self.glueWire(parent);
    }

    /// Wire-name form of `gluePresentation`, suitable for arbitrary-octet DNS
    /// names. The returned iterator owns a canonical copy of `parent_zone`.
    pub fn glueWire(self: Referral, parent_zone: name_mod.Uncompressed) Error!GlueIterator {
        var result: GlueIterator = .{
            .referral = self,
            .records = try self.msg.records(.additional),
            .parent_len = 0,
        };
        const parent_name = try name_mod.Name.init(parent_zone.bytes, 0);
        const canonical = try parent_name.writeCanonicalWire(&result.parent_wire);
        result.parent_len = @intCast(canonical.len);
        const stable_parent = try name_mod.Name.init(result.parent_wire[0..result.parent_len], 0);
        if (!try self.delegation.isSubdomainOf(stable_parent)) return error.ParentNotAncestor;
        return result;
    }
};

pub const NameServerIterator = struct {
    records: message.RecordIterator,
    delegation: name_mod.Name,
    class: types.Class,

    pub fn next(self: *NameServerIterator) Error!?NameServer {
        while (try self.records.next()) |rr| {
            if (rr.class != self.class or rr.rr_type != .NS) continue;
            if (!try rr.name.eqlIgnoreCase(self.delegation)) continue;
            const target = try strictNsTarget(rr);
            return .{
                .record = rr,
                .target = target,
                .in_domain = try target.isSubdomainOf(self.delegation),
            };
        }
        return null;
    }
};

pub const DsIterator = struct {
    records: message.RecordIterator,
    delegation: name_mod.Name,
    class: types.Class,

    pub fn next(self: *DsIterator) Error!?Ds {
        while (try self.records.next()) |rr| {
            if (rr.class != self.class or rr.rr_type != .DS) continue;
            if (!try rr.name.eqlIgnoreCase(self.delegation)) continue;
            const data = try rdata.ds(rr);
            if (data.digest.len == 0) return error.InvalidDsRdata;
            return .{ .record = rr, .data = data };
        }
        return null;
    }
};

pub const GlueIterator = struct {
    referral: Referral,
    records: message.RecordIterator,
    parent_wire: [name_mod.Name.max_wire_len]u8 = undefined,
    parent_len: u16,

    pub fn next(self: *GlueIterator) Error!?Glue {
        const parent = try name_mod.Name.init(self.parent_wire[0..self.parent_len], 0);
        while (try self.records.next()) |rr| {
            if (rr.class != self.referral.class) continue;
            if (rr.rr_type != .A and rr.rr_type != .AAAA) continue;

            var ns = try self.referral.nameServers();
            while (try ns.next()) |server| {
                if (!try rr.name.eqlIgnoreCase(server.target)) continue;
                // Parse address bytes only after proving that this Additional
                // RR actually belongs to a delegation NS. Unrelated hints are
                // ignored rather than promoted into resolver input.
                const address: Address = switch (rr.rr_type) {
                    .A => .{ .ipv4 = try rdata.a(rr) },
                    .AAAA => .{ .ipv6 = try rdata.aaaa(rr) },
                    else => unreachable,
                };
                const scope: GlueScope = if (server.in_domain)
                    .in_domain
                else if (try server.target.isSubdomainOf(parent))
                    .sibling
                else
                    .out_of_bailiwick;
                return .{
                    .record = rr,
                    .nameserver = server.target,
                    .scope = scope,
                    .address = address,
                };
            }
        }
        return null;
    }
};

fn strictNsTarget(rr: message.Record) Error!name_mod.Name {
    const target = rdata.targetName(rr) catch return error.InvalidNsRdata;
    if (try target.consumed() != rr.rdata.len) return error.InvalidNsRdata;
    return target;
}

fn expectName(n: name_mod.Name, expected: []const u8) !void {
    var out: [name_mod.Name.max_presentation_len]u8 = undefined;
    try std.testing.expectEqualStrings(expected, try n.writePresentation(&out));
}

test "extracts delegation NS DS and bailiwick-aware glue" {
    var packet: [2048]u8 = undefined;
    var compression: [96]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 1, .{ .response = true });
    try b.addQuestion("www.child.example", .A, .IN);
    try b.addNameRecord(.authority, "child.example", .NS, 3600, "ns1.child.example");
    try b.addNameRecord(.authority, "child.example", .NS, 3600, "ns2.sibling.example");
    try b.addNameRecord(.authority, "child.example", .NS, 3600, "ns3.external.test");
    try b.addRawRecord(.authority, "child.example", .DS, .IN, 3600, &.{ 0x12, 0x34, 15, 2, 1, 2, 3, 4 });
    try b.addA(.additional, "ns1.child.example", 3600, .{ 192, 0, 2, 1 });
    try b.addAAAA(.additional, "ns2.sibling.example", 3600, .{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ .{2});
    try b.addA(.additional, "ns3.external.test", 3600, .{ 198, 51, 100, 3 });
    try b.addA(.additional, "unrelated.example", 3600, .{ 203, 0, 113, 9 });
    const msg = try message.Message.init(try b.finish());

    const referral = try Referral.init(msg, .{ .name = "www.child.example", .qtype = .A });
    try expectName(referral.delegation, "child.example");

    var ns = try referral.nameServers();
    const ns1 = (try ns.next()).?;
    const ns2 = (try ns.next()).?;
    const ns3 = (try ns.next()).?;
    try std.testing.expect(ns1.in_domain);
    try std.testing.expect(!ns2.in_domain);
    try std.testing.expect(!ns3.in_domain);
    try expectName(ns1.target, "ns1.child.example");
    try std.testing.expect((try ns.next()) == null);

    var ds = try referral.ds();
    const delegation_ds = (try ds.next()).?;
    try std.testing.expectEqual(@as(u16, 0x1234), delegation_ds.data.key_tag);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, delegation_ds.data.digest);
    try std.testing.expect((try ds.next()) == null);

    var glue = try referral.gluePresentation("example");
    const g1 = (try glue.next()).?;
    const g2 = (try glue.next()).?;
    const g3 = (try glue.next()).?;
    try std.testing.expectEqual(GlueScope.in_domain, g1.scope);
    try std.testing.expectEqual(GlueScope.sibling, g2.scope);
    try std.testing.expectEqual(GlueScope.out_of_bailiwick, g3.scope);
    try std.testing.expect(g1.usable());
    try std.testing.expect(g2.usable());
    try std.testing.expect(!g3.usable());
    try std.testing.expect((try glue.next()) == null); // unrelated Additional A is ignored
}

test "rejects mixed or unrelated delegation owners" {
    var packet: [1024]u8 = undefined;
    var compression: [48]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 2, .{ .response = true });
    try b.addQuestion("www.child.example", .A, .IN);
    try b.addNameRecord(.authority, "child.example", .NS, 300, "ns.child.example");
    try b.addNameRecord(.authority, "other.example", .NS, 300, "ns.other.example");
    try std.testing.expectError(error.MixedDelegations, Referral.init(try message.Message.init(try b.finish()), .{ .name = "www.child.example", .qtype = .A }));

    var b2 = try builder.Builder.init(&packet, &compression, 3, .{ .response = true });
    try b2.addQuestion("www.child.example", .A, .IN);
    try b2.addNameRecord(.authority, "unrelated.test", .NS, 300, "ns.unrelated.test");
    try std.testing.expectError(error.NotReferral, Referral.init(try message.Message.init(try b2.finish()), .{ .name = "www.child.example", .qtype = .A }));
}

test "glue classification requires an ancestor parent zone" {
    var packet: [768]u8 = undefined;
    var compression: [32]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 4, .{ .response = true });
    try b.addQuestion("www.child.example", .A, .IN);
    try b.addNameRecord(.authority, "child.example", .NS, 300, "ns.child.example");
    const referral = try Referral.init(try message.Message.init(try b.finish()), .{ .name = "www.child.example", .qtype = .A });
    try std.testing.expectError(error.ParentNotAncestor, referral.gluePresentation("other.test"));
}

test "SOA or answer data prevents referral extraction" {
    var packet: [1024]u8 = undefined;
    var compression: [48]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 5, .{ .response = true });
    try b.addQuestion("child.example", .A, .IN);
    try b.addA(.answer, "child.example", 60, .{ 192, 0, 2, 1 });
    try b.addNameRecord(.authority, "child.example", .NS, 300, "ns.child.example");
    try std.testing.expectError(error.NotReferral, Referral.init(try message.Message.init(try b.finish()), .{ .name = "child.example", .qtype = .A }));

    var b2 = try builder.Builder.init(&packet, &compression, 6, .{ .response = true });
    try b2.addQuestion("child.example", .AAAA, .IN);
    try b2.addSoa(.authority, "example", 60, "ns.example", "hostmaster.example", 1, 3600, 600, 86400, 60);
    try b2.addNameRecord(.authority, "child.example", .NS, 300, "ns.child.example");
    try std.testing.expectError(error.NotReferral, Referral.init(try message.Message.init(try b2.finish()), .{ .name = "child.example", .qtype = .AAAA }));
}

test "unrelated malformed address data is ignored while matched glue is parsed" {
    var packet: [1024]u8 = undefined;
    var compression: [48]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 7, .{ .response = true });
    try b.addQuestion("www.child.example", .A, .IN);
    try b.addNameRecord(.authority, "child.example", .NS, 300, "ns.child.example");
    try b.addRawRecord(.additional, "noise.example", .A, .IN, 60, &.{ 1, 2, 3 });
    try b.addA(.additional, "ns.child.example", 60, .{ 192, 0, 2, 9 });
    const referral = try Referral.init(try message.Message.init(try b.finish()), .{ .name = "www.child.example", .qtype = .A });
    var glue = try referral.gluePresentation("example");
    const item = (try glue.next()).?;
    try std.testing.expectEqual(GlueScope.in_domain, item.scope);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 9 }, &item.address.ipv4);
    try std.testing.expect((try glue.next()) == null);
}

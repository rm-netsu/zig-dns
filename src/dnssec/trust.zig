const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const rdata = @import("../rdata.zig");
const key = @import("key.zig");
const ds_mod = @import("ds.zig");
const policy_mod = @import("policy.zig");
const crypto_backend = @import("crypto_backend.zig");
const status_mod = @import("status.zig");

pub const SecurityStatus = status_mod.SecurityStatus;

pub const Reason = enum {
    unproven_delegation,
    authenticated_no_ds,
    opt_out,
    no_supported_ds,
    no_matching_dnskey,
};

pub const ValidationState = struct {
    status: SecurityStatus,
    reason: ?Reason = null,
};

pub const Error = name_mod.Error || rdata.Error || key.Error || ds_mod.Error || error{
    EmptyDnskeySet,
    EmptyDsSet,
    NotDnskey,
    NotDs,
    NotTrustAnchor,
    OwnerMismatch,
    ClassMismatch,
    InvalidDnskey,
};

pub const DnskeySet = struct {
    owner: name_mod.Name,
    class: types.Class,
    records: []const message.Record,

    pub fn init(records: []const message.Record) Error!DnskeySet {
        if (records.len == 0) return error.EmptyDnskeySet;
        const first = records[0];
        if (first.rr_type != .DNSKEY) return error.NotDnskey;
        for (records) |rr| {
            if (rr.rr_type != .DNSKEY) return error.NotDnskey;
            if (rr.class != first.class) return error.ClassMismatch;
            if (!(try rr.name.eqlIgnoreCase(first.name))) return error.OwnerMismatch;
            const parsed = try rdata.dnskey(rr);
            if (parsed.protocol != 3 or parsed.public_key.len == 0) return error.InvalidDnskey;
        }
        return .{ .owner = first.name, .class = first.class, .records = records };
    }

    pub fn find(self: DnskeySet, key_tag: u16, algorithm: u8) Error!?message.Record {
        for (self.records) |rr| {
            const parsed = try rdata.dnskey(rr);
            if (parsed.algorithm != algorithm) continue;
            if (try key.keyTag(rr.rdata) != key_tag) continue;
            return rr;
        }
        return null;
    }
};

pub const TrustAnchor = union(enum) {
    dnskey: message.Record,
    ds: message.Record,

    pub fn init(rr: message.Record) Error!TrustAnchor {
        return switch (rr.rr_type) {
            .DNSKEY => .{ .dnskey = rr },
            .DS => .{ .ds = rr },
            else => error.NotTrustAnchor,
        };
    }

    pub fn matches(self: TrustAnchor, dnskeys: DnskeySet, digest_scratch: []u8) Error!bool {
        return switch (self) {
            .dnskey => |anchor| blk: {
                if (!(try anchor.name.eqlIgnoreCase(dnskeys.owner)) or anchor.class != dnskeys.class) break :blk false;
                for (dnskeys.records) |rr| {
                    if (std.mem.eql(u8, anchor.rdata, rr.rdata)) break :blk true;
                }
                break :blk false;
            },
            .ds => |anchor| blk: {
                if (!(try anchor.name.eqlIgnoreCase(dnskeys.owner)) or anchor.class != dnskeys.class) break :blk false;
                const parsed_ds = try rdata.ds(anchor);
                if (!ds_mod.supportsDigest(parsed_ds.digest_type)) break :blk false;
                for (dnskeys.records) |rr| {
                    const parsed_key = try rdata.dnskey(rr);
                    if (parsed_key.protocol != 3 or (parsed_key.flags & 0x0100) == 0) continue;
                    if ((try ds_mod.matchDnskey(dnskeys.owner, parsed_ds, rr.rdata, digest_scratch)) == .match) break :blk true;
                }
                break :blk false;
            },
        };
    }
};

pub const Delegation = struct {
    owner: name_mod.Name,
    class: types.Class,
    evidence: Evidence,

    pub const Evidence = union(enum) {
        unproven,
        no_ds,
        opt_out,
        ds: []const message.Record,
    };

    pub fn unproven(owner: name_mod.Name, class: types.Class) Delegation {
        return .{ .owner = owner, .class = class, .evidence = .unproven };
    }

    pub fn authenticatedNoDs(owner: name_mod.Name, class: types.Class) Delegation {
        return .{ .owner = owner, .class = class, .evidence = .no_ds };
    }

    pub fn authenticatedOptOut(owner: name_mod.Name, class: types.Class) Delegation {
        return .{ .owner = owner, .class = class, .evidence = .opt_out };
    }

    pub fn authenticatedDs(records: []const message.Record) Error!Delegation {
        if (records.len == 0) return error.EmptyDsSet;
        const first = records[0];
        if (first.rr_type != .DS) return error.NotDs;
        for (records) |rr| {
            if (rr.rr_type != .DS) return error.NotDs;
            if (rr.class != first.class) return error.ClassMismatch;
            if (!(try rr.name.eqlIgnoreCase(first.name))) return error.OwnerMismatch;
            _ = try rdata.ds(rr);
        }
        return .{ .owner = first.name, .class = first.class, .evidence = .{ .ds = records } };
    }

    pub fn evaluate(self: Delegation, dnskeys: DnskeySet, digest_scratch: []u8, options: Options) Error!LinkResult {
        if (!(try self.owner.eqlIgnoreCase(dnskeys.owner))) return error.OwnerMismatch;
        if (self.class != dnskeys.class) return error.ClassMismatch;
        return switch (self.evidence) {
            .unproven => .{ .validation = .{ .status = .indeterminate, .reason = .unproven_delegation } },
            .no_ds => .{ .validation = .{ .status = .insecure, .reason = .authenticated_no_ds } },
            .opt_out => .{ .validation = .{ .status = .insecure, .reason = .opt_out } },
            .ds => |ds_records| evaluateDs(self.owner, ds_records, dnskeys, digest_scratch, options),
        };
    }
};

pub const Options = struct {
    algorithm_policy: policy_mod.AlgorithmPolicy = policy_mod.AlgorithmPolicy.registry_2026_01_13,
    backend: crypto_backend.Backend = crypto_backend.Backend.builtin,
};

pub const LinkResult = struct {
    validation: ValidationState,
    ds: ?message.Record = null,
    dnskey: ?message.Record = null,
};

fn evaluateDs(owner: name_mod.Name, ds_records: []const message.Record, dnskeys: DnskeySet, digest_scratch: []u8, options: Options) Error!LinkResult {
    var usable_ds = false;
    for (ds_records) |ds_rr| {
        const parsed_ds = try rdata.ds(ds_rr);
        if (!ds_mod.supportsDigest(parsed_ds.digest_type)) continue;
        if (!options.algorithm_policy.accepts(parsed_ds.algorithm)) continue;
        if (!options.backend.supports(parsed_ds.algorithm)) continue;
        usable_ds = true;

        for (dnskeys.records) |key_rr| {
            const parsed_key = try rdata.dnskey(key_rr);
            if (parsed_key.protocol != 3 or (parsed_key.flags & 0x0100) == 0) continue;
            if (parsed_key.algorithm != parsed_ds.algorithm) continue;
            if (try key.keyTag(key_rr.rdata) != parsed_ds.key_tag) continue;
            if ((try ds_mod.matchDnskey(owner, parsed_ds, key_rr.rdata, digest_scratch)) == .match) {
                return .{
                    .validation = .{ .status = .secure },
                    .ds = ds_rr,
                    .dnskey = key_rr,
                };
            }
        }
    }

    if (!usable_ds) return .{ .validation = .{ .status = .insecure, .reason = .no_supported_ds } };
    return .{ .validation = .{ .status = .bogus, .reason = .no_matching_dnskey } };
}

fn parsedName(presentation: []const u8, out: []u8) !name_mod.Name {
    const wire = try name_mod.writePresentationWire(presentation, out);
    return name_mod.Name.init(wire, 0);
}

test "delegation states remain distinct" {
    var owner_buf: [64]u8 = undefined;
    const owner = try parsedName("example", &owner_buf);

    // A tiny synthetic key set is enough to exercise non-DS evidence states.
    const packet = [_]u8{ 0, 0x01, 0x00, 0x03, 15, 1 };
    const key_owner = try name_mod.Name.init(&packet, 0);
    const rr: message.Record = .{
        .packet = &packet,
        .name = key_owner,
        .rr_type = .DNSKEY,
        .class = .IN,
        .ttl = 60,
        .rdata_offset = 1,
        .rdata = packet[1..],
    };
    var keys_array = [_]message.Record{rr};
    const keys = try DnskeySet.init(&keys_array);
    var scratch: [48]u8 = undefined;

    // Use the same root owner for the synthetic key set and evidence.
    const unproven = Delegation.unproven(key_owner, .IN);
    const absent = Delegation.authenticatedNoDs(key_owner, .IN);
    const opt_out = Delegation.authenticatedOptOut(key_owner, .IN);
    try std.testing.expectEqual(SecurityStatus.indeterminate, (try unproven.evaluate(keys, &scratch, .{})).validation.status);
    try std.testing.expectEqual(SecurityStatus.insecure, (try absent.evaluate(keys, &scratch, .{})).validation.status);
    try std.testing.expectEqual(Reason.opt_out, (try opt_out.evaluate(keys, &scratch, .{})).validation.reason.?);
    _ = owner;
}

test "DS to DNSKEY link becomes secure only after digest match" {
    const builder_mod = @import("../builder.zig");
    const Ed25519 = std.crypto.sign.Ed25519;
    const pair = try Ed25519.KeyPair.generateDeterministic([_]u8{0x5a} ** Ed25519.KeyPair.seed_length);
    const public_key = pair.public_key.toBytes();

    var owner_wire_buf: [64]u8 = undefined;
    const owner = try parsedName("child.example", &owner_wire_buf);
    var dnskey_rdata: [4 + public_key.len]u8 = undefined;
    dnskey_rdata[0..4].* = .{ 0x01, 0x00, 0x03, 15 };
    dnskey_rdata[4..].* = public_key;
    const tag = try key.keyTag(&dnskey_rdata);
    var digest_buf: [48]u8 = undefined;
    const digest = try ds_mod.digestDnskey(owner, &dnskey_rdata, 2, &digest_buf);

    var packet: [768]u8 = undefined;
    var compression: [32]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 1, .{ .response = true });
    try b.addDs(.authority, "child.example", 300, tag, 15, 2, digest);
    try b.addDnskey(.additional, "child.example", 300, 0x0100, 15, &public_key);
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    var authority = try m.records(.authority);
    var ds_records = [_]message.Record{(try authority.next()).?};
    var additional = try m.records(.additional);
    var key_records = [_]message.Record{(try additional.next()).?};

    const delegation = try Delegation.authenticatedDs(&ds_records);
    const dnskeys = try DnskeySet.init(&key_records);
    var scratch: [48]u8 = undefined;
    const result = try delegation.evaluate(dnskeys, &scratch, .{});
    try std.testing.expectEqual(SecurityStatus.secure, result.validation.status);
    try std.testing.expect(result.ds != null and result.dnskey != null);

    const anchor = try TrustAnchor.init(ds_records[0]);
    try std.testing.expect(try anchor.matches(dnskeys, &scratch));
}

test "supported DS mismatch is bogus while unsupported algorithm is insecure" {
    const builder_mod = @import("../builder.zig");
    var owner_buf: [64]u8 = undefined;
    const owner = try parsedName("child.example", &owner_buf);

    const public_key = [_]u8{0x22} ** 32;
    var rdata15: [36]u8 = undefined;
    rdata15[0..4].* = .{ 0x01, 0x00, 0x03, 15 };
    rdata15[4..].* = public_key;
    const tag15 = try key.keyTag(&rdata15);
    var digest_buf: [48]u8 = undefined;
    var wrong_digest = (try ds_mod.digestDnskey(owner, &rdata15, 2, &digest_buf))[0..32].*;
    wrong_digest[0] ^= 1;

    var packet: [1024]u8 = undefined;
    var compression: [32]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 1, .{ .response = true });
    try b.addDs(.authority, "child.example", 300, tag15, 15, 2, &wrong_digest);
    try b.addDnskey(.additional, "child.example", 300, 0x0100, 15, &public_key);
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    var authority = try m.records(.authority);
    var ds_records = [_]message.Record{(try authority.next()).?};
    var additional = try m.records(.additional);
    var key_records = [_]message.Record{(try additional.next()).?};
    const bogus = try (try Delegation.authenticatedDs(&ds_records)).evaluate(try DnskeySet.init(&key_records), &digest_buf, .{});
    try std.testing.expectEqual(SecurityStatus.bogus, bogus.validation.status);

    // ED448 is accepted by the registry policy but not implemented by the
    // built-in backend, so an authenticated DS-only path is treated as
    // unsupported rather than as a failed cryptographic match.
    var rdata16: [36]u8 = undefined;
    rdata16[0..4].* = .{ 0x01, 0x00, 0x03, 16 };
    rdata16[4..].* = public_key;
    const tag16 = try key.keyTag(&rdata16);
    const digest16 = try ds_mod.digestDnskey(owner, &rdata16, 2, &digest_buf);
    var packet2: [1024]u8 = undefined;
    var compression2: [32]builder_mod.CompressionEntry = undefined;
    var b2 = try builder_mod.Builder.init(&packet2, &compression2, 1, .{ .response = true });
    try b2.addDs(.authority, "child.example", 300, tag16, 16, 2, digest16);
    try b2.addDnskey(.additional, "child.example", 300, 0x0100, 16, &public_key);
    const bytes2 = try b2.finish();
    const m2 = try message.Message.init(bytes2);
    var authority2 = try m2.records(.authority);
    var ds_records2 = [_]message.Record{(try authority2.next()).?};
    var additional2 = try m2.records(.additional);
    var key_records2 = [_]message.Record{(try additional2.next()).?};
    const unsupported = try (try Delegation.authenticatedDs(&ds_records2)).evaluate(try DnskeySet.init(&key_records2), &digest_buf, .{});
    try std.testing.expectEqual(SecurityStatus.insecure, unsupported.validation.status);
    try std.testing.expectEqual(Reason.no_supported_ds, unsupported.validation.reason.?);
}

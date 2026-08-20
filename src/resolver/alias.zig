const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const rdata = @import("../rdata.zig");
const builder = @import("../builder.zig");

pub const Error = name_mod.Error || rdata.Error || error{
    InvalidRecordType,
    OwnerMismatch,
    DnameNotApplicable,
    SynthesizedCnameMismatch,
    SynthesizedCnameTtl,
    AliasLoop,
    AliasLimit,
    NoSpace,
};

/// One canonical DNS name stored in a caller-owned byte arena.
pub const Entry = struct {
    offset: usize,
    len: u16,
};

/// Bounded, allocation-free CNAME/DNAME chain state.
///
/// `entries` limits alias depth (`entries.len - 1` redirects after the initial
/// name), while `storage` holds canonical uncompressed wire names. The chain
/// never borrows DNS packets and can therefore outlive each response buffer.
pub const Chain = struct {
    entries: []Entry,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn initPresentation(entries: []Entry, storage: []u8, initial: []const u8) Error!Chain {
        var canonical_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const wire = try canonicalPresentation(initial, &canonical_buf);
        return initCanonical(entries, storage, wire);
    }

    pub fn initWire(entries: []Entry, storage: []u8, initial: name_mod.Uncompressed) Error!Chain {
        var canonical_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const n = try name_mod.Name.init(initial.bytes, 0);
        const wire = try n.writeCanonicalWire(&canonical_buf);
        return initCanonical(entries, storage, wire);
    }

    fn initCanonical(entries: []Entry, storage: []u8, wire: []const u8) Error!Chain {
        if (entries.len == 0) return error.AliasLimit;
        if (wire.len > storage.len) return error.NoSpace;
        @memcpy(storage[0..wire.len], wire);
        entries[0] = .{ .offset = 0, .len = @intCast(wire.len) };
        return .{ .entries = entries, .storage = storage, .count = 1, .used = wire.len };
    }

    pub fn aliasCount(self: *const Chain) usize {
        return self.count - 1;
    }

    pub fn currentWire(self: *const Chain) []const u8 {
        const e = self.entries[self.count - 1];
        return self.storage[e.offset..][0..e.len];
    }

    pub fn currentName(self: *const Chain) name_mod.Uncompressed {
        return .{ .bytes = self.currentWire() };
    }

    pub fn writeCurrentPresentation(self: *const Chain, out: []u8) name_mod.Error![]const u8 {
        const n = try name_mod.Name.init(self.currentWire(), 0);
        return n.writePresentation(out);
    }

    /// Follow a CNAME whose owner must equal the current chain name.
    pub fn followCname(self: *Chain, rr: message.Record) Error!void {
        if (rr.rr_type != .CNAME) return error.InvalidRecordType;

        var owner_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const owner = try rr.name.writeCanonicalWire(&owner_buf);
        if (!std.mem.eql(u8, owner, self.currentWire())) return error.OwnerMismatch;

        var target_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const target = try (try rdata.targetName(rr)).writeCanonicalWire(&target_buf);
        try self.appendCanonical(target);
    }

    /// Follow a DNAME by replacing the matching owner suffix of the current
    /// name with the DNAME target. The DNAME owner itself is not redirected.
    pub fn followDname(self: *Chain, rr: message.Record) Error!void {
        if (rr.rr_type != .DNAME) return error.InvalidRecordType;
        var target_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const target = try substituteDname(self.currentName(), rr, &target_buf);
        try self.appendCanonical(target);
    }

    fn appendCanonical(self: *Chain, wire: []const u8) Error!void {
        // Check semantic failures before mutating caller-owned storage.
        for (self.entries[0..self.count]) |entry| {
            const prior = self.storage[entry.offset..][0..entry.len];
            if (std.mem.eql(u8, prior, wire)) return error.AliasLoop;
        }
        if (self.count == self.entries.len) return error.AliasLimit;
        if (wire.len > self.storage.len -| self.used) return error.NoSpace;

        const offset = self.used;
        @memcpy(self.storage[offset..][0..wire.len], wire);
        self.entries[self.count] = .{ .offset = offset, .len = @intCast(wire.len) };
        self.count += 1;
        self.used += wire.len;
    }
};

/// Compute the canonical CNAME target implied by a DNAME RR.
///
/// `source` must be strictly below the DNAME owner. Only whole labels are
/// replaced and an oversized result fails before `out` is modified.
pub fn substituteDname(source: name_mod.Uncompressed, dname: message.Record, out: []u8) Error![]const u8 {
    if (dname.rr_type != .DNAME) return error.InvalidRecordType;

    var source_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var owner_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var target_buf: [name_mod.Name.max_wire_len]u8 = undefined;

    const source_name = try name_mod.Name.init(source.bytes, 0);
    const source_wire = try source_name.writeCanonicalWire(&source_buf);
    const owner_wire = try dname.name.writeCanonicalWire(&owner_buf);
    const target_wire = try (try rdata.targetName(dname)).writeCanonicalWire(&target_buf);

    const prefix_len = strictSuffixPrefixLen(source_wire, owner_wire) orelse return error.DnameNotApplicable;
    const result_len = prefix_len + target_wire.len;
    if (result_len > name_mod.Name.max_wire_len) return error.NameTooLong;
    if (result_len > out.len) return error.BufferTooSmall;

    @memcpy(out[0..prefix_len], source_wire[0..prefix_len]);
    @memcpy(out[prefix_len..][0..target_wire.len], target_wire);
    return out[0..result_len];
}

/// Verify a synthesized CNAME accompanying a DNAME substitution.
///
/// RFC 6672 requires owner=source and target=the DNAME substitution. Resolvers
/// must accept a synthesized TTL of either zero or the DNAME TTL.
pub fn validateSynthesizedCname(source: name_mod.Uncompressed, dname: message.Record, cname: message.Record) Error!void {
    if (dname.rr_type != .DNAME or cname.rr_type != .CNAME) return error.InvalidRecordType;
    if (dname.class != cname.class) return error.SynthesizedCnameMismatch;

    var source_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const source_canonical = try (try name_mod.Name.init(source.bytes, 0)).writeCanonicalWire(&source_buf);

    var owner_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const cname_owner = try cname.name.writeCanonicalWire(&owner_buf);
    if (!std.mem.eql(u8, source_canonical, cname_owner)) return error.SynthesizedCnameMismatch;

    var expected_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const expected = try substituteDname(source, dname, &expected_buf);
    var actual_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const actual = try (try rdata.targetName(cname)).writeCanonicalWire(&actual_buf);
    if (!std.mem.eql(u8, expected, actual)) return error.SynthesizedCnameMismatch;

    if (cname.ttl != 0 and cname.ttl != dname.ttl) return error.SynthesizedCnameTtl;
}

fn canonicalPresentation(presentation: []const u8, out: []u8) name_mod.Error![]const u8 {
    var wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const wire = try name_mod.writePresentationWire(presentation, &wire_buf);
    return (try name_mod.Name.init(wire, 0)).writeCanonicalWire(out);
}

fn strictSuffixPrefixLen(source: []const u8, suffix: []const u8) ?usize {
    var pos: usize = 0;
    while (pos < source.len) {
        // `pos != 0` preserves the DNAME rule that the owner itself is not
        // redirected. Check before the root-label exit so a DNAME at the
        // root can redirect any non-root name.
        if (pos != 0 and std.mem.eql(u8, source[pos..], suffix)) return pos;
        const label_len: usize = source[pos];
        if (label_len == 0) return null;
        pos += 1 + label_len;
    }
    return null;
}

fn firstAnswer(m: message.Message, rr_type: types.Type) !message.Record {
    var it = try m.records(.answer);
    while (try it.next()) |rr| if (rr.rr_type == rr_type) return rr;
    return error.TestExpectedEqual;
}

test "bounded CNAME chain canonicalizes names and detects loops" {
    var entries: [4]Entry = undefined;
    var storage: [128]u8 = undefined;
    var chain = try Chain.initPresentation(&entries, &storage, "WWW.Example");

    var packet: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 1, .{ .response = true });
    try b.addQuestion("www.example", .A, .IN);
    try b.addNameRecord(.answer, "WWW.EXAMPLE", .CNAME, 60, "Alias.Example");
    try b.addNameRecord(.answer, "alias.example", .CNAME, 60, "www.example");
    const m = try message.Message.init(try b.finish());

    var answers = try m.records(.answer);
    const first = (try answers.next()).?;
    const second = (try answers.next()).?;
    try chain.followCname(first);
    try std.testing.expectEqual(@as(usize, 1), chain.aliasCount());
    var present: [64]u8 = undefined;
    try std.testing.expectEqualStrings("alias.example", try chain.writeCurrentPresentation(&present));

    const before_count = chain.count;
    const before_used = chain.used;
    try std.testing.expectError(error.AliasLoop, chain.followCname(second));
    try std.testing.expectEqual(before_count, chain.count);
    try std.testing.expectEqual(before_used, chain.used);
}

test "alias depth and storage failures are transactional" {
    var entries: [2]Entry = undefined;
    var storage: [64]u8 = undefined;
    var chain = try Chain.initPresentation(&entries, &storage, "a.example");

    var packet: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 2, .{ .response = true });
    try b.addNameRecord(.answer, "a.example", .CNAME, 60, "b.example");
    try b.addNameRecord(.answer, "b.example", .CNAME, 60, "c.example");
    const m = try message.Message.init(try b.finish());
    var answers = try m.records(.answer);
    try chain.followCname((try answers.next()).?);
    const before_count = chain.count;
    const before_used = chain.used;
    try std.testing.expectError(error.AliasLimit, chain.followCname((try answers.next()).?));
    try std.testing.expectEqual(before_count, chain.count);
    try std.testing.expectEqual(before_used, chain.used);

    var tight_entries: [2]Entry = undefined;
    var tight_storage: [12]u8 = undefined;
    var tight = try Chain.initPresentation(&tight_entries, &tight_storage, "a.example");
    var b2 = try builder.Builder.init(&packet, &compression, 3, .{ .response = true });
    try b2.addNameRecord(.answer, "a.example", .CNAME, 60, "longer.example");
    const m2 = try message.Message.init(try b2.finish());
    const rr = try firstAnswer(m2, .CNAME);
    const tight_count = tight.count;
    const tight_used = tight.used;
    try std.testing.expectError(error.NoSpace, tight.followCname(rr));
    try std.testing.expectEqual(tight_count, tight.count);
    try std.testing.expectEqual(tight_used, tight.used);
}

test "DNAME substitution preserves prefix labels and validates synthesized CNAME" {
    var packet: [768]u8 = undefined;
    var compression: [32]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 4, .{ .response = true });
    try b.addQuestion("Host.Sub.Old.Example", .A, .IN);
    try b.addNameRecord(.answer, "Old.Example", .DNAME, 300, "New.Example");
    try b.addNameRecord(.answer, "host.sub.old.example", .CNAME, 300, "host.sub.new.example");
    const m = try message.Message.init(try b.finish());
    const dname = try firstAnswer(m, .DNAME);
    const cname = try firstAnswer(m, .CNAME);

    var source_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const source = try name_mod.Uncompressed.init(try name_mod.writePresentationWire("HOST.SUB.OLD.EXAMPLE", &source_buf));
    var target_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const target = try substituteDname(source, dname, &target_buf);
    var target_name = try name_mod.Name.init(target, 0);
    var present: [64]u8 = undefined;
    try std.testing.expectEqualStrings("host.sub.new.example", try target_name.writePresentation(&present));
    try validateSynthesizedCname(source, dname, cname);

    var entries: [4]Entry = undefined;
    var storage: [128]u8 = undefined;
    var chain = try Chain.initWire(&entries, &storage, source);
    try chain.followDname(dname);
    try std.testing.expectEqualStrings("host.sub.new.example", try chain.writeCurrentPresentation(&present));
}

test "DNAME does not redirect its owner and detects bad synthesized CNAME" {
    var packet: [768]u8 = undefined;
    var compression: [32]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 5, .{ .response = true });
    try b.addNameRecord(.answer, "old.example", .DNAME, 300, "new.example");
    try b.addNameRecord(.answer, "host.old.example", .CNAME, 42, "wrong.example");
    const m = try message.Message.init(try b.finish());
    const dname = try firstAnswer(m, .DNAME);
    const cname = try firstAnswer(m, .CNAME);

    var owner_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const owner = try name_mod.Uncompressed.init(try name_mod.writePresentationWire("old.example", &owner_buf));
    var out: [name_mod.Name.max_wire_len]u8 = undefined;
    try std.testing.expectError(error.DnameNotApplicable, substituteDname(owner, dname, &out));

    var source_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const source = try name_mod.Uncompressed.init(try name_mod.writePresentationWire("host.old.example", &source_buf));
    try std.testing.expectError(error.SynthesizedCnameMismatch, validateSynthesizedCname(source, dname, cname));
}

test "synthesized CNAME accepts zero TTL and rejects unrelated TTL" {
    var packet: [768]u8 = undefined;
    var compression: [32]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 6, .{ .response = true });
    try b.addNameRecord(.answer, "old.example", .DNAME, 300, "new.example");
    try b.addNameRecord(.answer, "host.old.example", .CNAME, 0, "host.new.example");
    const m = try message.Message.init(try b.finish());
    const dname = try firstAnswer(m, .DNAME);
    const zero = try firstAnswer(m, .CNAME);
    var source_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const source = try name_mod.Uncompressed.init(try name_mod.writePresentationWire("host.old.example", &source_buf));
    try validateSynthesizedCname(source, dname, zero);

    var b2 = try builder.Builder.init(&packet, &compression, 7, .{ .response = true });
    try b2.addNameRecord(.answer, "old.example", .DNAME, 300, "new.example");
    try b2.addNameRecord(.answer, "host.old.example", .CNAME, 299, "host.new.example");
    const m2 = try message.Message.init(try b2.finish());
    try std.testing.expectError(
        error.SynthesizedCnameTtl,
        validateSynthesizedCname(source, try firstAnswer(m2, .DNAME), try firstAnswer(m2, .CNAME)),
    );
}

test "DNAME at root redirects non-root names but not the root owner" {
    var packet: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 8, .{ .response = true });
    try b.addNameRecord(.answer, ".", .DNAME, 300, "mirror.example");
    const m = try message.Message.init(try b.finish());
    const dname = try firstAnswer(m, .DNAME);

    var source_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const source = try name_mod.Uncompressed.init(try name_mod.writePresentationWire("www", &source_buf));
    var out: [name_mod.Name.max_wire_len]u8 = undefined;
    const result = try substituteDname(source, dname, &out);
    const result_name = try name_mod.Name.init(result, 0);
    var present: [64]u8 = undefined;
    try std.testing.expectEqualStrings("www.mirror.example", try result_name.writePresentation(&present));

    const root = try name_mod.Uncompressed.init(&.{0});
    try std.testing.expectError(error.DnameNotApplicable, substituteDname(root, dname, &out));
}

test "CNAME owner and type failures leave chain unchanged" {
    var entries: [4]Entry = undefined;
    var storage: [128]u8 = undefined;
    var chain = try Chain.initPresentation(&entries, &storage, "host.example");

    var packet: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 9, .{ .response = true });
    try b.addNameRecord(.answer, "other.example", .CNAME, 60, "target.example");
    try b.addA(.answer, "host.example", 60, .{ 192, 0, 2, 1 });
    const m = try message.Message.init(try b.finish());
    var answers = try m.records(.answer);
    const wrong_owner = (try answers.next()).?;
    const wrong_type = (try answers.next()).?;

    const before_count = chain.count;
    const before_used = chain.used;
    try std.testing.expectError(error.OwnerMismatch, chain.followCname(wrong_owner));
    try std.testing.expectError(error.InvalidRecordType, chain.followCname(wrong_type));
    try std.testing.expectEqual(before_count, chain.count);
    try std.testing.expectEqual(before_used, chain.used);
}

test "oversized DNAME substitution is rejected before output or chain mutation" {
    var packet: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 10, .{ .response = true });
    try b.addNameRecord(.answer, "x", .DNAME, 300, "target.example");
    const m = try message.Message.init(try b.finish());
    const dname = try firstAnswer(m, .DNAME);

    var source_wire: [255]u8 = undefined;
    var pos: usize = 0;
    for ([_]struct { len: u8, byte: u8 }{
        .{ .len = 63, .byte = 'a' },
        .{ .len = 63, .byte = 'b' },
        .{ .len = 63, .byte = 'c' },
        .{ .len = 59, .byte = 'd' },
        .{ .len = 1, .byte = 'x' },
    }) |label| {
        source_wire[pos] = label.len;
        pos += 1;
        @memset(source_wire[pos..][0..label.len], label.byte);
        pos += label.len;
    }
    source_wire[pos] = 0;
    pos += 1;
    try std.testing.expectEqual(source_wire.len, pos);
    const source = try name_mod.Uncompressed.init(&source_wire);

    var out: [name_mod.Name.max_wire_len]u8 = [_]u8{0xa5} ** name_mod.Name.max_wire_len;
    try std.testing.expectError(error.NameTooLong, substituteDname(source, dname, &out));
    for (out) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);

    var entries: [3]Entry = undefined;
    var storage: [512]u8 = undefined;
    var chain = try Chain.initWire(&entries, &storage, source);
    const before_count = chain.count;
    const before_used = chain.used;
    try std.testing.expectError(error.NameTooLong, chain.followDname(dname));
    try std.testing.expectEqual(before_count, chain.count);
    try std.testing.expectEqual(before_used, chain.used);
}

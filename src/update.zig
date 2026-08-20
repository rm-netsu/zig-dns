const std = @import("std");
const types = @import("types.zig");
const message = @import("message.zig");
const name_mod = @import("name.zig");
const builder_mod = @import("builder.zig");

pub const Error = builder_mod.Error || message.ParseError || error{
    InvalidOpcode,
    NotRequest,
    InvalidZoneSection,
    InvalidZoneClass,
    InvalidDataType,
    InvalidPrerequisite,
    InvalidUpdate,
    NotZone,
};

/// RFC 2136 UPDATE request composer. It owns no allocation and wraps the
/// normal DNS Builder so callers can still drop down to raw Additional data
/// or TSIG after composing prerequisites and updates.
pub const Composer = struct {
    builder: builder_mod.Builder,
    zone_class: types.Class,

    pub fn init(
        out: []u8,
        compression: []builder_mod.CompressionEntry,
        id: u16,
        zone: []const u8,
        zone_class: types.Class,
    ) Error!Composer {
        if (!validZoneClass(zone_class)) return error.InvalidZoneClass;
        var builder = try builder_mod.Builder.init(out, compression, id, .{ .opcode = .update });
        try builder.addQuestion(zone, .SOA, zone_class);
        return .{ .builder = builder, .zone_class = zone_class };
    }

    pub fn finish(self: *Composer) Error![]const u8 {
        return self.builder.finish();
    }

    // ----- Prerequisites -------------------------------------------------

    pub fn requireNameExists(self: *Composer, owner: []const u8) Error!void {
        try self.requireOwnerInZone(owner);
        try self.builder.addRawRecord(.answer, owner, .ANY, .ANY, 0, &.{});
    }

    pub fn requireNameNotExists(self: *Composer, owner: []const u8) Error!void {
        try self.requireOwnerInZone(owner);
        try self.builder.addRawRecord(.answer, owner, .ANY, .NONE, 0, &.{});
    }

    pub fn requireRrsetExists(self: *Composer, owner: []const u8, rr_type: types.Type) Error!void {
        try requireDataType(rr_type);
        try self.requireOwnerInZone(owner);
        try self.builder.addRawRecord(.answer, owner, rr_type, .ANY, 0, &.{});
    }

    pub fn requireRrsetNotExists(self: *Composer, owner: []const u8, rr_type: types.Type) Error!void {
        try requireDataType(rr_type);
        try self.requireOwnerInZone(owner);
        try self.builder.addRawRecord(.answer, owner, rr_type, .NONE, 0, &.{});
    }

    /// Add one member of a value-dependent prerequisite RRset. Call this once
    /// for every member that must match the zone RRset exactly.
    pub fn requireRecordExists(self: *Composer, owner: []const u8, rr_type: types.Type, rdata: []const u8) Error!void {
        try requireDataType(rr_type);
        try self.requireOwnerInZone(owner);
        try self.builder.addRawRecord(.answer, owner, rr_type, self.zone_class, 0, rdata);
    }

    // ----- Updates -------------------------------------------------------

    pub fn add(self: *Composer, owner: []const u8, rr_type: types.Type, ttl: u32, rdata: []const u8) Error!void {
        try requireDataType(rr_type);
        try self.requireOwnerInZone(owner);
        try self.builder.addRawRecord(.authority, owner, rr_type, self.zone_class, ttl, rdata);
    }

    pub fn deleteName(self: *Composer, owner: []const u8) Error!void {
        try self.requireOwnerInZone(owner);
        try self.builder.addRawRecord(.authority, owner, .ANY, .ANY, 0, &.{});
    }

    pub fn deleteRrset(self: *Composer, owner: []const u8, rr_type: types.Type) Error!void {
        try requireDataType(rr_type);
        try self.requireOwnerInZone(owner);
        try self.builder.addRawRecord(.authority, owner, rr_type, .ANY, 0, &.{});
    }

    pub fn deleteRecord(self: *Composer, owner: []const u8, rr_type: types.Type, rdata: []const u8) Error!void {
        try requireDataType(rr_type);
        try self.requireOwnerInZone(owner);
        try self.builder.addRawRecord(.authority, owner, rr_type, .NONE, 0, rdata);
    }

    // ----- Common typed values ------------------------------------------

    pub fn addA(self: *Composer, owner: []const u8, ttl: u32, addr: [4]u8) Error!void {
        try self.add(owner, .A, ttl, &addr);
    }

    pub fn deleteA(self: *Composer, owner: []const u8, addr: [4]u8) Error!void {
        try self.deleteRecord(owner, .A, &addr);
    }

    pub fn requireA(self: *Composer, owner: []const u8, addr: [4]u8) Error!void {
        try self.requireRecordExists(owner, .A, &addr);
    }

    pub fn addAAAA(self: *Composer, owner: []const u8, ttl: u32, addr: [16]u8) Error!void {
        try self.add(owner, .AAAA, ttl, &addr);
    }

    pub fn deleteAAAA(self: *Composer, owner: []const u8, addr: [16]u8) Error!void {
        try self.deleteRecord(owner, .AAAA, &addr);
    }

    pub fn requireAAAA(self: *Composer, owner: []const u8, addr: [16]u8) Error!void {
        try self.requireRecordExists(owner, .AAAA, &addr);
    }

    pub fn addNameRecord(self: *Composer, owner: []const u8, rr_type: types.Type, ttl: u32, target: []const u8) Error!void {
        try requireSingleNameType(rr_type);
        try self.requireOwnerInZone(owner);
        var w = try self.builder.beginRecord(.authority, owner, rr_type, self.zone_class, ttl);
        errdefer w.abort();
        try w.writeName(target);
        try w.finish();
    }

    pub fn deleteNameRecord(self: *Composer, owner: []const u8, rr_type: types.Type, target: []const u8) Error!void {
        try requireSingleNameType(rr_type);
        try self.requireOwnerInZone(owner);
        var w = try self.builder.beginRecord(.authority, owner, rr_type, .NONE, 0);
        errdefer w.abort();
        try w.writeName(target);
        try w.finish();
    }

    pub fn requireNameRecord(self: *Composer, owner: []const u8, rr_type: types.Type, target: []const u8) Error!void {
        try requireSingleNameType(rr_type);
        try self.requireOwnerInZone(owner);
        var w = try self.builder.beginRecord(.answer, owner, rr_type, self.zone_class, 0);
        errdefer w.abort();
        try w.writeName(target);
        try w.finish();
    }

    pub fn addMx(self: *Composer, owner: []const u8, ttl: u32, preference: u16, exchange: []const u8) Error!void {
        try self.writeMx(.authority, owner, self.zone_class, ttl, preference, exchange);
    }

    pub fn deleteMx(self: *Composer, owner: []const u8, preference: u16, exchange: []const u8) Error!void {
        try self.writeMx(.authority, owner, .NONE, 0, preference, exchange);
    }

    pub fn requireMx(self: *Composer, owner: []const u8, preference: u16, exchange: []const u8) Error!void {
        try self.writeMx(.answer, owner, self.zone_class, 0, preference, exchange);
    }

    fn requireOwnerInZone(self: *Composer, owner: []const u8) Error!void {
        var owner_wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const owner_wire = try name_mod.writePresentationWire(owner, &owner_wire_buf);
        const owner_name = try name_mod.Name.init(owner_wire, 0);
        const zone_name = try name_mod.Name.init(self.builder.out, types.Header.wire_len);
        if (!(try owner_name.isSubdomainOf(zone_name))) return error.NotZone;
    }

    fn writeMx(self: *Composer, section: types.Section, owner: []const u8, class: types.Class, ttl: u32, preference: u16, exchange: []const u8) Error!void {
        try self.requireOwnerInZone(owner);
        var w = try self.builder.beginRecord(section, owner, .MX, class, ttl);
        errdefer w.abort();
        try w.writeU16(preference);
        try w.writeName(exchange);
        try w.finish();
    }
};

/// Syntactic request view after RFC 2136 prescan. Zone-content prerequisites
/// and authorization are intentionally left to the caller's zone store.
pub const Request = struct {
    message: message.Message,
    zone: message.Question,

    pub fn prerequisites(self: Request) message.RecordIterator {
        return self.message.records(.answer) catch unreachable;
    }

    pub fn updates(self: Request) message.RecordIterator {
        return self.message.records(.authority) catch unreachable;
    }

    pub fn additional(self: Request) message.RecordIterator {
        return self.message.records(.additional) catch unreachable;
    }
};

pub fn validateRequest(m: message.Message) Error!Request {
    if (m.header.flags.opcode != .update) return error.InvalidOpcode;
    if (m.header.flags.response) return error.NotRequest;
    if (m.header.question_count != 1) return error.InvalidZoneSection;

    var questions = m.questions();
    const zone = (try questions.next()) orelse return error.InvalidZoneSection;
    if (zone.qtype != .SOA or !validZoneClass(zone.qclass)) return error.InvalidZoneSection;
    if (try questions.next() != null) return error.InvalidZoneSection;

    var prerequisites = try m.records(.answer);
    while (try prerequisites.next()) |rr| {
        if (!(try rr.name.isSubdomainOf(zone.name))) return error.NotZone;
        try validatePrerequisite(rr, zone.qclass);
    }

    var updates = try m.records(.authority);
    while (try updates.next()) |rr| {
        if (!(try rr.name.isSubdomainOf(zone.name))) return error.NotZone;
        try validateUpdate(rr, zone.qclass);
    }

    // Fully walk Additional and reject trailing bytes, while leaving extension
    // semantics (OPT/TSIG/etc.) to their dedicated validators.
    var additional = try m.records(.additional);
    while (try additional.next()) |_| {}
    if (additional.offset != m.bytes.len) return error.TrailingData;

    return .{ .message = m, .zone = zone };
}

fn validatePrerequisite(rr: message.Record, zone_class: types.Class) Error!void {
    if (rr.ttl != 0) return error.InvalidPrerequisite;
    if (rr.class == .ANY or rr.class == .NONE) {
        if (rr.rdata.len != 0) return error.InvalidPrerequisite;
        if (rr.rr_type != .ANY) try requireDataType(rr.rr_type);
        return;
    }
    if (rr.class != zone_class or rr.rr_type == .ANY) return error.InvalidPrerequisite;
    requireDataType(rr.rr_type) catch return error.InvalidPrerequisite;
}

fn validateUpdate(rr: message.Record, zone_class: types.Class) Error!void {
    if (rr.class == zone_class) {
        requireDataType(rr.rr_type) catch return error.InvalidUpdate;
        return;
    }
    if (rr.class == .ANY) {
        if (rr.ttl != 0 or rr.rdata.len != 0) return error.InvalidUpdate;
        if (rr.rr_type != .ANY) requireDataType(rr.rr_type) catch return error.InvalidUpdate;
        return;
    }
    if (rr.class == .NONE) {
        if (rr.ttl != 0 or rr.rr_type == .ANY) return error.InvalidUpdate;
        requireDataType(rr.rr_type) catch return error.InvalidUpdate;
        return;
    }
    return error.InvalidUpdate;
}

fn validZoneClass(class: types.Class) bool {
    return class != .ANY and class != .NONE and @intFromEnum(class) != 0;
}

fn requireDataType(rr_type: types.Type) Error!void {
    const value = @intFromEnum(rr_type);

    // IANA DNS Parameters separates ordinary data RRTYPEs from the
    // 128..255 QTYPE/Meta-TYPE space. 61440..65279 and 65535 are reserved,
    // while 65280..65534 is explicitly Private Use and remains valid opaque
    // zone data. OPT is the one currently-assigned meta-type below 128.
    if (value == 0 or rr_type == .OPT or
        (value >= 128 and value <= 255) or
        (value >= 61440 and value <= 65279) or
        value == 65535)
    {
        return error.InvalidDataType;
    }
}

fn requireSingleNameType(rr_type: types.Type) Error!void {
    switch (rr_type) {
        .NS, .CNAME, .PTR, .DNAME, .MB, .MD, .MF, .MG, .MR => {},
        else => return error.InvalidDataType,
    }
}

test "UPDATE composer encodes prerequisite and update metavalues" {
    var packet: [1024]u8 = undefined;
    var compression: [32]builder_mod.CompressionEntry = undefined;
    var u = try Composer.init(&packet, &compression, 0x1234, "example.com", .IN);
    try u.requireNameExists("host.example.com");
    try u.requireRrsetNotExists("host.example.com", .AAAA);
    try u.requireA("host.example.com", .{ 192, 0, 2, 1 });
    try u.addA("host.example.com", 300, .{ 192, 0, 2, 2 });
    try u.deleteRrset("old.example.com", .TXT);
    try u.deleteName("gone.example.com");

    const m = try message.Message.init(try u.finish());
    const request = try validateRequest(m);
    try std.testing.expectEqual(types.Opcode.update, m.header.flags.opcode);
    try std.testing.expectEqual(@as(u16, 1), m.header.question_count);
    try std.testing.expectEqual(@as(u16, 3), m.header.answer_count);
    try std.testing.expectEqual(@as(u16, 3), m.header.authority_count);
    try std.testing.expectEqual(types.Type.SOA, request.zone.qtype);

    var prerequisites = request.prerequisites();
    const name_exists = (try prerequisites.next()).?;
    try std.testing.expectEqual(types.Class.ANY, name_exists.class);
    try std.testing.expectEqual(types.Type.ANY, name_exists.rr_type);
    try std.testing.expectEqual(@as(usize, 0), name_exists.rdata.len);
    const missing_aaaa = (try prerequisites.next()).?;
    try std.testing.expectEqual(types.Class.NONE, missing_aaaa.class);
    try std.testing.expectEqual(types.Type.AAAA, missing_aaaa.rr_type);
    const exact_a = (try prerequisites.next()).?;
    try std.testing.expectEqual(types.Class.IN, exact_a.class);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, exact_a.rdata);

    var updates = request.updates();
    const add_a = (try updates.next()).?;
    try std.testing.expectEqual(types.Class.IN, add_a.class);
    try std.testing.expectEqual(@as(u32, 300), add_a.ttl);
    const delete_txt = (try updates.next()).?;
    try std.testing.expectEqual(types.Class.ANY, delete_txt.class);
    try std.testing.expectEqual(types.Type.TXT, delete_txt.rr_type);
    const delete_name = (try updates.next()).?;
    try std.testing.expectEqual(types.Class.ANY, delete_name.class);
    try std.testing.expectEqual(types.Type.ANY, delete_name.rr_type);
}

test "UPDATE invalid operations fail before builder mutation" {
    var packet: [256]u8 = undefined;
    var compression: [8]builder_mod.CompressionEntry = undefined;
    var u = try Composer.init(&packet, &compression, 1, "example.com", .IN);
    const before = u.builder.pos;
    try std.testing.expectError(error.InvalidDataType, u.add("example.com", .AXFR, 1, &.{}));
    try std.testing.expectEqual(before, u.builder.pos);
    try std.testing.expectEqual(@as(u16, 0), u.builder.header.authority_count);
}

test "UPDATE validator rejects malformed prerequisite metavalues" {
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 9, .{ .opcode = .update });
    try b.addQuestion("example.com", .SOA, .IN);
    try b.addRawRecord(.answer, "host.example.com", .A, .ANY, 1, &.{});
    const m = try message.Message.init(try b.finish());
    try std.testing.expectError(error.InvalidPrerequisite, validateRequest(m));
}

test "UPDATE typed name and MX values remain structurally valid" {
    var packet: [1024]u8 = undefined;
    var compression: [32]builder_mod.CompressionEntry = undefined;
    var u = try Composer.init(&packet, &compression, 11, "example.com", .IN);
    try u.requireNameRecord("www.example.com", .CNAME, "origin.example.com");
    try u.addNameRecord("www.example.com", .CNAME, 60, "new.example.com");
    try u.addMx("example.com", 300, 10, "mail.example.com");
    const m = try message.Message.init(try u.finish());
    _ = try validateRequest(m);
    try m.validate();
}

test "UPDATE rejects out-of-zone owners before mutation" {
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var u = try Composer.init(&packet, &compression, 13, "example.com", .IN);
    const before_pos = u.builder.pos;
    const before_compression = u.builder.compression_len;
    try std.testing.expectError(error.NotZone, u.addA("example.net", 60, .{ 192, 0, 2, 1 }));
    try std.testing.expectEqual(before_pos, u.builder.pos);
    try std.testing.expectEqual(before_compression, u.builder.compression_len);
    try std.testing.expectEqual(@as(u16, 0), u.builder.header.authority_count);
}

test "UPDATE prescan rejects out-of-zone wire records" {
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 14, .{ .opcode = .update });
    try b.addQuestion("example.com", .SOA, .IN);
    try b.addRawRecord(.authority, "example.net", .A, .IN, 60, &.{ 192, 0, 2, 1 });
    try std.testing.expectError(error.NotZone, validateRequest(try message.Message.init(try b.finish())));
}

test "UPDATE rejects meta and reserved type ranges transactionally" {
    const invalid_types = [_]types.Type{
        .NXNAME,
        @enumFromInt(200),
        @enumFromInt(61440),
        @enumFromInt(65535),
    };

    for (invalid_types) |rr_type| {
        var packet: [512]u8 = undefined;
        var compression: [16]builder_mod.CompressionEntry = undefined;
        var u = try Composer.init(&packet, &compression, 16, "example.com", .IN);
        const before_pos = u.builder.pos;
        const before_compression = u.builder.compression_len;
        try std.testing.expectError(error.InvalidDataType, u.add("host.example.com", rr_type, 60, &.{}));
        try std.testing.expectEqual(before_pos, u.builder.pos);
        try std.testing.expectEqual(before_compression, u.builder.compression_len);
        try std.testing.expectEqual(@as(u16, 0), u.builder.header.authority_count);
    }
}

test "UPDATE prescan rejects meta and reserved type ranges" {
    const invalid_types = [_]types.Type{
        .NXNAME,
        @enumFromInt(200),
        @enumFromInt(61440),
        @enumFromInt(65535),
    };

    for (invalid_types) |rr_type| {
        var packet: [512]u8 = undefined;
        var compression: [16]builder_mod.CompressionEntry = undefined;
        var b = try builder_mod.Builder.init(&packet, &compression, 17, .{ .opcode = .update });
        try b.addQuestion("example.com", .SOA, .IN);
        try b.addRawRecord(.authority, "host.example.com", rr_type, .IN, 60, &.{});
        try std.testing.expectError(error.InvalidUpdate, validateRequest(try message.Message.init(try b.finish())));
    }
}

test "UPDATE accepts unknown ordinary and private-use data types" {
    const data_types = [_]types.Type{ @enumFromInt(258), @enumFromInt(60000), @enumFromInt(65400) };
    for (data_types) |rr_type| {
        var packet: [512]u8 = undefined;
        var compression: [16]builder_mod.CompressionEntry = undefined;
        var u = try Composer.init(&packet, &compression, 18, "example.com", .IN);
        try u.add("future.example.com", rr_type, 60, &.{ 0xde, 0xad });
        _ = try validateRequest(try message.Message.init(try u.finish()));
    }
}

test "UPDATE preserves RFC 3597 unknown data types" {
    const future_type: types.Type = @enumFromInt(65400);
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var u = try Composer.init(&packet, &compression, 15, "example.com", .IN);
    try u.requireRrsetNotExists("future.example.com", future_type);
    try u.add("future.example.com", future_type, 60, &.{ 0xde, 0xad, 0xbe, 0xef });
    const m = try message.Message.init(try u.finish());
    _ = try validateRequest(m);
}

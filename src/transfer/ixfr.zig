const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const rdata = @import("../rdata.zig");
const builder_mod = @import("../builder.zig");
const soa_mod = @import("soa.zig");

pub const Error = message.ParseError || rdata.Error || builder_mod.Error || soa_mod.Error || error{
    InvalidClass,
    InvalidId,
    NotResponse,
    InvalidOpcode,
    TruncatedResponse,
    InvalidQuestionCount,
    QuestionMismatch,
    NonEmptyAuthority,
    EmptyAnswer,
    NotAuthoritative,
    FirstRecordNotSoa,
    SoaOwnerMismatch,
    RecordClassMismatch,
    DeltaStartMismatch,
    DeltaOriginMismatch,
    DeltaSerialNotIncreasing,
    AmbiguousSerial,
    ClosingSoaMismatch,
    UnexpectedDataAfterCurrentVersion,
    MessageNotDrained,
    AlreadyComplete,
    FailedTransfer,
    PrematureEof,
};

pub const Storage = struct {
    zone: [name_mod.Name.max_wire_len]u8 = undefined,
    current: soa_mod.Storage = .{},
    last_new: soa_mod.Storage = .{},
};

pub const Mode = enum { incremental, axfr_fallback, up_to_date };
const Phase = enum { awaiting_current, deciding, deleting, adding, fallback, complete, failed };

pub const Event = union(enum) {
    /// Server's current SOA, always the first answer RR.
    begin: message.Record,
    /// The client already has the server's current serial. No changes follow.
    up_to_date: void,
    /// The response has switched to full-zone AXFR-style fallback semantics.
    fallback_begin: void,
    fallback_record: message.Record,
    fallback_end: message.Record,
    /// Older SOA beginning the deletions for one delta.
    delete_begin: message.Record,
    delete: message.Record,
    /// Newer SOA beginning additions for one delta.
    add_begin: message.Record,
    add: message.Record,
    /// All delete/add records for one serial transition have been emitted.
    version_end: void,
    /// Closing copy of the current SOA after the final delta.
    end: message.Record,
    remote_error: types.Rcode,
};

pub const Transfer = struct {
    storage: *Storage,
    expected_id: u16,
    zone_class: types.Class,
    zone_len: u16,
    requested_serial: u32,
    current: ?soa_mod.Snapshot = null,
    last_new: ?soa_mod.Snapshot = null,
    origin_serial: u32 = 0,
    mode_value: ?Mode = null,
    phase: Phase = .awaiting_current,
    message_open: bool = false,

    pub fn init(
        storage: *Storage,
        expected_id: u16,
        zone: []const u8,
        zone_class: types.Class,
        requested_serial: u32,
    ) Error!Transfer {
        if (!validClass(zone_class)) return error.InvalidClass;
        const wire = try name_mod.writePresentationWire(zone, &storage.zone);
        return .{
            .storage = storage,
            .expected_id = expected_id,
            .zone_class = zone_class,
            .zone_len = @intCast(wire.len),
            .requested_serial = requested_serial,
        };
    }

    pub fn initWire(
        storage: *Storage,
        expected_id: u16,
        zone: name_mod.Uncompressed,
        zone_class: types.Class,
        requested_serial: u32,
    ) Error!Transfer {
        if (!validClass(zone_class)) return error.InvalidClass;
        @memcpy(storage.zone[0..zone.bytes.len], zone.bytes);
        return .{
            .storage = storage,
            .expected_id = expected_id,
            .zone_class = zone_class,
            .zone_len = @intCast(zone.bytes.len),
            .requested_serial = requested_serial,
        };
    }

    pub fn mode(self: Transfer) ?Mode {
        return self.mode_value;
    }

    pub fn isComplete(self: Transfer) bool {
        return self.phase == .complete;
    }

    pub fn openMessage(self: *Transfer, m: message.Message) Error!Cursor {
        if (self.phase == .complete) return error.AlreadyComplete;
        if (self.phase == .failed) return error.FailedTransfer;
        if (self.message_open) return error.MessageNotDrained;

        try m.validate();
        if (m.header.id != self.expected_id) return error.InvalidId;
        if (!m.header.flags.response) return error.NotResponse;
        if (m.header.flags.opcode != .query) return error.InvalidOpcode;
        if (m.header.flags.truncated) return error.TruncatedResponse;
        if (m.header.authority_count != 0) return error.NonEmptyAuthority;

        const rcode = try m.rcode();
        const first = self.phase == .awaiting_current;
        const error_response = rcode != .no_error;
        try self.validateQuestions(m, first, error_response);

        if (error_response) {
            self.phase = .complete;
            return .{
                .transfer = self,
                .answers = try m.records(.answer),
                .pending_error = rcode,
            };
        }

        if (!m.header.flags.authoritative) return error.NotAuthoritative;
        if (m.header.answer_count == 0) return error.EmptyAnswer;

        self.message_open = true;
        return .{ .transfer = self, .answers = try m.records(.answer) };
    }

    pub fn finish(self: *Transfer) Error!void {
        if (self.message_open) return error.MessageNotDrained;
        return switch (self.phase) {
            .complete => {},
            .failed => error.FailedTransfer,
            else => error.PrematureEof,
        };
    }

    fn zoneName(self: Transfer) Error!name_mod.Name {
        return name_mod.Name.init(self.storage.zone[0..self.zone_len], 0);
    }

    fn validateQuestions(self: Transfer, m: message.Message, first: bool, error_response: bool) Error!void {
        if (first or error_response) {
            if (m.header.question_count != 1) return error.InvalidQuestionCount;
        } else if (m.header.question_count > 1) {
            return error.InvalidQuestionCount;
        }
        if (m.header.question_count == 0) return;
        var questions = m.questions();
        const q = (try questions.next()) orelse return error.InvalidQuestionCount;
        if (q.qtype != .IXFR or q.qclass != self.zone_class) return error.QuestionMismatch;
        if (!(try q.name.eqlIgnoreCase(try self.zoneName()))) return error.QuestionMismatch;
        if (try questions.next() != null) return error.InvalidQuestionCount;
    }

    fn validateZoneRecord(self: Transfer, rr: message.Record) Error!void {
        if (rr.class != self.zone_class) return error.RecordClassMismatch;
    }

    fn validateZoneSoa(self: Transfer, rr: message.Record) Error!void {
        try self.validateZoneRecord(rr);
        if (!(try rr.name.eqlIgnoreCase(try self.zoneName()))) return error.SoaOwnerMismatch;
    }

    fn fail(self: *Transfer) void {
        self.phase = .failed;
        self.message_open = false;
    }
};

pub const Cursor = struct {
    transfer: *Transfer,
    answers: message.RecordIterator,
    pending: ?Event = null,
    pending_terminal: bool = false,
    pending_error: ?types.Rcode = null,
    finished: bool = false,

    pub fn next(self: *Cursor) Error!?Event {
        if (self.finished) return null;

        if (self.pending_error) |rcode| {
            self.pending_error = null;
            self.finished = true;
            return .{ .remote_error = rcode };
        }

        if (self.pending) |event| {
            self.pending = null;
            if (self.pending_terminal) {
                self.pending_terminal = false;
                self.finished = true;
                self.transfer.message_open = false;
            }
            return event;
        }

        const maybe_rr = self.answers.next() catch |err| {
            self.transfer.fail();
            return err;
        };
        const rr = maybe_rr orelse return self.endMessage() catch |err| {
            self.transfer.fail();
            return err;
        };

        return self.processRecord(rr) catch |err| {
            self.transfer.fail();
            return err;
        };
    }

    fn endMessage(self: *Cursor) Error!?Event {
        if (self.transfer.phase == .deciding) {
            const current = self.transfer.current orelse return error.FailedTransfer;
            if (!(try serverSerialIsNewer(self.transfer.requested_serial, current.serial))) {
                self.transfer.mode_value = .up_to_date;
                self.transfer.phase = .complete;
                self.transfer.message_open = false;
                self.finished = true;
                return .{ .up_to_date = {} };
            }
        }
        self.transfer.message_open = false;
        self.finished = true;
        return null;
    }

    fn processRecord(self: *Cursor, rr: message.Record) Error!Event {
        switch (self.transfer.phase) {
            .awaiting_current => {
                if (rr.rr_type != .SOA) return error.FirstRecordNotSoa;
                try self.transfer.validateZoneSoa(rr);
                self.transfer.current = try soa_mod.Snapshot.capture(rr, &self.transfer.storage.current);
                self.transfer.phase = .deciding;
                return .{ .begin = rr };
            },
            .deciding => return self.decideMode(rr),
            .deleting => return self.processDelete(rr),
            .adding => return self.processAdd(rr),
            .fallback => return self.processFallback(rr),
            .complete, .failed => return error.FailedTransfer,
        }
    }

    fn decideMode(self: *Cursor, rr: message.Record) Error!Event {
        const current = self.transfer.current orelse return error.FailedTransfer;
        if (!(try serverSerialIsNewer(self.transfer.requested_serial, current.serial))) return error.UnexpectedDataAfterCurrentVersion;
        try self.transfer.validateZoneRecord(rr);

        if (rr.rr_type == .SOA) {
            try self.transfer.validateZoneSoa(rr);
            if (try current.eqlRecord(&self.transfer.storage.current, rr)) {
                self.transfer.mode_value = .axfr_fallback;
                self.transfer.phase = .complete;
                self.pending = .{ .fallback_end = rr };
                self.pending_terminal = true;
                return .{ .fallback_begin = {} };
            }
            const old = try rdata.soa(rr);
            if (old.serial != self.transfer.requested_serial) return error.DeltaStartMismatch;
            self.transfer.mode_value = .incremental;
            self.transfer.origin_serial = old.serial;
            self.transfer.phase = .deleting;
            return .{ .delete_begin = rr };
        }

        self.transfer.mode_value = .axfr_fallback;
        self.transfer.phase = .fallback;
        self.pending = .{ .fallback_record = rr };
        return .{ .fallback_begin = {} };
    }

    fn processDelete(self: *Cursor, rr: message.Record) Error!Event {
        try self.transfer.validateZoneRecord(rr);
        if (rr.rr_type != .SOA) return .{ .delete = rr };
        try self.transfer.validateZoneSoa(rr);
        const next_soa = try soa_mod.Snapshot.capture(rr, &self.transfer.storage.last_new);
        try requireNewerSerial(self.transfer.origin_serial, next_soa.serial);
        self.transfer.last_new = next_soa;
        self.transfer.phase = .adding;
        return .{ .add_begin = rr };
    }

    fn processAdd(self: *Cursor, rr: message.Record) Error!Event {
        try self.transfer.validateZoneRecord(rr);
        if (rr.rr_type != .SOA) return .{ .add = rr };
        try self.transfer.validateZoneSoa(rr);

        const current = self.transfer.current orelse return error.FailedTransfer;
        const last_new = self.transfer.last_new orelse return error.FailedTransfer;
        if (try current.eqlRecord(&self.transfer.storage.current, rr)) {
            if (!(try last_new.eqlSnapshot(&self.transfer.storage.last_new, current, &self.transfer.storage.current))) {
                return error.ClosingSoaMismatch;
            }
            if (self.answers.remaining != 0) return error.UnexpectedDataAfterCurrentVersion;
            self.transfer.phase = .complete;
            self.pending = .{ .end = rr };
            self.pending_terminal = true;
            return .{ .version_end = {} };
        }

        if (!(try last_new.eqlRecord(&self.transfer.storage.last_new, rr))) return error.DeltaOriginMismatch;
        self.transfer.origin_serial = last_new.serial;
        self.transfer.phase = .deleting;
        self.pending = .{ .delete_begin = rr };
        return .{ .version_end = {} };
    }

    fn processFallback(self: *Cursor, rr: message.Record) Error!Event {
        try self.transfer.validateZoneRecord(rr);
        if (rr.rr_type != .SOA) return .{ .fallback_record = rr };
        try self.transfer.validateZoneSoa(rr);
        const current = self.transfer.current orelse return error.FailedTransfer;
        if (!(try current.eqlRecord(&self.transfer.storage.current, rr))) return error.ClosingSoaMismatch;
        if (self.answers.remaining != 0) return error.UnexpectedDataAfterCurrentVersion;
        self.transfer.phase = .complete;
        self.transfer.message_open = false;
        self.finished = true;
        return .{ .fallback_end = rr };
    }
};

pub const QuerySoa = struct {
    ttl: u32,
    mname: []const u8,
    rname: []const u8,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
};

pub const QuerySoaWire = struct {
    ttl: u32,
    mname: name_mod.Uncompressed,
    rname: name_mod.Uncompressed,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
};

pub fn queryBuilder(
    out: []u8,
    compression: []builder_mod.CompressionEntry,
    id: u16,
    zone: []const u8,
    zone_class: types.Class,
    client_soa: QuerySoa,
) Error!builder_mod.Builder {
    if (!validClass(zone_class)) return error.InvalidClass;
    var builder = try builder_mod.Builder.init(out, compression, id, .{});
    try builder.addQuestion(zone, .IXFR, zone_class);
    var w = try builder.beginRecord(.authority, zone, .SOA, zone_class, client_soa.ttl);
    errdefer w.abort();
    try w.writeName(client_soa.mname);
    try w.writeName(client_soa.rname);
    try w.writeU32(client_soa.serial);
    try w.writeU32(client_soa.refresh);
    try w.writeU32(client_soa.retry);
    try w.writeU32(client_soa.expire);
    try w.writeU32(client_soa.minimum);
    try w.finish();
    return builder;
}

pub fn queryBuilderWire(
    out: []u8,
    compression: []builder_mod.CompressionEntry,
    id: u16,
    zone: name_mod.Uncompressed,
    zone_class: types.Class,
    client_soa: QuerySoaWire,
) Error!builder_mod.Builder {
    if (!validClass(zone_class)) return error.InvalidClass;
    var builder = try builder_mod.Builder.init(out, compression, id, .{});
    try builder.addQuestionWire(zone, .IXFR, zone_class);
    var w = try builder.beginRecordWire(.authority, zone, .SOA, zone_class, client_soa.ttl);
    errdefer w.abort();
    try w.writeWireName(client_soa.mname);
    try w.writeWireName(client_soa.rname);
    try w.writeU32(client_soa.serial);
    try w.writeU32(client_soa.refresh);
    try w.writeU32(client_soa.retry);
    try w.writeU32(client_soa.expire);
    try w.writeU32(client_soa.minimum);
    try w.finish();
    return builder;
}

fn validClass(class: types.Class) bool {
    return class != .ANY and class != .NONE and @intFromEnum(class) != 0;
}

fn serverSerialIsNewer(client: u32, server: u32) Error!bool {
    if (client == server) return false;
    const forward = server -% client;
    if (forward == 0x8000_0000) return error.AmbiguousSerial;
    return forward < 0x8000_0000;
}

fn requireNewerSerial(old: u32, new: u32) Error!void {
    if (!(try serverSerialIsNewer(old, new))) return error.DeltaSerialNotIncreasing;
}

fn addSoa(builder: *builder_mod.Builder, serial: u32) !void {
    try builder.addSoa(.answer, "example.com", 300, "ns1.example.com", "hostmaster.example.com", serial, 3600, 600, 86400, 300);
}

fn responseBuilder(packet: []u8, compression: []builder_mod.CompressionEntry, id: u16, with_question: bool) !builder_mod.Builder {
    var builder = try builder_mod.Builder.init(packet, compression, id, .{ .response = true, .authoritative = true });
    if (with_question) try builder.addQuestion("example.com", .IXFR, .IN);
    return builder;
}

test "IXFR wire query preserves arbitrary name octets" {
    const zone_bytes = [_]u8{ 3, 0, '.', 0xff, 0 };
    const mname_bytes = [_]u8{ 2, 0, 'm', 0 };
    const rname_bytes = [_]u8{ 2, 0, 'r', 0 };
    const zone = try name_mod.Uncompressed.init(&zone_bytes);
    const mname = try name_mod.Uncompressed.init(&mname_bytes);
    const rname = try name_mod.Uncompressed.init(&rname_bytes);
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var builder = try queryBuilderWire(&packet, &compression, 0x100f, zone, .IN, .{
        .ttl = 1,
        .mname = mname,
        .rname = rname,
        .serial = 7,
        .refresh = 1,
        .retry = 2,
        .expire = 3,
        .minimum = 4,
    });
    const m = try message.Message.init(try builder.finish());
    var q = m.questions();
    var expanded: [name_mod.Name.max_wire_len]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &zone_bytes, try (try q.next()).?.name.writeWire(&expanded));
    var authority = try m.records(.authority);
    const soa = try rdata.soa((try authority.next()).?);
    try std.testing.expectEqualSlices(u8, &mname_bytes, try soa.mname.writeWire(&expanded));
    try std.testing.expectEqualSlices(u8, &rname_bytes, try soa.rname.writeWire(&expanded));
}

test "IXFR query carries client SOA in Authority" {
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var builder = try queryBuilder(&packet, &compression, 0x1010, "example.com", .IN, .{
        .ttl = 300,
        .mname = "ns1.example.com",
        .rname = "hostmaster.example.com",
        .serial = 7,
        .refresh = 3600,
        .retry = 600,
        .expire = 86400,
        .minimum = 300,
    });
    const m = try message.Message.init(try builder.finish());
    try std.testing.expectEqual(@as(u16, 1), m.header.question_count);
    try std.testing.expectEqual(@as(u16, 1), m.header.authority_count);
    var q = m.questions();
    try std.testing.expectEqual(types.Type.IXFR, (try q.next()).?.qtype);
    var authority = try m.records(.authority);
    const rr = (try authority.next()).?;
    try std.testing.expectEqual(types.Type.SOA, rr.rr_type);
    try std.testing.expectEqual(@as(u32, 7), (try rdata.soa(rr)).serial);
}

test "IXFR streams one incremental delta as semantic events" {
    var packet: [2048]u8 = undefined;
    var compression: [64]builder_mod.CompressionEntry = undefined;
    var builder = try responseBuilder(&packet, &compression, 0x2020, true);
    try addSoa(&builder, 3);
    try addSoa(&builder, 1);
    try builder.addA(.answer, "old.example.com", 60, .{ 192, 0, 2, 1 });
    try addSoa(&builder, 3);
    try builder.addA(.answer, "new.example.com", 60, .{ 192, 0, 2, 3 });
    try addSoa(&builder, 3);

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 0x2020, "example.com", .IN, 1);
    var cursor = try transfer.openMessage(try message.Message.init(try builder.finish()));
    try std.testing.expect((try cursor.next()).? == .begin);
    try std.testing.expect((try cursor.next()).? == .delete_begin);
    try std.testing.expect((try cursor.next()).? == .delete);
    try std.testing.expect((try cursor.next()).? == .add_begin);
    try std.testing.expect((try cursor.next()).? == .add);
    try std.testing.expect((try cursor.next()).? == .version_end);
    try std.testing.expect((try cursor.next()).? == .end);
    try std.testing.expect(try cursor.next() == null);
    try transfer.finish();
    try std.testing.expectEqual(Mode.incremental, transfer.mode().?);
}

test "IXFR streams several deltas across DNS message boundaries" {
    var first_packet: [1536]u8 = undefined;
    var first_compression: [48]builder_mod.CompressionEntry = undefined;
    var first = try responseBuilder(&first_packet, &first_compression, 0x3030, true);
    try addSoa(&first, 3);
    try addSoa(&first, 1);
    try first.addA(.answer, "old.example.com", 60, .{ 192, 0, 2, 1 });

    var middle_packet: [1536]u8 = undefined;
    var middle_compression: [48]builder_mod.CompressionEntry = undefined;
    var middle = try responseBuilder(&middle_packet, &middle_compression, 0x3030, false);
    try addSoa(&middle, 2);
    try middle.addA(.answer, "v2.example.com", 60, .{ 192, 0, 2, 2 });
    try addSoa(&middle, 2);
    try middle.addAAAA(.answer, "removed.example.com", 60, .{0} ** 16);

    var last_packet: [1536]u8 = undefined;
    var last_compression: [48]builder_mod.CompressionEntry = undefined;
    var last = try responseBuilder(&last_packet, &last_compression, 0x3030, false);
    try addSoa(&last, 3);
    try last.addA(.answer, "v3.example.com", 60, .{ 192, 0, 2, 3 });
    try addSoa(&last, 3);

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 0x3030, "example.com", .IN, 1);
    var event_count: usize = 0;
    for ([_][]const u8{ try first.finish(), try middle.finish(), try last.finish() }) |wire| {
        var cursor = try transfer.openMessage(try message.Message.init(wire));
        while (try cursor.next()) |_| event_count += 1;
    }
    try transfer.finish();
    // begin + (delete_begin/delete/add_begin/add/version_end) * 2 + end
    try std.testing.expectEqual(@as(usize, 12), event_count);
}

test "IXFR detects premature EOF inside incremental delta" {
    var packet: [1024]u8 = undefined;
    var compression: [32]builder_mod.CompressionEntry = undefined;
    var builder = try responseBuilder(&packet, &compression, 0x3031, true);
    try addSoa(&builder, 3);
    try addSoa(&builder, 1);
    try builder.addA(.answer, "old.example.com", 60, .{ 192, 0, 2, 1 });

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 0x3031, "example.com", .IN, 1);
    var cursor = try transfer.openMessage(try message.Message.init(try builder.finish()));
    while (try cursor.next()) |_| {}
    try std.testing.expectError(error.PrematureEof, transfer.finish());
}

test "IXFR persistent state is bounded independently of delta count" {
    try std.testing.expect(@sizeOf(Storage) <= 2048);
    try std.testing.expect(@sizeOf(Transfer) <= 160);
}

test "IXFR detects AXFR fallback without materializing the zone" {
    var packet: [1536]u8 = undefined;
    var compression: [48]builder_mod.CompressionEntry = undefined;
    var builder = try responseBuilder(&packet, &compression, 0x4040, true);
    try addSoa(&builder, 9);
    try builder.addA(.answer, "www.example.com", 60, .{ 192, 0, 2, 9 });
    try addSoa(&builder, 9);

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 0x4040, "example.com", .IN, 1);
    var cursor = try transfer.openMessage(try message.Message.init(try builder.finish()));
    try std.testing.expect((try cursor.next()).? == .begin);
    try std.testing.expect((try cursor.next()).? == .fallback_begin);
    try std.testing.expect((try cursor.next()).? == .fallback_record);
    try std.testing.expect((try cursor.next()).? == .fallback_end);
    try transfer.finish();
    try std.testing.expectEqual(Mode.axfr_fallback, transfer.mode().?);
}

test "IXFR recognizes current client with a single SOA" {
    var packet: [768]u8 = undefined;
    var compression: [24]builder_mod.CompressionEntry = undefined;
    var builder = try responseBuilder(&packet, &compression, 0x5050, true);
    try addSoa(&builder, 12);

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 0x5050, "example.com", .IN, 12);
    var cursor = try transfer.openMessage(try message.Message.init(try builder.finish()));
    try std.testing.expect((try cursor.next()).? == .begin);
    try std.testing.expect((try cursor.next()).? == .up_to_date);
    try std.testing.expect(try cursor.next() == null);
    try transfer.finish();
    try std.testing.expectEqual(Mode.up_to_date, transfer.mode().?);
}

test "IXFR accepts a client serial newer than the server with a single SOA" {
    var packet: [768]u8 = undefined;
    var compression: [24]builder_mod.CompressionEntry = undefined;
    var builder = try responseBuilder(&packet, &compression, 0x5051, true);
    try addSoa(&builder, 12);

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 0x5051, "example.com", .IN, 13);
    var cursor = try transfer.openMessage(try message.Message.init(try builder.finish()));
    try std.testing.expect((try cursor.next()).? == .begin);
    try std.testing.expect((try cursor.next()).? == .up_to_date);
    try transfer.finish();
    try std.testing.expectEqual(Mode.up_to_date, transfer.mode().?);
}

test "IXFR validates delta origin chain and final current SOA" {
    var bad_start_packet: [1024]u8 = undefined;
    var bad_start_compression: [32]builder_mod.CompressionEntry = undefined;
    var bad_start = try responseBuilder(&bad_start_packet, &bad_start_compression, 0x6060, true);
    try addSoa(&bad_start, 5);
    try addSoa(&bad_start, 2);
    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 0x6060, "example.com", .IN, 1);
    var cursor = try transfer.openMessage(try message.Message.init(try bad_start.finish()));
    _ = try cursor.next();
    try std.testing.expectError(error.DeltaStartMismatch, cursor.next());

    var bad_close_packet: [1536]u8 = undefined;
    var bad_close_compression: [48]builder_mod.CompressionEntry = undefined;
    var bad_close = try responseBuilder(&bad_close_packet, &bad_close_compression, 0x6061, true);
    try addSoa(&bad_close, 5);
    try addSoa(&bad_close, 1);
    try addSoa(&bad_close, 3);
    try addSoa(&bad_close, 5);
    var storage2: Storage = .{};
    var transfer2 = try Transfer.init(&storage2, 0x6061, "example.com", .IN, 1);
    var cursor2 = try transfer2.openMessage(try message.Message.init(try bad_close.finish()));
    _ = try cursor2.next();
    _ = try cursor2.next();
    _ = try cursor2.next();
    try std.testing.expectError(error.ClosingSoaMismatch, cursor2.next());
}

test "IXFR marks ambiguous single-SOA serial relation failed" {
    var packet: [768]u8 = undefined;
    var compression: [24]builder_mod.CompressionEntry = undefined;
    var builder = try responseBuilder(&packet, &compression, 0x7070, true);
    try addSoa(&builder, 0x8000_0000);

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 0x7070, "example.com", .IN, 0);
    var cursor = try transfer.openMessage(try message.Message.init(try builder.finish()));
    _ = try cursor.next();
    try std.testing.expectError(error.AmbiguousSerial, cursor.next());
    try std.testing.expectError(error.FailedTransfer, transfer.finish());
}

test "IXFR serial transitions use RFC 1982 arithmetic" {
    try std.testing.expect(try serverSerialIsNewer(0xffff_ffff, 0));
    try std.testing.expect(!(try serverSerialIsNewer(13, 12)));
    try std.testing.expect(!(try serverSerialIsNewer(12, 12)));
    try std.testing.expectError(error.AmbiguousSerial, serverSerialIsNewer(0, 0x8000_0000));
    try requireNewerSerial(0xffff_ffff, 0);
    try requireNewerSerial(10, 11);
    try std.testing.expectError(error.DeltaSerialNotIncreasing, requireNewerSerial(11, 10));
    try std.testing.expectError(error.DeltaSerialNotIncreasing, requireNewerSerial(1, 1));
    try std.testing.expectError(error.AmbiguousSerial, requireNewerSerial(0, 0x8000_0000));
}

test "IXFR composes with TCP decoder across every stream split" {
    const tcp_mod = @import("../tcp.zig");

    var first_packet: [1536]u8 = undefined;
    var first_compression: [48]builder_mod.CompressionEntry = undefined;
    var first = try responseBuilder(&first_packet, &first_compression, 0x8181, true);
    try addSoa(&first, 3);
    try addSoa(&first, 1);
    try first.addA(.answer, "old.example.com", 60, .{ 192, 0, 2, 1 });
    const first_wire = try first.finish();

    var last_packet: [1536]u8 = undefined;
    var last_compression: [48]builder_mod.CompressionEntry = undefined;
    var last = try responseBuilder(&last_packet, &last_compression, 0x8181, false);
    try addSoa(&last, 3);
    try last.addA(.answer, "new.example.com", 60, .{ 192, 0, 2, 3 });
    try addSoa(&last, 3);
    const last_wire = try last.finish();

    var first_frame_buf: [1800]u8 = undefined;
    const first_frame = try tcp_mod.frame(first_wire, &first_frame_buf);
    var last_frame_buf: [1800]u8 = undefined;
    const last_frame = try tcp_mod.frame(last_wire, &last_frame_buf);
    var stream: [3600]u8 = undefined;
    @memcpy(stream[0..first_frame.len], first_frame);
    @memcpy(stream[first_frame.len..][0..last_frame.len], last_frame);
    const stream_wire = stream[0 .. first_frame.len + last_frame.len];

    const Driver = struct {
        fn consumeChunk(
            decoder: *tcp_mod.Decoder,
            transfer: *Transfer,
            chunk: []const u8,
            events: *usize,
        ) !void {
            var offset: usize = 0;
            while (offset < chunk.len) {
                const fed = try decoder.feed(chunk[offset..]);
                if (fed.consumed == 0) return error.TestUnexpectedResult;
                offset += fed.consumed;
                switch (fed.event) {
                    .need_more => {},
                    .message => |wire| {
                        var cursor = try transfer.openMessage(try message.Message.init(wire));
                        while (try cursor.next()) |_| events.* += 1;
                    },
                }
            }
        }
    };

    for (0..stream_wire.len + 1) |split| {
        var decoder_storage: [1536]u8 = undefined;
        var decoder = tcp_mod.Decoder.init(&decoder_storage);
        var storage: Storage = .{};
        var transfer = try Transfer.init(&storage, 0x8181, "example.com", .IN, 1);
        var events: usize = 0;
        try Driver.consumeChunk(&decoder, &transfer, stream_wire[0..split], &events);
        try Driver.consumeChunk(&decoder, &transfer, stream_wire[split..], &events);
        try decoder.finish();
        try transfer.finish();
        try std.testing.expectEqual(@as(usize, 7), events);
    }
}

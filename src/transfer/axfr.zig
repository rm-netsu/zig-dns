const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const rdata = @import("../rdata.zig");
const builder_mod = @import("../builder.zig");
const soa_mod = @import("soa.zig");

pub const Error = message.ParseError || rdata.Error || builder_mod.Error || error{
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
    UnexpectedSoa,
    ClosingSoaMismatch,
    MessageNotDrained,
    AlreadyComplete,
    FailedTransfer,
    PrematureEof,
};

/// Persistent caller-owned backing storage. Its size is independent of the
/// number of messages and records in the transfer.
pub const Storage = struct {
    zone: [name_mod.Name.max_wire_len]u8 = undefined,
    opening: soa_mod.Storage = .{},
};

const Phase = enum { awaiting_first, body, complete, failed };

pub const Event = union(enum) {
    /// First SOA of the transfer. This RR is not repeated as `.record`.
    begin: message.Record,
    /// One ordinary zone RR borrowed from the current DNS message.
    record: message.Record,
    /// Closing SOA, semantically identical to `.begin`.
    end: message.Record,
    /// A DNS error response terminates the AXFR session without a closing SOA.
    remote_error: types.Rcode,
};

/// Allocation-free RFC 5936 AXFR receiver state. The caller owns TCP framing,
/// message buffers, retry policy, and optional TSIG verification.
pub const Transfer = struct {
    storage: *Storage,
    expected_id: u16,
    zone_class: types.Class,
    zone_len: u16,
    opening: ?soa_mod.Snapshot = null,
    phase: Phase = .awaiting_first,
    message_open: bool = false,

    pub fn init(
        storage: *Storage,
        expected_id: u16,
        zone: []const u8,
        zone_class: types.Class,
    ) Error!Transfer {
        if (!validClass(zone_class)) return error.InvalidClass;
        const wire = try name_mod.writePresentationWire(zone, &storage.zone);
        return .{
            .storage = storage,
            .expected_id = expected_id,
            .zone_class = zone_class,
            .zone_len = @intCast(wire.len),
        };
    }

    pub fn initWire(
        storage: *Storage,
        expected_id: u16,
        zone: name_mod.Uncompressed,
        zone_class: types.Class,
    ) Error!Transfer {
        if (!validClass(zone_class)) return error.InvalidClass;
        @memcpy(storage.zone[0..zone.bytes.len], zone.bytes);
        return .{
            .storage = storage,
            .expected_id = expected_id,
            .zone_class = zone_class,
            .zone_len = @intCast(zone.bytes.len),
        };
    }

    /// Validate one complete DNS response and create a borrowed event cursor.
    /// The cursor must be drained before another message is opened.
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
        const first = self.phase == .awaiting_first;
        const error_response = rcode != .no_error;
        try self.validateQuestions(m, first, error_response);

        if (error_response) {
            // RFC 5936 section 2.2: an error response terminates the AXFR
            // session and does not require the closing SOA.
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
        return .{
            .transfer = self,
            .answers = try m.records(.answer),
        };
    }

    /// Mark transport EOF. A transfer without a closing SOA is incomplete.
    pub fn finish(self: *Transfer) Error!void {
        if (self.message_open) return error.MessageNotDrained;
        return switch (self.phase) {
            .complete => {},
            .failed => error.FailedTransfer,
            .awaiting_first, .body => error.PrematureEof,
        };
    }

    pub fn isComplete(self: Transfer) bool {
        return self.phase == .complete;
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
        if (q.qtype != .AXFR or q.qclass != self.zone_class) return error.QuestionMismatch;
        if (!(try q.name.eqlIgnoreCase(try self.zoneName()))) return error.QuestionMismatch;
        if (try questions.next() != null) return error.InvalidQuestionCount;
    }

    fn captureOpening(self: *Transfer, rr: message.Record) Error!void {
        if (rr.class != self.zone_class) return error.RecordClassMismatch;
        if (!(try rr.name.eqlIgnoreCase(try self.zoneName()))) return error.SoaOwnerMismatch;
        self.opening = try soa_mod.Snapshot.capture(rr, &self.storage.opening);
    }

    fn closingMatches(self: Transfer, rr: message.Record) Error!bool {
        const opening = self.opening orelse return false;
        if (rr.class != self.zone_class) return false;
        if (!(try rr.name.eqlIgnoreCase(try self.zoneName()))) return false;
        return opening.eqlRecord(&self.storage.opening, rr);
    }

    fn fail(self: *Transfer) void {
        self.phase = .failed;
        self.message_open = false;
    }
};

pub const Cursor = struct {
    transfer: *Transfer,
    answers: message.RecordIterator,
    pending_error: ?types.Rcode = null,
    finished: bool = false,

    pub fn next(self: *Cursor) Error!?Event {
        if (self.finished) return null;

        if (self.pending_error) |rcode| {
            self.pending_error = null;
            self.finished = true;
            return .{ .remote_error = rcode };
        }

        const maybe_rr = self.answers.next() catch |err| {
            self.transfer.fail();
            return err;
        };
        const rr = maybe_rr orelse {
            self.finished = true;
            self.transfer.message_open = false;
            return null;
        };

        if (self.transfer.phase == .awaiting_first) {
            if (rr.rr_type != .SOA) {
                self.transfer.fail();
                return error.FirstRecordNotSoa;
            }
            self.transfer.captureOpening(rr) catch |err| {
                self.transfer.fail();
                return err;
            };
            self.transfer.phase = .body;
            return .{ .begin = rr };
        }

        if (self.transfer.phase != .body) {
            self.transfer.fail();
            return error.FailedTransfer;
        }
        if (rr.class != self.transfer.zone_class) {
            self.transfer.fail();
            return error.RecordClassMismatch;
        }

        if (rr.rr_type == .SOA) {
            if (self.answers.remaining != 0) {
                self.transfer.fail();
                return error.UnexpectedSoa;
            }
            const same = self.transfer.closingMatches(rr) catch |err| {
                self.transfer.fail();
                return err;
            };
            if (!same) {
                self.transfer.fail();
                return error.ClosingSoaMismatch;
            }
            self.transfer.phase = .complete;
            self.transfer.message_open = false;
            self.finished = true;
            return .{ .end = rr };
        }

        return .{ .record = rr };
    }
};

/// Compose the canonical AXFR query. The returned Builder is intentionally
/// exposed so the caller can append OPT and/or TSIG in Additional.
pub fn queryBuilder(
    out: []u8,
    compression: []builder_mod.CompressionEntry,
    id: u16,
    zone: []const u8,
    zone_class: types.Class,
) Error!builder_mod.Builder {
    if (!validClass(zone_class)) return error.InvalidClass;
    var builder = try builder_mod.Builder.init(out, compression, id, .{});
    try builder.addQuestion(zone, .AXFR, zone_class);
    return builder;
}

fn validClass(class: types.Class) bool {
    return class != .ANY and class != .NONE and @intFromEnum(class) != 0;
}

fn addSoa(builder: *builder_mod.Builder, serial: u32) !void {
    try builder.addSoa(.answer, "example.com", 300, "ns1.example.com", "hostmaster.example.com", serial, 3600, 600, 86400, 300);
}

fn responseBuilder(packet: []u8, compression: []builder_mod.CompressionEntry, id: u16, with_question: bool) !builder_mod.Builder {
    var builder = try builder_mod.Builder.init(packet, compression, id, .{ .response = true, .authoritative = true });
    if (with_question) try builder.addQuestion("example.com", .AXFR, .IN);
    return builder;
}

test "AXFR query and single-message transfer stream semantic events" {
    var query_packet: [256]u8 = undefined;
    var query_compression: [8]builder_mod.CompressionEntry = undefined;
    var query = try queryBuilder(&query_packet, &query_compression, 0x1234, "example.com", .IN);
    const query_message = try message.Message.init(try query.finish());
    var questions = query_message.questions();
    const q = (try questions.next()).?;
    try std.testing.expectEqual(types.Type.AXFR, q.qtype);

    var packet: [1024]u8 = undefined;
    var compression: [32]builder_mod.CompressionEntry = undefined;
    var builder = try responseBuilder(&packet, &compression, 0x1234, true);
    try addSoa(&builder, 7);
    try builder.addA(.answer, "www.example.com", 60, .{ 192, 0, 2, 1 });
    try addSoa(&builder, 7);

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 0x1234, "example.com", .IN);
    var cursor = try transfer.openMessage(try message.Message.init(try builder.finish()));
    try std.testing.expect((try cursor.next()).? == .begin);
    const record = (try cursor.next()).?;
    try std.testing.expect(record == .record);
    try std.testing.expectEqual(types.Type.A, record.record.rr_type);
    try std.testing.expect((try cursor.next()).? == .end);
    try std.testing.expect(try cursor.next() == null);
    try transfer.finish();
    try std.testing.expect(transfer.isComplete());
}

test "AXFR accepts omitted question after first response message" {
    var first_packet: [768]u8 = undefined;
    var first_compression: [24]builder_mod.CompressionEntry = undefined;
    var first = try responseBuilder(&first_packet, &first_compression, 10, true);
    try addSoa(&first, 11);
    try first.addA(.answer, "a.example.com", 60, .{ 192, 0, 2, 1 });

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 10, "example.com", .IN);
    var first_cursor = try transfer.openMessage(try message.Message.init(try first.finish()));
    try std.testing.expect((try first_cursor.next()).? == .begin);
    try std.testing.expect((try first_cursor.next()).? == .record);
    try std.testing.expect(try first_cursor.next() == null);

    var last_packet: [768]u8 = undefined;
    var last_compression: [24]builder_mod.CompressionEntry = undefined;
    var last = try responseBuilder(&last_packet, &last_compression, 10, false);
    try last.addAAAA(.answer, "b.example.com", 60, .{0} ** 16);
    try addSoa(&last, 11);
    var last_cursor = try transfer.openMessage(try message.Message.init(try last.finish()));
    try std.testing.expect((try last_cursor.next()).? == .record);
    try std.testing.expect((try last_cursor.next()).? == .end);
    try transfer.finish();
}

test "AXFR rejects malformed SOA sequence and detects premature EOF" {
    var packet: [768]u8 = undefined;
    var compression: [24]builder_mod.CompressionEntry = undefined;
    var builder = try responseBuilder(&packet, &compression, 20, true);
    try builder.addA(.answer, "www.example.com", 60, .{ 192, 0, 2, 1 });

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 20, "example.com", .IN);
    var cursor = try transfer.openMessage(try message.Message.init(try builder.finish()));
    try std.testing.expectError(error.FirstRecordNotSoa, cursor.next());
    try std.testing.expectError(error.FailedTransfer, transfer.finish());

    var open_packet: [768]u8 = undefined;
    var open_compression: [24]builder_mod.CompressionEntry = undefined;
    var open = try responseBuilder(&open_packet, &open_compression, 21, true);
    try addSoa(&open, 1);
    var storage2: Storage = .{};
    var incomplete = try Transfer.init(&storage2, 21, "example.com", .IN);
    var open_cursor = try incomplete.openMessage(try message.Message.init(try open.finish()));
    _ = try open_cursor.next();
    _ = try open_cursor.next();
    try std.testing.expectError(error.PrematureEof, incomplete.finish());
}

test "AXFR closing SOA must be identical and last in the message" {
    var packet: [1024]u8 = undefined;
    var compression: [32]builder_mod.CompressionEntry = undefined;
    var builder = try responseBuilder(&packet, &compression, 30, true);
    try addSoa(&builder, 1);
    try addSoa(&builder, 2);

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 30, "example.com", .IN);
    var cursor = try transfer.openMessage(try message.Message.init(try builder.finish()));
    _ = try cursor.next();
    try std.testing.expectError(error.ClosingSoaMismatch, cursor.next());

    var packet2: [1024]u8 = undefined;
    var compression2: [32]builder_mod.CompressionEntry = undefined;
    var builder2 = try responseBuilder(&packet2, &compression2, 31, true);
    try addSoa(&builder2, 1);
    try addSoa(&builder2, 1);
    try builder2.addA(.answer, "after.example.com", 60, .{ 192, 0, 2, 9 });
    var storage2: Storage = .{};
    var transfer2 = try Transfer.init(&storage2, 31, "example.com", .IN);
    var cursor2 = try transfer2.openMessage(try message.Message.init(try builder2.finish()));
    _ = try cursor2.next();
    try std.testing.expectError(error.UnexpectedSoa, cursor2.next());
}

test "AXFR surfaces terminal DNS error response" {
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var builder = try builder_mod.Builder.init(&packet, &compression, 40, .{
        .response = true,
        .rcode_low = @intCast(@intFromEnum(types.Rcode.refused)),
    });
    try builder.addQuestion("example.com", .AXFR, .IN);

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 40, "example.com", .IN);
    var cursor = try transfer.openMessage(try message.Message.init(try builder.finish()));
    const event = (try cursor.next()).?;
    try std.testing.expect(event == .remote_error);
    try std.testing.expectEqual(types.Rcode.refused, event.remote_error);
    try std.testing.expect(try cursor.next() == null);
    try transfer.finish();
}

test "AXFR requires each message cursor to be drained" {
    var packet: [768]u8 = undefined;
    var compression: [24]builder_mod.CompressionEntry = undefined;
    var builder = try responseBuilder(&packet, &compression, 50, true);
    try addSoa(&builder, 1);
    try builder.addA(.answer, "a.example.com", 60, .{ 192, 0, 2, 1 });

    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 50, "example.com", .IN);
    var cursor = try transfer.openMessage(try message.Message.init(try builder.finish()));
    _ = try cursor.next();
    try std.testing.expectError(error.MessageNotDrained, transfer.openMessage(try message.Message.init(builder.out[0..builder.pos])));
}

test "AXFR composes with TCP decoder across every stream split" {
    const tcp_mod = @import("../tcp.zig");

    var first_packet: [768]u8 = undefined;
    var first_compression: [24]builder_mod.CompressionEntry = undefined;
    var first = try responseBuilder(&first_packet, &first_compression, 0x5151, true);
    try addSoa(&first, 44);
    try first.addA(.answer, "a.example.com", 60, .{ 192, 0, 2, 1 });
    const first_wire = try first.finish();

    var last_packet: [768]u8 = undefined;
    var last_compression: [24]builder_mod.CompressionEntry = undefined;
    var last = try responseBuilder(&last_packet, &last_compression, 0x5151, false);
    try last.addAAAA(.answer, "b.example.com", 60, .{0} ** 16);
    try addSoa(&last, 44);
    const last_wire = try last.finish();

    var first_frame_buf: [1024]u8 = undefined;
    const first_frame = try tcp_mod.frame(first_wire, &first_frame_buf);
    var last_frame_buf: [1024]u8 = undefined;
    const last_frame = try tcp_mod.frame(last_wire, &last_frame_buf);
    var stream: [2048]u8 = undefined;
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

    // Exercise every possible two-fragment split, including splits inside
    // both length prefixes and every DNS wire field.
    for (0..stream_wire.len + 1) |split| {
        var decoder_storage: [1024]u8 = undefined;
        var decoder = tcp_mod.Decoder.init(&decoder_storage);
        var storage: Storage = .{};
        var transfer = try Transfer.init(&storage, 0x5151, "example.com", .IN);
        var events: usize = 0;
        try Driver.consumeChunk(&decoder, &transfer, stream_wire[0..split], &events);
        try Driver.consumeChunk(&decoder, &transfer, stream_wire[split..], &events);
        try decoder.finish();
        try transfer.finish();
        try std.testing.expectEqual(@as(usize, 4), events);
    }
}

test "AXFR composes with RFC 8945 TSIG request and continuation MACs" {
    const tsig_mod = @import("../tsig.zig");
    const validate_mod = @import("../validate.zig");

    var key_name_storage: [name_mod.Name.max_wire_len]u8 = undefined;
    const key = try tsig_mod.auth.Key.init("axfr-key.example", "zone transfer shared secret", &key_name_storage);

    // Signed AXFR request: its MAC is the prefix for the first response MAC.
    var query_packet: [512]u8 = undefined;
    var query_compression: [16]builder_mod.CompressionEntry = undefined;
    var query = try queryBuilder(&query_packet, &query_compression, 0x6262, "example.com", .IN);
    var request_mac = try tsig_mod.auth.signBuilder(&query, key, .{ .time_signed = 1_700_000_000 });
    defer request_mac.deinit();
    const query_message = try message.Message.init(try query.finish());
    const query_strict = try validate_mod.messageStrict(query_message, .{});
    try tsig_mod.auth.verify(query_message, query_strict.tsig.?, key, .{ .now = 1_700_000_000 });

    var first_packet: [1024]u8 = undefined;
    var first_compression: [32]builder_mod.CompressionEntry = undefined;
    var first = try responseBuilder(&first_packet, &first_compression, 0x6262, true);
    try addSoa(&first, 51);
    try first.addA(.answer, "a.example.com", 60, .{ 192, 0, 2, 10 });
    var first_mac = try tsig_mod.auth.signBuilder(&first, key, .{
        .time_signed = 1_700_000_001,
        .request_mac = request_mac.slice(),
    });
    defer first_mac.deinit();
    const first_message = try message.Message.init(try first.finish());
    const first_strict = try validate_mod.messageStrict(first_message, .{});
    const first_tsig = first_strict.tsig.?;
    try tsig_mod.auth.verify(first_message, first_tsig, key, .{
        .now = 1_700_000_001,
        .request_mac = request_mac.slice(),
    });

    var signer_chain = try tsig_mod.auth.Chain.init(key, first_mac.slice(), 1_700_000_001);
    defer signer_chain.deinit();
    var verifier_chain = try tsig_mod.auth.Chain.init(key, first_tsig.mac, first_tsig.time_signed);
    defer verifier_chain.deinit();

    var last_packet: [1024]u8 = undefined;
    var last_compression: [32]builder_mod.CompressionEntry = undefined;
    var last = try responseBuilder(&last_packet, &last_compression, 0x6262, false);
    try last.addAAAA(.answer, "b.example.com", 60, .{0} ** 16);
    try addSoa(&last, 51);
    var last_mac = try signer_chain.signBuilder(&last, .{ .time_signed = 1_700_000_002 });
    defer last_mac.deinit();
    const last_message = try message.Message.init(try last.finish());
    const last_strict = try validate_mod.messageStrict(last_message, .{});
    try verifier_chain.verifySigned(last_message, last_strict.tsig.?, .{ .now = 1_700_000_002 });
    try std.testing.expectEqualSlices(u8, last_mac.slice(), verifier_chain.priorMac());

    // Authentication is intentionally composed outside the AXFR protocol
    // state: callers can replace TSIG with another authorization mechanism.
    var storage: Storage = .{};
    var transfer = try Transfer.init(&storage, 0x6262, "example.com", .IN);
    var first_cursor = try transfer.openMessage(first_message);
    try std.testing.expect((try first_cursor.next()).? == .begin);
    try std.testing.expect((try first_cursor.next()).? == .record);
    try std.testing.expect(try first_cursor.next() == null);
    var last_cursor = try transfer.openMessage(last_message);
    try std.testing.expect((try last_cursor.next()).? == .record);
    try std.testing.expect((try last_cursor.next()).? == .end);
    try transfer.finish();
}

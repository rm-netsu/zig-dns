const std = @import("std");
const types = @import("types.zig");
const name_mod = @import("name.zig");
const message = @import("message.zig");
const builder_mod = @import("builder.zig");

pub const Error = message.ParseError || builder_mod.Error || error{
    InvalidOpcode,
    NotRequest,
    NotResponse,
    MissingQuestion,
    UnsupportedEvent,
    MixedEvents,
    MultipleChildZones,
    InvalidClass,
    NotAuthoritative,
    InvalidFlags,
    InvalidRcode,
    QuestionMismatch,
};

/// Notification event carried in the Question QTYPE. RFC 9859 extends the
/// original RFC 1996 SOA event with delegation-maintenance CDS and CSYNC
/// events while leaving the NOTIFY envelope unchanged.
pub const Event = enum {
    soa_change,
    cds,
    csync,

    pub fn rrType(self: Event) types.Type {
        return switch (self) {
            .soa_change => .SOA,
            .cds => .CDS,
            .csync => .CSYNC,
        };
    }

    pub fn fromType(rr_type: types.Type) ?Event {
        return switch (rr_type) {
            .SOA => .soa_change,
            .CDS => .cds,
            .CSYNC => .csync,
            else => null,
        };
    }
};

/// Borrowed RFC 1996 NOTIFY view. RFC 1996 says QDCOUNT > 0 but otherwise
/// speaks about the event tuple in the singular; keep the raw question
/// iterator available instead of silently discarding additional questions.
pub const Notification = struct {
    message: message.Message,

    pub fn questions(self: Notification) message.QuestionIterator {
        return self.message.questions();
    }

    pub fn event(self: Notification) Error!Event {
        var it = self.message.questions();
        const question = (try it.next()) orelse return error.MissingQuestion;
        return Event.fromType(question.qtype) orelse error.UnsupportedEvent;
    }
};

/// Compose a canonical one-question NOTIFY request. `soa_change` is the RFC
/// 1996 section 4.5 form; `cds` and `csync` are generalized notifications from
/// RFC 9859. The returned Builder stays public so callers can append Answer
/// hints, EDNS Report-Channel, TSIG, or other transport/authentication data.
pub fn requestBuilder(
    out: []u8,
    compression: []builder_mod.CompressionEntry,
    id: u16,
    zone: []const u8,
    zone_class: types.Class,
    event: Event,
) Error!builder_mod.Builder {
    if (!validClass(zone_class)) return error.InvalidClass;
    var builder = try builder_mod.Builder.init(out, compression, id, .{
        .opcode = .notify,
        .authoritative = true,
    });
    try builder.addQuestion(zone, event.rrType(), zone_class);
    return builder;
}

/// Build the successful RFC 1996 response envelope by copying every Question
/// from the validated request. The response is otherwise empty; caller-owned
/// Builder remains available for a TSIG response when authentication is used.
pub fn responseBuilder(
    out: []u8,
    compression: []builder_mod.CompressionEntry,
    request: Notification,
) Error!builder_mod.Builder {
    _ = try validateRequest(request.message);
    var builder = try builder_mod.Builder.init(out, compression, request.message.header.id, .{
        .opcode = .notify,
        .response = true,
        .authoritative = true,
    });
    var questions = request.message.questions();
    while (try questions.next()) |question| {
        var wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const wire = try question.name.writeWire(&wire_buf);
        try builder.addQuestionWire(try name_mod.Uncompressed.init(wire), question.qtype, question.qclass);
    }
    return builder;
}

pub fn validateRequest(m: message.Message) Error!Notification {
    if (m.header.flags.opcode != .notify) return error.InvalidOpcode;
    if (m.header.flags.response) return error.NotRequest;
    if (!m.header.flags.authoritative) return error.NotAuthoritative;
    try validateEnvelopeFlags(m.header.flags, false);
    try validateQuestions(m);
    try m.validate();
    return .{ .message = m };
}

/// Validate the canonical successful NOERROR response form from RFC 1996
/// section 4.7. Error responses such as NOTIMP are ordinary DNS responses and
/// remain available through Message/Rcode rather than being misclassified as
/// successful notifications.
pub fn validateSuccessResponse(m: message.Message) Error!Notification {
    if (m.header.flags.opcode != .notify) return error.InvalidOpcode;
    if (!m.header.flags.response) return error.NotResponse;
    if (!m.header.flags.authoritative) return error.NotAuthoritative;
    try validateEnvelopeFlags(m.header.flags, true);
    try validateQuestions(m);
    try m.validate();
    return .{ .message = m };
}

/// Match the DNS-visible portion of a response to a request. Transport source
/// address and source port matching required for UDP remain caller-owned.
pub fn matches(request: Notification, response: Notification) Error!bool {
    if (request.message.header.id != response.message.header.id) return false;
    if (request.message.header.question_count != response.message.header.question_count) return false;

    var request_questions = request.message.questions();
    var response_questions = response.message.questions();
    while (try request_questions.next()) |rq| {
        const sq = (try response_questions.next()) orelse return false;
        if (rq.qtype != sq.qtype or rq.qclass != sq.qclass) return false;
        if (!(try rq.name.eqlIgnoreCase(sq.name))) return false;
    }
    return try response_questions.next() == null;
}

fn validateQuestions(m: message.Message) Error!void {
    if (m.header.question_count == 0) return error.MissingQuestion;
    var questions = m.questions();
    var first_event: ?Event = null;
    var first_generalized_name: ?name_mod.Name = null;
    var first_generalized_class: ?types.Class = null;

    while (try questions.next()) |question| {
        const event = Event.fromType(question.qtype) orelse return error.UnsupportedEvent;
        if (!validClass(question.qclass)) return error.InvalidClass;

        if (first_event) |expected| {
            if (event != expected) return error.MixedEvents;
        } else {
            first_event = event;
        }

        if (event == .soa_change) continue;
        if (first_generalized_name) |expected_name| {
            if (!(try question.name.eqlIgnoreCase(expected_name))) return error.MultipleChildZones;
            if (question.qclass != first_generalized_class.?) return error.InvalidClass;
        } else {
            first_generalized_name = question.name;
            first_generalized_class = question.qclass;
        }
    }
}

fn validClass(class: types.Class) bool {
    return class != .ANY and class != .NONE and @intFromEnum(class) != 0;
}

fn validateEnvelopeFlags(flags: types.Flags, is_response: bool) Error!void {
    // RFC 1996 section 3.2 requires fields not described by NOTIFY to be
    // binary zero. The normal SOA-change envelopes in sections 4.5/4.7 use
    // AA in both directions and QR only on the response.
    if (flags.response != is_response or !flags.authoritative) return error.InvalidFlags;
    if (flags.truncated or flags.recursion_desired or flags.recursion_available or
        flags.zero or flags.authenticated_data or flags.checking_disabled)
    {
        return error.InvalidFlags;
    }
    if (flags.rcode_low != 0) return error.InvalidRcode;
}

test "SOA NOTIFY request and response compose and match" {
    var request_bytes: [512]u8 = undefined;
    var request_compression: [16]builder_mod.CompressionEntry = undefined;
    var builder = try requestBuilder(&request_bytes, &request_compression, 0x1234, "Example.COM", .IN, .soa_change);
    const request_message = try message.Message.init(try builder.finish());
    const request = try validateRequest(request_message);
    try std.testing.expectEqual(Event.soa_change, try request.event());

    try std.testing.expectEqual(types.Opcode.notify, request_message.header.flags.opcode);
    try std.testing.expect(request_message.header.flags.authoritative);
    try std.testing.expectEqual(@as(u16, 1), request_message.header.question_count);

    var response_bytes: [512]u8 = undefined;
    var response_compression: [16]builder_mod.CompressionEntry = undefined;
    var response_builder = try responseBuilder(&response_bytes, &response_compression, request);
    const response_message = try message.Message.init(try response_builder.finish());
    const response = try validateSuccessResponse(response_message);
    try std.testing.expect(response_message.header.flags.response);
    try std.testing.expect(try matches(request, response));
}

test "NOTIFY accepts RFC 1996 multi-question SOA envelope" {
    var bytes: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var builder = try builder_mod.Builder.init(&bytes, &compression, 7, .{ .opcode = .notify, .authoritative = true });
    try builder.addQuestion("example.com", .SOA, .IN);
    try builder.addQuestion("example.net", .SOA, .IN);
    _ = try validateRequest(try message.Message.init(try builder.finish()));

    var invalid_bytes: [256]u8 = undefined;
    var invalid_compression: [8]builder_mod.CompressionEntry = undefined;
    var invalid = try builder_mod.Builder.init(&invalid_bytes, &invalid_compression, 8, .{ .opcode = .notify, .authoritative = true });
    try invalid.addQuestion("example.com", .A, .IN);
    try std.testing.expectError(error.UnsupportedEvent, validateRequest(try message.Message.init(try invalid.finish())));
}

test "NOTIFY matching detects changed ID and question" {
    var request_bytes: [256]u8 = undefined;
    var request_compression: [8]builder_mod.CompressionEntry = undefined;
    var request_builder = try requestBuilder(&request_bytes, &request_compression, 11, "example.com", .IN, .soa_change);
    const request = try validateRequest(try message.Message.init(try request_builder.finish()));

    var response_bytes: [256]u8 = undefined;
    var response_compression: [8]builder_mod.CompressionEntry = undefined;
    var response_builder = try builder_mod.Builder.init(&response_bytes, &response_compression, 12, .{ .opcode = .notify, .response = true, .authoritative = true });
    try response_builder.addQuestion("example.com", .SOA, .IN);
    const response = try validateSuccessResponse(try message.Message.init(try response_builder.finish()));
    try std.testing.expect(!(try matches(request, response)));
}

test "RFC 9859 generalized NOTIFY composes CDS and CSYNC events" {
    inline for (.{ Event.cds, Event.csync }) |event| {
        var request_bytes: [256]u8 = undefined;
        var request_compression: [8]builder_mod.CompressionEntry = undefined;
        var request_builder = try requestBuilder(&request_bytes, &request_compression, 30, "child.example", .IN, event);
        const request = try validateRequest(try message.Message.init(try request_builder.finish()));
        try std.testing.expectEqual(event, try request.event());

        var response_bytes: [256]u8 = undefined;
        var response_compression: [8]builder_mod.CompressionEntry = undefined;
        var response_builder = try responseBuilder(&response_bytes, &response_compression, request);
        const response = try validateSuccessResponse(try message.Message.init(try response_builder.finish()));
        try std.testing.expectEqual(event, try response.event());
        try std.testing.expect(try matches(request, response));
    }
}

test "RFC 9859 generalized NOTIFY rejects mixed events and child zones" {
    var mixed_bytes: [256]u8 = undefined;
    var mixed_compression: [8]builder_mod.CompressionEntry = undefined;
    var mixed = try builder_mod.Builder.init(&mixed_bytes, &mixed_compression, 31, .{ .opcode = .notify, .authoritative = true });
    try mixed.addQuestion("child.example", .CDS, .IN);
    try mixed.addQuestion("child.example", .CSYNC, .IN);
    try std.testing.expectError(error.MixedEvents, validateRequest(try message.Message.init(try mixed.finish())));

    var zones_bytes: [256]u8 = undefined;
    var zones_compression: [8]builder_mod.CompressionEntry = undefined;
    var zones = try builder_mod.Builder.init(&zones_bytes, &zones_compression, 32, .{ .opcode = .notify, .authoritative = true });
    try zones.addQuestion("one.example", .CDS, .IN);
    try zones.addQuestion("two.example", .CDS, .IN);
    try std.testing.expectError(error.MultipleChildZones, validateRequest(try message.Message.init(try zones.finish())));
}

test "NOTIFY rejects nonzero fields outside the RFC 1996 envelope" {
    var packet: [256]u8 = undefined;
    var compression: [8]builder_mod.CompressionEntry = undefined;
    var request = try builder_mod.Builder.init(&packet, &compression, 20, .{
        .opcode = .notify,
        .authoritative = true,
        .recursion_desired = true,
    });
    try request.addQuestion("example.com", .SOA, .IN);
    try std.testing.expectError(error.InvalidFlags, validateRequest(try message.Message.init(try request.finish())));

    var response_packet: [256]u8 = undefined;
    var response_compression: [8]builder_mod.CompressionEntry = undefined;
    var response = try builder_mod.Builder.init(&response_packet, &response_compression, 21, .{
        .opcode = .notify,
        .response = true,
        .authoritative = true,
        .rcode_low = 1,
    });
    try response.addQuestion("example.com", .SOA, .IN);
    try std.testing.expectError(error.InvalidRcode, validateSuccessResponse(try message.Message.init(try response.finish())));
}

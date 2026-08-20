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
    InvalidClass,
    NotAuthoritative,
    QuestionMismatch,
};

/// Borrowed RFC 1996 NOTIFY view. RFC 1996 says QDCOUNT > 0 but otherwise
/// speaks about the event tuple in the singular; keep the raw question
/// iterator available instead of silently discarding additional questions.
pub const Notification = struct {
    message: message.Message,

    pub fn questions(self: Notification) message.QuestionIterator {
        return self.message.questions();
    }
};

/// Compose the canonical SOA-change NOTIFY request from RFC 1996 section 4.5.
/// The returned Builder stays public so callers may append an optional Answer
/// hint or transport/authentication records such as TSIG.
pub fn requestBuilder(
    out: []u8,
    compression: []builder_mod.CompressionEntry,
    id: u16,
    zone: []const u8,
    zone_class: types.Class,
) Error!builder_mod.Builder {
    if (!validClass(zone_class)) return error.InvalidClass;
    var builder = try builder_mod.Builder.init(out, compression, id, .{
        .opcode = .notify,
        .authoritative = true,
    });
    try builder.addQuestion(zone, .SOA, zone_class);
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
    try validateQuestions(m);
    try m.validate();
    return .{ .message = m };
}

pub fn validateResponse(m: message.Message) Error!Notification {
    if (m.header.flags.opcode != .notify) return error.InvalidOpcode;
    if (!m.header.flags.response) return error.NotResponse;
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
    while (try questions.next()) |question| {
        if (question.qtype != .SOA) return error.UnsupportedEvent;
        if (!validClass(question.qclass)) return error.InvalidClass;
    }
}

fn validClass(class: types.Class) bool {
    return class != .ANY and class != .NONE and @intFromEnum(class) != 0;
}

test "NOTIFY request and response compose and match" {
    var request_bytes: [512]u8 = undefined;
    var request_compression: [16]builder_mod.CompressionEntry = undefined;
    var builder = try requestBuilder(&request_bytes, &request_compression, 0x1234, "Example.COM", .IN);
    const request_message = try message.Message.init(try builder.finish());
    const request = try validateRequest(request_message);

    try std.testing.expectEqual(types.Opcode.notify, request_message.header.flags.opcode);
    try std.testing.expect(request_message.header.flags.authoritative);
    try std.testing.expectEqual(@as(u16, 1), request_message.header.question_count);

    var response_bytes: [512]u8 = undefined;
    var response_compression: [16]builder_mod.CompressionEntry = undefined;
    var response_builder = try responseBuilder(&response_bytes, &response_compression, request);
    const response_message = try message.Message.init(try response_builder.finish());
    const response = try validateResponse(response_message);
    try std.testing.expect(response_message.header.flags.response);
    try std.testing.expect(try matches(request, response));
}

test "NOTIFY accepts RFC 1996 multi-question envelope but only SOA events" {
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
    var request_builder = try requestBuilder(&request_bytes, &request_compression, 11, "example.com", .IN);
    const request = try validateRequest(try message.Message.init(try request_builder.finish()));

    var response_bytes: [256]u8 = undefined;
    var response_compression: [8]builder_mod.CompressionEntry = undefined;
    var response_builder = try builder_mod.Builder.init(&response_bytes, &response_compression, 12, .{ .opcode = .notify, .response = true, .authoritative = true });
    try response_builder.addQuestion("example.com", .SOA, .IN);
    const response = try validateResponse(try message.Message.init(try response_builder.finish()));
    try std.testing.expect(!(try matches(request, response)));
}

const types = @import("types.zig");
const name_mod = @import("name.zig");
const message = @import("message.zig");

pub const Error = message.ParseError || error{ NotResponse, IdMismatch, OpcodeMismatch, QuestionMismatch, NoQuestion };

pub const QuestionKey = struct { name: []const u8, qtype: types.Type, qclass: types.Class = .IN };
pub const WireQuestionKey = struct { name: name_mod.Uncompressed, qtype: types.Type, qclass: types.Class = .IN };

pub fn validateResponse(expected_id: u16, expected: QuestionKey, bytes: []const u8) Error!message.Message {
    const m = try message.Message.init(bytes);
    try validateEnvelope(expected_id, m);
    var q = m.questions();
    const first = (try q.next()) orelse return error.NoQuestion;
    if (first.qtype != expected.qtype or first.qclass != expected.qclass) return error.QuestionMismatch;
    if (!(try first.name.eqlPresentationIgnoreCase(expected.name))) return error.QuestionMismatch;
    return m;
}

/// Wire-name form of `validateResponse`, suitable for arbitrary-octet labels.
/// The expected name is caller-owned and remains allocation-free.
pub fn validateResponseWire(expected_id: u16, expected: WireQuestionKey, bytes: []const u8) Error!message.Message {
    const m = try message.Message.init(bytes);
    try validateEnvelope(expected_id, m);
    var q = m.questions();
    const first = (try q.next()) orelse return error.NoQuestion;
    if (first.qtype != expected.qtype or first.qclass != expected.qclass) return error.QuestionMismatch;
    const expected_name = try name_mod.Name.init(expected.name.bytes, 0);
    if (!(try first.name.eqlIgnoreCase(expected_name))) return error.QuestionMismatch;
    return m;
}

fn validateEnvelope(expected_id: u16, m: message.Message) Error!void {
    if (!m.header.flags.response) return error.NotResponse;
    if (m.header.id != expected_id) return error.IdMismatch;
    if (m.header.flags.opcode != .query) return error.OpcodeMismatch;
    if (m.header.question_count != 1) return error.QuestionMismatch;
}

test "wire response validation accepts arbitrary label octets" {
    const std = @import("std");
    const builder = @import("builder.zig");

    const wire_name = [_]u8{ 3, 'a', 0, 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    const expected_name = try name_mod.Uncompressed.init(&wire_name);

    var packet: [256]u8 = undefined;
    var compression: [8]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 0x1234, .{ .response = true });
    try b.addQuestionWire(expected_name, .AAAA, .IN);
    const bytes = try b.finish();

    _ = try validateResponseWire(0x1234, .{ .name = expected_name, .qtype = .AAAA }, bytes);
    try std.testing.expectError(error.IdMismatch, validateResponseWire(0x1235, .{ .name = expected_name, .qtype = .AAAA }, bytes));
}

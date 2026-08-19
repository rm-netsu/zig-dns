const types = @import("types.zig");
const message = @import("message.zig");

pub const Error = message.ParseError || error{ NotResponse, IdMismatch, OpcodeMismatch, QuestionMismatch, NoQuestion };

pub const QuestionKey = struct { name: []const u8, qtype: types.Type, qclass: types.Class = .IN };

pub fn validateResponse(expected_id: u16, expected: QuestionKey, bytes: []const u8) Error!message.Message {
    const m = try message.Message.init(bytes);
    if (!m.header.flags.response) return error.NotResponse;
    if (m.header.id != expected_id) return error.IdMismatch;
    if (m.header.flags.opcode != .query) return error.OpcodeMismatch;
    if (m.header.question_count != 1) return error.QuestionMismatch;
    var q = m.questions();
    const first = (try q.next()) orelse return error.NoQuestion;
    if (first.qtype != expected.qtype or first.qclass != expected.qclass) return error.QuestionMismatch;
    if (!(try first.name.eqlPresentationIgnoreCase(expected.name))) return error.QuestionMismatch;
    return m;
}

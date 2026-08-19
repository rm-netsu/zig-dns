const message = @import("message.zig");
pub const tcp = @import("tcp.zig");

pub const alpn = "doq";
pub const default_port: u16 = 853;
pub const required_message_id: u16 = 0;
pub const max_message_size: usize = 65535;

pub const Error = message.ParseError || tcp.Error || error{ InvalidMessageId, ExpectedQuery, ExpectedResponse, ExtraMessage, UnexpectedEof };

pub fn validateQuery(bytes: []const u8) Error!message.Message {
    const m = try message.Message.init(bytes);
    if (m.header.id != 0) return error.InvalidMessageId;
    if (m.header.flags.response) return error.ExpectedQuery;
    return m;
}

pub fn validateResponse(bytes: []const u8) Error!message.Message {
    const m = try message.Message.init(bytes);
    if (m.header.id != 0) return error.InvalidMessageId;
    if (!m.header.flags.response) return error.ExpectedResponse;
    return m;
}

pub const StreamKind = enum { query, response };

pub const StreamDecoder = struct {
    inner: tcp.Decoder,
    kind: StreamKind,
    done: bool = false,

    pub const Feed = struct { consumed: usize, message: ?message.Message = null };

    pub fn init(storage: []u8, kind: StreamKind) StreamDecoder {
        return .{ .inner = tcp.Decoder.init(storage), .kind = kind };
    }

    pub fn feed(self: *StreamDecoder, input: []const u8) Error!Feed {
        if (self.done) {
            if (input.len != 0) return error.ExtraMessage;
            return .{ .consumed = 0 };
        }
        const got = try self.inner.feed(input);
        switch (got.event) {
            .need_more => return .{ .consumed = got.consumed },
            .message => |wire| {
                const parsed = switch (self.kind) {
                    .query => try validateQuery(wire),
                    .response => try validateResponse(wire),
                };
                self.done = true;
                return .{ .consumed = got.consumed, .message = parsed };
            },
        }
    }

    pub fn finish(self: *const StreamDecoder) Error!void {
        if (!self.done) return error.UnexpectedEof;
        try self.inner.finish();
    }
};

test "DoQ stream accepts exactly one zero-ID framed query" {
    const std = @import("std");
    const builder = @import("builder.zig");
    var packet: [128]u8 = undefined;
    var entries: [8]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &entries, 0, .{});
    try b.addQuestion("example.com", .A, .IN);
    const query = try b.finish();
    var framed: [130]u8 = undefined;
    const wire = try tcp.frame(query, &framed);
    var storage: [128]u8 = undefined;
    var decoder = StreamDecoder.init(&storage, .query);
    const got = try decoder.feed(wire);
    try std.testing.expect(got.message != null);
    try decoder.finish();
    try std.testing.expectError(error.ExtraMessage, decoder.feed(&.{ 0, 0 }));
}

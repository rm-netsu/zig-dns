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

/// Expected DNS message cardinality for one DoQ bidirectional stream.
///
/// RFC 9250 maps one query to one QUIC stream. Ordinary DNS transactions
/// have one response message, while zone transfers may return multiple
/// length-prefixed response messages before the server sends STREAM FIN.
pub const StreamMode = enum {
    query,
    single_response,
    multi_response,
};

pub const StreamDecoder = struct {
    inner: tcp.Decoder,
    mode: StreamMode,
    message_count: usize = 0,
    finished: bool = false,

    pub const Feed = struct { consumed: usize, message: ?message.Message = null };

    pub fn init(storage: []u8, mode: StreamMode) StreamDecoder {
        return .{ .inner = tcp.Decoder.init(storage), .mode = mode };
    }

    pub fn feed(self: *StreamDecoder, input: []const u8) Error!Feed {
        if (self.finished) {
            if (input.len != 0) return error.ExtraMessage;
            return .{ .consumed = 0 };
        }
        if (self.messageLimitReached()) {
            if (input.len != 0) return error.ExtraMessage;
            return .{ .consumed = 0 };
        }
        const got = try self.inner.feed(input);
        switch (got.event) {
            .need_more => return .{ .consumed = got.consumed },
            .message => |wire| {
                const parsed = switch (self.mode) {
                    .query => try validateQuery(wire),
                    .single_response, .multi_response => try validateResponse(wire),
                };
                self.message_count += 1;
                if (self.messageLimitReached() and got.consumed != input.len) return error.ExtraMessage;
                return .{ .consumed = got.consumed, .message = parsed };
            },
        }
    }

    /// Mark receipt of STREAM FIN. A partial length-prefixed message or an
    /// empty stream is a protocol error. For `.multi_response`, semantic
    /// completion (for example, the closing AXFR SOA) remains the caller's
    /// responsibility.
    pub fn finish(self: *StreamDecoder) Error!void {
        if (self.finished) return;
        try self.inner.finish();
        if (self.message_count == 0) return error.UnexpectedEof;
        self.finished = true;
    }

    pub fn messageCount(self: *const StreamDecoder) usize {
        return self.message_count;
    }

    fn messageLimitReached(self: *const StreamDecoder) bool {
        return switch (self.mode) {
            .query, .single_response => self.message_count != 0,
            .multi_response => false,
        };
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

test "DoQ single response rejects a second framed message" {
    const std = @import("std");
    const builder = @import("builder.zig");

    var packet: [128]u8 = undefined;
    var entries: [8]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &entries, 0, .{ .response = true });
    try b.addQuestion("example.com", .A, .IN);
    const response = try b.finish();

    var framed: [130]u8 = undefined;
    const wire = try tcp.frame(response, &framed);
    var storage: [128]u8 = undefined;
    var decoder = StreamDecoder.init(&storage, .single_response);
    const got = try decoder.feed(wire);
    try std.testing.expect(got.message != null);
    try std.testing.expectEqual(@as(usize, 1), decoder.messageCount());
    try std.testing.expectError(error.ExtraMessage, decoder.feed(wire));
    try decoder.finish();
}

test "DoQ multi response accepts fragmented zone-transfer stream" {
    const std = @import("std");
    const builder = @import("builder.zig");

    var first_packet: [128]u8 = undefined;
    var first_entries: [8]builder.CompressionEntry = undefined;
    var first = try builder.Builder.init(&first_packet, &first_entries, 0, .{ .response = true });
    try first.addQuestion("example.com", .AXFR, .IN);
    const first_wire = try first.finish();

    var second_packet: [128]u8 = undefined;
    var second_entries: [8]builder.CompressionEntry = undefined;
    var second = try builder.Builder.init(&second_packet, &second_entries, 0, .{ .response = true });
    const second_wire = try second.finish();

    var first_frame_buf: [130]u8 = undefined;
    const first_frame = try tcp.frame(first_wire, &first_frame_buf);
    var second_frame_buf: [130]u8 = undefined;
    const second_frame = try tcp.frame(second_wire, &second_frame_buf);
    var stream: [260]u8 = undefined;
    @memcpy(stream[0..first_frame.len], first_frame);
    @memcpy(stream[first_frame.len..][0..second_frame.len], second_frame);
    const wire = stream[0 .. first_frame.len + second_frame.len];

    for (0..wire.len + 1) |split| {
        var storage: [128]u8 = undefined;
        var decoder = StreamDecoder.init(&storage, .multi_response);
        var messages: usize = 0;

        const Driver = struct {
            fn feedAll(d: *StreamDecoder, chunk: []const u8, count: *usize) !void {
                var offset: usize = 0;
                while (offset < chunk.len) {
                    const got = try d.feed(chunk[offset..]);
                    if (got.consumed == 0) return error.TestUnexpectedResult;
                    offset += got.consumed;
                    if (got.message != null) count.* += 1;
                }
            }
        };

        try Driver.feedAll(&decoder, wire[0..split], &messages);
        try Driver.feedAll(&decoder, wire[split..], &messages);
        try decoder.finish();
        try std.testing.expectEqual(@as(usize, 2), messages);
        try std.testing.expectEqual(@as(usize, 2), decoder.messageCount());
    }
}

test "DoQ stream FIN rejects partial response framing" {
    const std = @import("std");
    var storage: [32]u8 = undefined;
    var decoder = StreamDecoder.init(&storage, .multi_response);
    _ = try decoder.feed(&.{ 0, 12, 0, 0 });
    try std.testing.expectError(error.UnexpectedEof, decoder.finish());
}

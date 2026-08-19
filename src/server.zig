const types = @import("types.zig");
const message = @import("message.zig");
const builder = @import("builder.zig");
const edns = @import("edns.zig");

pub const Error = message.ParseError || builder.Error || error{ ExpectedQuery, ExtendedRcodeRequiresOpt };

pub const Options = struct {
    authoritative: bool = false,
    recursion_available: bool = false,
    rcode: types.Rcode = .no_error,
};

pub fn beginResponse(out: []u8, compression: []builder.CompressionEntry, query: message.Message, options: Options) Error!builder.Builder {
    if (query.header.flags.response) return error.ExpectedQuery;
    const code: u12 = @intFromEnum(options.rcode);
    if (code > 15) return error.ExtendedRcodeRequiresOpt;
    var flags: types.Flags = .{
        .response = true,
        .opcode = query.header.flags.opcode,
        .authoritative = options.authoritative,
        .recursion_desired = query.header.flags.recursion_desired,
        .recursion_available = options.recursion_available,
        .checking_disabled = query.header.flags.checking_disabled,
        .rcode_low = @truncate(code),
    };
    _ = &flags;
    var b = try builder.Builder.init(out, compression, query.header.id, flags);
    var questions = query.questions();
    var name_buf: [255]u8 = undefined;
    while (try questions.next()) |q| {
        const wire = try q.name.writeWire(&name_buf);
        try b.addQuestionWire(try @import("name.zig").Uncompressed.init(wire), q.qtype, q.qclass);
    }
    return b;
}

pub fn extendedRcodeHigh(rcode: types.Rcode) u8 {
    return @truncate(@as(u12, @intFromEnum(rcode)) >> 4);
}

pub fn addResponseOpt(b: *builder.Builder, rcode: types.Rcode, udp_payload_size: u16, version: u8, flags: edns.Flags, options: []const u8) builder.Error!void {
    try b.addOpt(udp_payload_size, extendedRcodeHigh(rcode), version, flags, options);
}

test "extended rcode cannot be silently truncated" {
    const Builder = @import("builder.zig");
    var query_buf: [128]u8 = undefined;
    var query_compression: [8]Builder.CompressionEntry = undefined;
    var q = try Builder.Builder.init(&query_buf, &query_compression, 1, .{});
    try q.addQuestion("example.com", .A, .IN);
    const query = try message.Message.init(try q.finish());
    var out: [128]u8 = undefined;
    var compression: [8]Builder.CompressionEntry = undefined;
    try @import("std").testing.expectError(error.ExtendedRcodeRequiresOpt, beginResponse(&out, &compression, query, .{ .rcode = .bad_version_or_signature }));
    try @import("std").testing.expectEqual(@as(u8, 1), extendedRcodeHigh(.bad_version_or_signature));
}

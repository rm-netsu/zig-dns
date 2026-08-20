const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    var packet: [1232]u8 = undefined;
    var compression: [48]dns.CompressionEntry = undefined;
    var update = try dns.update.Composer.init(&packet, &compression, 0x4d21, "example.com", .IN);

    // Require the name to exist, but AAAA to be absent, then atomically add A
    // and remove the old TXT RRset. The Composer supplies RFC 2136's overloaded
    // CLASS/TTL/RDLENGTH values; callers express the operation semantically.
    try update.requireNameExists("host.example.com");
    try update.requireRrsetNotExists("host.example.com", .AAAA);
    try update.addA("host.example.com", 300, .{ 192, 0, 2, 42 });
    try update.deleteRrset("host.example.com", .TXT);

    var key_name_buf: [64]u8 = undefined;
    const key = try dns.tsig.auth.Key.init(
        "update-key.example",
        "replace with caller-owned secret",
        &key_name_buf,
    );
    var mac = try dns.tsig.auth.signBuilder(&update.builder, key, .{ .time_signed = 1_800_000_000 });
    defer mac.deinit();

    const wire = try update.finish();
    const parsed = try dns.Message.init(wire);
    _ = try dns.update.validateRequest(parsed);
    const strict = try dns.validate.messageStrict(parsed, .{});
    const tsig = strict.tsig orelse return error.MissingTsig;
    try dns.tsig.auth.verify(parsed, tsig, key, .{ .now = 1_800_000_000 });

    std.debug.print("signed UPDATE: {d} bytes, {d} prerequisite(s), {d} update(s), TSIG MAC {d} bytes\n", .{
        wire.len,
        parsed.header.answer_count,
        parsed.header.authority_count,
        mac.slice().len,
    });
}

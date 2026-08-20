const std = @import("std");
const dns = @import("dns");

fn wireName(presentation: []const u8, out: []u8) !dns.name.Uncompressed {
    return dns.name.Uncompressed.init(try dns.name.writePresentationWire(presentation, out));
}

pub fn main() !void {
    var packet: [1232]u8 = undefined;
    var compression: [48]dns.CompressionEntry = undefined;
    var update = try dns.update.Composer.init(&packet, &compression, 0x4d21, "example.com", .IN);
    try update.requireNameExists("host.example.com");
    try update.requireRrsetNotExists("host.example.com", .AAAA);
    try update.requireA("host.example.com", .{ 192, 0, 2, 1 });
    try update.addA("host.example.com", 300, .{ 192, 0, 2, 42 });
    try update.deleteRrset("host.example.com", .TXT);
    try update.deleteA("stale.example.com", .{ 192, 0, 2, 99 });

    var key_name_buf: [64]u8 = undefined;
    const key: dns.tsig.auth.Key = .{
        .name = try wireName("update-key.example", &key_name_buf),
        .secret = "interop update secret",
    };
    var mac = try dns.tsig.auth.signBuilder(&update.builder, key, .{ .time_signed = 1_800_000_000 });
    defer mac.deinit();

    for (try update.finish()) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
}

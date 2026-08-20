const std = @import("std");
const dns = @import("dns");

fn printHex(label: []const u8, bytes: []const u8) void {
    std.debug.print("{s}=", .{label});
    for (bytes) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
}

pub fn main() !void {
    var key_name_buf: [64]u8 = undefined;
    const key = try dns.tsig.auth.Key.init("key.example", "shared secret bytes", &key_name_buf);

    var request_buf: [512]u8 = undefined;
    var request_compression: [16]dns.CompressionEntry = undefined;
    var request = try dns.Builder.init(&request_buf, &request_compression, 0x1234, .{ .recursion_desired = true });
    try request.addQuestion("example.com", .A, .IN);
    var request_mac = try dns.tsig.auth.signBuilder(&request, key, .{ .time_signed = 1_700_000_000 });
    defer request_mac.deinit();
    printHex("request", try request.finish());

    var response_buf: [512]u8 = undefined;
    var response_compression: [16]dns.CompressionEntry = undefined;
    var response = try dns.Builder.init(&response_buf, &response_compression, 0x1234, .{
        .response = true,
        .recursion_desired = true,
    });
    try response.addQuestion("example.com", .A, .IN);
    try response.addA(.answer, "example.com", 60, .{ 1, 2, 3, 4 });
    var response_mac = try dns.tsig.auth.signBuilder(&response, key, .{
        .time_signed = 1_700_000_001,
        .request_mac = request_mac.slice(),
    });
    defer response_mac.deinit();
    printHex("response", try response.finish());

    var chain = try dns.tsig.auth.Chain.init(key, response_mac.slice(), 1_700_000_001);
    defer chain.deinit();
    var continuation_buf: [512]u8 = undefined;
    var continuation_compression: [16]dns.CompressionEntry = undefined;
    var continuation = try dns.Builder.init(&continuation_buf, &continuation_compression, 0x1234, .{ .response = true });
    try continuation.addA(.answer, "next.example.com", 60, .{ 5, 6, 7, 8 });
    var continuation_mac = try chain.signBuilder(&continuation, .{ .time_signed = 1_700_000_002 });
    defer continuation_mac.deinit();
    printHex("continuation", try continuation.finish());
}

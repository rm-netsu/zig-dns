const std = @import("std");
const dns = @import("dns");

const iterations = 200_000;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var axfr_packet: [1536]u8 = undefined;
    var axfr_compression: [48]dns.CompressionEntry = undefined;
    const axfr_wire = try buildAxfr(&axfr_packet, &axfr_compression);

    var ixfr_packet: [1536]u8 = undefined;
    var ixfr_compression: [48]dns.CompressionEntry = undefined;
    const ixfr_wire = try buildIxfr(&ixfr_packet, &ixfr_compression);

    try benchAxfr(io, axfr_wire);
    try benchIxfr(io, ixfr_wire);

    std.debug.print(
        "transfer.state: AXFR Storage={d} B Transfer={d} B; IXFR Storage={d} B Transfer={d} B\n",
        .{
            @sizeOf(dns.transfer.axfr.Storage),
            @sizeOf(dns.transfer.axfr.Transfer),
            @sizeOf(dns.transfer.ixfr.Storage),
            @sizeOf(dns.transfer.ixfr.Transfer),
        },
    );
}

fn buildAxfr(packet: []u8, compression: []dns.CompressionEntry) ![]const u8 {
    var b = try dns.Builder.init(packet, compression, 0x5151, .{ .response = true, .authoritative = true });
    try b.addQuestion("example.com", .AXFR, .IN);
    try addSoa(&b, 7);
    try b.addA(.answer, "a.example.com", 300, .{ 192, 0, 2, 1 });
    try b.addAAAA(.answer, "b.example.com", 300, .{0} ** 16);
    try b.addNameRecord(.answer, "example.com", .NS, 300, "ns1.example.com");
    try b.addA(.answer, "ns1.example.com", 300, .{ 192, 0, 2, 53 });
    try addSoa(&b, 7);
    return b.finish();
}

fn buildIxfr(packet: []u8, compression: []dns.CompressionEntry) ![]const u8 {
    var b = try dns.Builder.init(packet, compression, 0x6161, .{ .response = true, .authoritative = true });
    try b.addQuestion("example.com", .IXFR, .IN);
    try addSoa(&b, 3);
    try addSoa(&b, 1);
    try b.addA(.answer, "old.example.com", 300, .{ 192, 0, 2, 1 });
    try addSoa(&b, 3);
    try b.addA(.answer, "new.example.com", 300, .{ 192, 0, 2, 3 });
    try addSoa(&b, 3);
    return b.finish();
}

fn addSoa(b: *dns.Builder, serial: u32) !void {
    try b.addSoa(
        .answer,
        "example.com",
        300,
        "ns1.example.com",
        "hostmaster.example.com",
        serial,
        3600,
        600,
        86400,
        300,
    );
}

fn benchAxfr(io: std.Io, wire: []const u8) !void {
    const parsed = try dns.Message.init(wire);
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..iterations) |_| {
        var storage: dns.transfer.axfr.Storage = .{};
        var transfer = try dns.transfer.axfr.Transfer.init(&storage, 0x5151, "example.com", .IN);
        var cursor = try transfer.openMessage(parsed);
        while (try cursor.next()) |_| checksum +%= 1;
        try transfer.finish();
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("transfer.axfr_message", iterations, elapsed);
}

fn benchIxfr(io: std.Io, wire: []const u8) !void {
    const parsed = try dns.Message.init(wire);
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..iterations) |_| {
        var storage: dns.transfer.ixfr.Storage = .{};
        var transfer = try dns.transfer.ixfr.Transfer.init(&storage, 0x6161, "example.com", .IN, 1);
        var cursor = try transfer.openMessage(parsed);
        while (try cursor.next()) |_| checksum +%= 1;
        try transfer.finish();
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("transfer.ixfr_delta", iterations, elapsed);
}

fn report(name: []const u8, count: usize, elapsed_ns: i96) void {
    const elapsed: u64 = @intCast(elapsed_ns);
    const ns_per_op = elapsed / count;
    const ops_per_s = @as(u64, @intCast(count)) * std.time.ns_per_s / @max(elapsed, 1);
    std.debug.print("{s}: {d} ns/op, {d} ops/s ({d} iterations)\n", .{ name, ns_per_op, ops_per_s, count });
}

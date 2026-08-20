const std = @import("std");
const dns = @import("dns");

const parse_iterations = 1_000_000;
const name_iterations = 1_000_000;
const build_iterations = 250_000;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var packet_storage: [512]u8 = undefined;
    var compression: [32]dns.CompressionEntry = undefined;
    var b = try dns.Builder.init(&packet_storage, &compression, 0x1234, .{ .response = true, .recursion_desired = true });
    try b.addQuestion("www.example.com", .A, .IN);
    try b.addA(.answer, "www.example.com", 300, .{ 192, 0, 2, 1 });
    try b.addAAAA(.answer, "www.example.com", 300, .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{1});
    try b.addNameRecord(.authority, "example.com", .NS, 300, "ns1.example.com");
    const packet = try b.finish();

    try benchParse(io, packet);
    try benchName(io, packet);
    try benchBuild(io);
}

fn benchParse(io: std.Io, packet: []const u8) !void {
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..parse_iterations) |_| {
        const m = try dns.Message.init(packet);
        var questions = m.questions();
        while (try questions.next()) |q| checksum +%= @intFromEnum(q.qtype);
        var answers = try m.records(.answer);
        while (try answers.next()) |rr| checksum +%= rr.rdata.len;
        var authority = try m.records(.authority);
        while (try authority.next()) |rr| checksum +%= rr.rdata.len;
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("core.parse_message", parse_iterations, elapsed);
}

fn benchName(io: std.Io, packet: []const u8) !void {
    const m = try dns.Message.init(packet);
    var answers = try m.records(.answer);
    const rr = (try answers.next()).?;
    var out: [dns.name.Name.max_wire_len]u8 = undefined;

    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..name_iterations) |_| {
        const wire = try rr.name.writeWire(&out);
        checksum +%= wire.len + wire[wire.len - 1];
        std.mem.doNotOptimizeAway(out);
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("core.decompress_name", name_iterations, elapsed);
}

fn benchBuild(io: std.Io) !void {
    var packet: [512]u8 = undefined;
    var compression: [32]dns.CompressionEntry = undefined;

    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..build_iterations) |i| {
        var b = try dns.Builder.init(&packet, &compression, @truncate(i), .{ .response = true, .recursion_desired = true });
        try b.addQuestion("www.example.com", .A, .IN);
        try b.addA(.answer, "www.example.com", 300, .{ 192, 0, 2, 1 });
        try b.addAAAA(.answer, "www.example.com", 300, .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 11 ++ .{1});
        try b.addNameRecord(.authority, "example.com", .NS, 300, "ns1.example.com");
        const wire = try b.finish();
        checksum +%= wire.len + wire[wire.len - 1];
        std.mem.doNotOptimizeAway(packet);
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("core.build_response", build_iterations, elapsed);
}

fn report(name: []const u8, iterations: usize, elapsed_ns: i96) void {
    const elapsed: u64 = @intCast(elapsed_ns);
    const ns_per_op = elapsed / iterations;
    const ops_per_s = @as(u64, @intCast(iterations)) * std.time.ns_per_s / @max(elapsed, 1);
    std.debug.print("{s}: {d} ns/op, {d} ops/s ({d} iterations)\n", .{ name, ns_per_op, ops_per_s, iterations });
}

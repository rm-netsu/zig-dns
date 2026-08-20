const std = @import("std");
const dns = @import("dns");
const corpus = @import("real_corpus.zig");

const R = dns.high_level.Resolver(.{});
const direct_rounds = 80_000;
const alias_rounds = 45_000;
const fallback_rounds = 55_000;
const cache_rounds = 140_000;

const AlwaysHit = struct {
    hits: usize = 0,

    fn lookup(ctx: *anyopaque, _: dns.client.WireQuestionKey, _: u64) ?dns.high_level.CacheHit {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.hits +%= 1;
        return .{ .kind = .answer, .security = .secure, .token = 7 };
    }
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    std.debug.print("high_level.storage: {d} bytes ({d} bytes/query at max_queries={d})\n", .{
        @sizeOf(R.Storage),
        @sizeOf(R.Storage) / 64,
        64,
    });
    std.debug.print("high_level.resolver: {d} bytes\n", .{@sizeOf(R)});

    try benchDirect(io);
    try benchAlias(io);
    try benchFallback(io);
    try benchCacheHit(io);
}

fn benchDirect(io: std.Io) !void {
    var storage: R.Storage = undefined;
    var resolver = R.initInPlace(&storage);
    var packet: [corpus.cases[0].wire.len]u8 = undefined;

    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..direct_rounds) |_| {
        const first = try resolver.beginPresentation(.{ .name = "cloudflare.com", .qtype = .A }, .{ .server_count = 2 });
        const d = dispatchFrom(first).?;
        @memcpy(&packet, corpus.cases[0].wire);
        setId(&packet, d.id);
        const completed = try resolver.onResponse(d.handle, &packet);
        const c = switch (completed) {
            .complete => |value| value,
            else => return error.UnexpectedAction,
        };
        checksum +%= c.handle.generation + c.server_index;
        try resolver.release(c.handle);
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("high_level.direct_real_answer", direct_rounds, elapsed);
}

fn benchAlias(io: std.Io) !void {
    var storage: R.Storage = undefined;
    var resolver = R.initInPlace(&storage);
    var packet: [corpus.cases[4].wire.len]u8 = undefined;

    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..alias_rounds) |_| {
        const first = try resolver.beginPresentation(.{ .name = "status.openai.com", .qtype = .A }, .{});
        const d = dispatchFrom(first).?;
        @memcpy(&packet, corpus.cases[4].wire);
        setId(&packet, d.id);
        const completed = try resolver.onResponse(d.handle, &packet);
        const c = switch (completed) {
            .complete => |value| value,
            else => return error.UnexpectedAction,
        };
        checksum +%= c.handle.generation + d.id;
        try resolver.release(c.handle);
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("high_level.real_cname_in_packet", alias_rounds, elapsed);
}

fn benchFallback(io: std.Io) !void {
    var storage: R.Storage = undefined;
    var resolver = R.initInPlace(&storage);
    var truncated_template: [256]u8 = undefined;
    var compression: [12]dns.CompressionEntry = undefined;
    var b = try dns.Builder.init(&truncated_template, &compression, 0, .{ .response = true, .truncated = true });
    try b.addQuestion("cloudflare.com", .A, .IN);
    const truncated_len = (try b.finish()).len;
    var answer: [corpus.cases[0].wire.len]u8 = undefined;

    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..fallback_rounds) |_| {
        const first = try resolver.beginPresentation(.{ .name = "cloudflare.com", .qtype = .A }, .{});
        const udp = dispatchFrom(first).?;
        setId(truncated_template[0..truncated_len], udp.id);
        const fallback = try resolver.onResponse(udp.handle, truncated_template[0..truncated_len]);
        const tcp = switch (fallback) {
            .connect_tcp => |value| value,
            else => return error.UnexpectedAction,
        };

        @memcpy(&answer, corpus.cases[0].wire);
        setId(&answer, tcp.id);
        const completed = try resolver.onResponse(tcp.handle, &answer);
        const c = switch (completed) {
            .complete => |value| value,
            else => return error.UnexpectedAction,
        };
        checksum +%= tcp.id + c.handle.generation;
        try resolver.release(c.handle);
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("high_level.udp_tcp_fallback_real_answer", fallback_rounds, elapsed);
}

fn benchCacheHit(io: std.Io) !void {
    var storage: R.Storage = undefined;
    var cache_ctx: AlwaysHit = .{};
    var resolver = R.initInPlaceWithCache(&storage, .{
        .context = &cache_ctx,
        .lookup = AlwaysHit.lookup,
    });

    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..cache_rounds) |_| {
        const action = try resolver.beginPresentation(.{ .name = "cloudflare.com", .qtype = .A }, .{ .now = 42 });
        const c = switch (action) {
            .complete => |value| value,
            else => return error.UnexpectedAction,
        };
        checksum +%= c.cache_token.? + c.handle.generation;
        try resolver.release(c.handle);
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum +% cache_ctx.hits);
    report("high_level.cache_hit", cache_rounds, elapsed);
}

fn dispatchFrom(action: dns.high_level.Action) ?dns.high_level.Dispatch {
    return switch (action) {
        .send => |d| d,
        .retry => |d| d,
        .connect_tcp => |d| d,
        .connect_dot => |d| d,
        .open_doq_stream => |d| d,
        .perform_doh => |d| d,
        else => null,
    };
}

fn setId(packet: []u8, id: u16) void {
    packet[0] = @intCast(id >> 8);
    packet[1] = @intCast(id & 0xff);
}

fn report(label: []const u8, operations: usize, elapsed_ns: i128) void {
    const elapsed: f64 = @floatFromInt(elapsed_ns);
    const ops: f64 = @floatFromInt(operations);
    std.debug.print("{s}: {d:.2} ns/op, {d:.3} Mops/s\n", .{
        label,
        elapsed / ops,
        ops * 1_000.0 / elapsed,
    });
}

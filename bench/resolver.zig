const std = @import("std");
const dns = @import("dns");
const corpus = @import("real_corpus.zig");

const classify_rounds = 120_000;
const referral_rounds = 2_000;
const cache_rounds = 180_000;
const alias_rounds = 180_000;

const queries = [_]dns.client.QuestionKey{
    .{ .name = "cloudflare.com", .qtype = .A },
    .{ .name = "cloudflare.com", .qtype = .AAAA },
    .{ .name = "cloudflare.com", .qtype = .NS },
    .{ .name = "cloudflare.com", .qtype = .CAA },
    .{ .name = "status.openai.com", .qtype = .A },
    .{ .name = "gmail.com", .qtype = .MX },
    .{ .name = "chatgpt.com", .qtype = .TXT },
    .{ .name = "dns.google", .qtype = .TXT },
    .{ .name = "example.com", .qtype = .DS },
    .{ .name = "example.com", .qtype = .CNAME },
    .{ .name = "bench-nx-20260820.example.com", .qtype = .A },
    .{ .name = ".", .qtype = .DNSKEY },
    .{ .name = "example.com", .qtype = .A },
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    comptime std.debug.assert(queries.len == corpus.cases.len);
    try benchClassification(io);
    try benchReferral(io);
    try benchCache(io);
    try benchAlias(io);
}

fn benchClassification(io: std.Io) !void {
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..classify_rounds) |_| {
        for (corpus.cases, queries) |case, q| {
            const m = try dns.Message.init(case.wire);
            const outcome = try dns.resolver.response.classify(m, q);
            checksum +%= @intFromEnum(std.meta.activeTag(outcome));
        }
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("resolver.classify_real_corpus", classify_rounds * corpus.cases.len, elapsed);
}

fn benchReferral(io: std.Io) !void {
    const referral_case = corpus.cases[12];
    const q = queries[12];
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..referral_rounds) |_| {
        const m = try dns.Message.init(referral_case.wire);
        const referral = try dns.resolver.referral.Referral.init(m, q);
        var ns = try referral.nameServers();
        while (try ns.next()) |server| checksum +%= @intFromBool(server.in_domain) + try server.target.consumed();
        var ds = try referral.ds();
        while (try ds.next()) |record| checksum +%= record.data.digest.len;
        var glue = try referral.gluePresentation(".");
        while (try glue.next()) |item| checksum +%= @intFromEnum(item.scope) + item.record.rdata.len;
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("resolver.extract_real_referral", referral_rounds, elapsed);
}

fn benchCache(io: std.Io) !void {
    const Cache = dns.cache.Fixed(u8, 32, 64);
    var cache = Cache.init();
    for (queries, 0..) |q, i| {
        _ = try cache.putPresentation(q.name, .{
            .kind = if (i == 10) .nxdomain else .positive,
            .rr_type = q.qtype,
            .expires_at = 10_000,
        }, @intCast(i), 0, null);
    }

    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..cache_rounds) |_| {
        for (queries) |q| {
            const hit = (try cache.lookupPresentation(q.name, q.qtype, q.qclass, 1)).?;
            checksum +%= hit.payload.* + hit.name.len;
        }
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("resolver.cache_real_names", cache_rounds * queries.len, elapsed);
}

fn benchAlias(io: std.Io) !void {
    const m = try dns.Message.init(corpus.cases[4].wire);
    var answers = try m.records(.answer);
    const cname = (try answers.next()).?;

    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..alias_rounds) |_| {
        var entries: [4]dns.resolver.alias.Entry = undefined;
        var storage: [128]u8 = undefined;
        var chain = try dns.resolver.alias.Chain.initPresentation(&entries, &storage, queries[4].name);
        try chain.followCname(cname);
        checksum +%= chain.currentWire().len + chain.aliasCount();
        std.mem.doNotOptimizeAway(storage);
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report("resolver.follow_real_cname", alias_rounds, elapsed);
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

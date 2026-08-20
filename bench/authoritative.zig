const std = @import("std");
const dns = @import("dns");
const corpus = @import("real_corpus.zig");

const exact_rounds = 160_000;
const signed_rounds = 100_000;
const negative_rounds = 160_000;

fn wire(comptime presentation: []const u8) [presentation.len + 2]u8 {
    var out: [presentation.len + 2]u8 = undefined;
    const value = dns.name.writePresentationWire(presentation, &out) catch unreachable;
    std.debug.assert(value.len == out.len);
    return out;
}

const cloudflare = wire("cloudflare.com");
const chatgpt = wire("chatgpt.com");
const ns_cloudflare = wire("ns.cloudflare.com");
const hostmaster_cloudflare = wire("hostmaster.cloudflare.com");
const ns_chatgpt = wire("ns.chatgpt.com");
const hostmaster_chatgpt = wire("hostmaster.chatgpt.com");

fn makeSoaRdata(comptime ns: []const u8, comptime hostmaster: []const u8) [ns.len + hostmaster.len + 20]u8 {
    var out: [ns.len + hostmaster.len + 20]u8 = undefined;
    var pos: usize = 0;
    @memcpy(out[pos..][0..ns.len], ns);
    pos += ns.len;
    @memcpy(out[pos..][0..hostmaster.len], hostmaster);
    pos += hostmaster.len;
    inline for (.{ @as(u32, 2026082001), 3600, 600, 86400, 300 }) |value| {
        std.mem.writeInt(u32, out[pos..][0..4], value, .big);
        pos += 4;
    }
    return out;
}
const cloudflare_soa = makeSoaRdata(&ns_cloudflare, &hostmaster_cloudflare);
const chatgpt_soa = makeSoaRdata(&ns_chatgpt, &hostmaster_chatgpt);

const BuiltQuery = struct {
    bytes: [128]u8,
    len: usize,

    fn message(self: *const BuiltQuery) !dns.Message {
        return dns.Message.init(self.bytes[0..self.len]);
    }
};

fn buildQuery(name: []const u8, rr_type: dns.Type) !BuiltQuery {
    var result: BuiltQuery = .{ .bytes = undefined, .len = 0 };
    var compression: [8]dns.CompressionEntry = undefined;
    var b = try dns.Builder.init(&result.bytes, &compression, 0x4242, .{});
    try b.addQuestion(name, rr_type, .IN);
    try b.addOpt(1232, 0, 0, .{}, &.{});
    result.len = (try b.finish()).len;
    return result;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var cloudflare_records: [16]dns.authoritative.ZoneRecord = undefined;
    var cloudflare_len: usize = 0;
    cloudflare_records[cloudflare_len] = .{
        .owner = .{ .bytes = &cloudflare },
        .rr_type = .SOA,
        .class = .IN,
        .ttl = 300,
        .rdata = &cloudflare_soa,
    };
    cloudflare_len += 1;
    try appendRealAnswers(&cloudflare_records, &cloudflare_len, .{ .bytes = &cloudflare }, corpus.cases[0].wire, .A);
    try appendRealAnswers(&cloudflare_records, &cloudflare_len, .{ .bytes = &cloudflare }, corpus.cases[1].wire, .AAAA);
    try appendRealAnswers(&cloudflare_records, &cloudflare_len, .{ .bytes = &cloudflare }, corpus.cases[3].wire, .CAA);

    var chatgpt_records: [8]dns.authoritative.ZoneRecord = undefined;
    var chatgpt_len: usize = 0;
    chatgpt_records[chatgpt_len] = .{
        .owner = .{ .bytes = &chatgpt },
        .rr_type = .SOA,
        .class = .IN,
        .ttl = 300,
        .rdata = &chatgpt_soa,
    };
    chatgpt_len += 1;
    try appendRealAnswers(&chatgpt_records, &chatgpt_len, .{ .bytes = &chatgpt }, corpus.cases[6].wire, .TXT);

    var cloudflare_store = dns.authoritative.SliceStore.init(.{ .bytes = &cloudflare }, cloudflare_records[0..cloudflare_len]);
    var cloudflare_composer = dns.authoritative.Composer(dns.authoritative.SliceStore).init(&cloudflare_store);
    var chatgpt_store = dns.authoritative.SliceStore.init(.{ .bytes = &chatgpt }, chatgpt_records[0..chatgpt_len]);
    var chatgpt_composer = dns.authoritative.Composer(dns.authoritative.SliceStore).init(&chatgpt_store);

    const a_query = try buildQuery("cloudflare.com", .A);
    const caa_query = try buildQuery("cloudflare.com", .CAA);
    const txt_query = try buildQuery("chatgpt.com", .TXT);
    const nx_query = try buildQuery("bench-nx-20260820.cloudflare.com", .A);

    try benchCompose(io, "authoritative.real_a_rrset", exact_rounds, &cloudflare_composer, try a_query.message());
    try benchCompose(io, "authoritative.real_caa_rrset", exact_rounds, &cloudflare_composer, try caa_query.message());
    try benchCompose(io, "authoritative.real_txt_rrset", exact_rounds, &chatgpt_composer, try txt_query.message());
    try benchCompose(io, "authoritative.negative_soa", negative_rounds, &cloudflare_composer, try nx_query.message());

    var key_name_storage: [64]u8 = undefined;
    const key = try dns.tsig.auth.Key.init("bench-key.cloudflare.com", "authoritative benchmark secret", &key_name_storage);
    var signed_query_buf: [512]u8 = undefined;
    var signed_query_compression: [16]dns.CompressionEntry = undefined;
    var signed_query_builder = try dns.Builder.init(&signed_query_buf, &signed_query_compression, 0x5252, .{});
    try signed_query_builder.addQuestion("cloudflare.com", .A, .IN);
    try signed_query_builder.addOpt(1232, 0, 0, .{}, &.{});
    var request_mac = try dns.tsig.auth.signBuilder(&signed_query_builder, key, .{ .time_signed = 1_700_000_000 });
    defer request_mac.deinit();
    const signed_query = try dns.Message.init(try signed_query_builder.finish());
    const response_sign_options: dns.tsig.auth.SignOptions = .{
        .time_signed = 1_700_000_001,
        .request_mac = request_mac.slice(),
    };
    const tail_reserve = try dns.tsig.auth.signedRecordWireSize(key, response_sign_options, true);
    try benchComposeTsig(io, "authoritative.real_a_rrset_tsig", signed_rounds, &cloudflare_composer, signed_query, key, response_sign_options, tail_reserve);

    std.debug.print("authoritative.slice_store: {d} bytes\n", .{@sizeOf(dns.authoritative.SliceStore)});
    std.debug.print("authoritative.composer: {d} bytes\n", .{@sizeOf(dns.authoritative.Composer(dns.authoritative.SliceStore))});
}

fn appendRealAnswers(
    records: []dns.authoritative.ZoneRecord,
    len: *usize,
    owner: dns.name.Uncompressed,
    packet: []const u8,
    rr_type: dns.Type,
) !void {
    const m = try dns.Message.init(packet);
    var answers = try m.records(.answer);
    while (try answers.next()) |rr| {
        if (rr.rr_type != rr_type) continue;
        if (len.* == records.len) return error.NoSpace;
        // A/AAAA/CAA/TXT RDATA contains no DNS compression pointers and can be
        // borrowed directly from the fixed real-data packet corpus.
        records[len.*] = .{ .owner = owner, .rr_type = rr.rr_type, .class = rr.class, .ttl = rr.ttl, .rdata = rr.rdata };
        len.* += 1;
    }
}

fn benchCompose(
    io: std.Io,
    label: []const u8,
    rounds: usize,
    composer: *dns.authoritative.Composer(dns.authoritative.SliceStore),
    query: dns.Message,
) !void {
    var out: [1232]u8 = undefined;
    var compression: [96]dns.CompressionEntry = undefined;
    var checksum: usize = 0;
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    for (0..rounds) |_| {
        const result = try composer.compose(query, &out, &compression, .{});
        checksum +%= result.bytes.len + @intFromEnum(result.kind);
        std.mem.doNotOptimizeAway(out);
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report(label, rounds, elapsed);
}

fn benchComposeTsig(
    io: std.Io,
    label: []const u8,
    rounds: usize,
    composer: *dns.authoritative.Composer(dns.authoritative.SliceStore),
    query: dns.Message,
    key: dns.tsig.auth.Key,
    sign_options: dns.tsig.auth.SignOptions,
    tail_reserve: usize,
) !void {
    var out: [1232]u8 = undefined;
    var compression: [96]dns.CompressionEntry = undefined;
    var checksum: usize = 0;
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    for (0..rounds) |_| {
        const result = try composer.compose(query, &out, &compression, .{ .tail_reserve = tail_reserve });
        var signed = try dns.tsig.auth.signInPlace(&out, result.bytes.len, key, sign_options);
        checksum +%= signed.bytes.len + signed.mac.len;
        std.mem.doNotOptimizeAway(out);
        signed.deinit();
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report(label, rounds, elapsed);
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

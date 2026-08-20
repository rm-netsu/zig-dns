const std = @import("std");
const dns = @import("dns");

fn wire(comptime presentation: []const u8) [presentation.len + 2]u8 {
    var out: [presentation.len + 2]u8 = undefined;
    const value = dns.name.writePresentationWire(presentation, &out) catch unreachable;
    std.debug.assert(value.len == out.len);
    return out;
}

const apex = wire("example.com");
const www = wire("www.example.com");
const wildcard = wire("*.example.com");
const ns = wire("ns.example.com");
const hostmaster = wire("hostmaster.example.com");

fn soaRdata() [ns.len + hostmaster.len + 20]u8 {
    var out: [ns.len + hostmaster.len + 20]u8 = undefined;
    var pos: usize = 0;
    @memcpy(out[pos..][0..ns.len], &ns);
    pos += ns.len;
    @memcpy(out[pos..][0..hostmaster.len], &hostmaster);
    pos += hostmaster.len;
    inline for (.{ @as(u32, 2026082001), 3600, 600, 86400, 300 }) |value| {
        std.mem.writeInt(u32, out[pos..][0..4], value, .big);
        pos += 4;
    }
    return out;
}
const soa_rdata = soaRdata();

const zone = [_]dns.authoritative.ZoneRecord{
    .{ .owner = .{ .bytes = &apex }, .rr_type = .SOA, .class = .IN, .ttl = 300, .rdata = &soa_rdata },
    .{ .owner = .{ .bytes = &apex }, .rr_type = .NS, .class = .IN, .ttl = 3600, .rdata = &ns },
    .{ .owner = .{ .bytes = &ns }, .rr_type = .A, .class = .IN, .ttl = 3600, .rdata = &.{ 192, 0, 2, 53 } },
    .{ .owner = .{ .bytes = &www }, .rr_type = .A, .class = .IN, .ttl = 300, .rdata = &.{ 192, 0, 2, 80 } },
    .{ .owner = .{ .bytes = &wildcard }, .rr_type = .A, .class = .IN, .ttl = 120, .rdata = &.{ 192, 0, 2, 81 } },
};

pub fn main(init: std.process.Init) !void {
    _ = init;
    var store = dns.authoritative.SliceStore.init(.{ .bytes = &apex }, &zone);
    var authoritative = dns.authoritative.Composer(dns.authoritative.SliceStore).init(&store);

    // The caller owns both query transport bytes and response storage.
    var query_buf: [512]u8 = undefined;
    var query_compression: [16]dns.CompressionEntry = undefined;
    var query_builder = try dns.Builder.init(&query_buf, &query_compression, 0x1234, .{ .recursion_desired = true });
    try query_builder.addQuestion("www.example.com", .A, .IN);
    try query_builder.addOpt(1232, 0, 0, .{}, &.{});
    const query = try dns.Message.init(try query_builder.finish());

    var response_buf: [1232]u8 = undefined;
    var response_compression: [64]dns.CompressionEntry = undefined;
    const result = try authoritative.compose(query, &response_buf, &response_compression, .{});

    const response = try dns.Message.init(result.bytes);
    var answers = try response.records(.answer);
    const rr = (try answers.next()).?;
    const address = try dns.rdata.a(rr);
    std.debug.print("{s}: {d}.{d}.{d}.{d} ({d} bytes)\n", .{
        @tagName(result.kind), address[0], address[1], address[2], address[3], result.bytes.len,
    });
}

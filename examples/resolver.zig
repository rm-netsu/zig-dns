const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    const question: dns.client.QuestionKey = .{ .name = "www.example.com", .qtype = .A };

    var query_buf: [1232]u8 = undefined;
    var query_compression: [32]dns.CompressionEntry = undefined;
    const query = try dns.resolver.buildQuery(
        &query_buf,
        &query_compression,
        0x4242,
        question,
        .{ .udp_payload_size = 1232, .dnssec_ok = true },
        &.{},
    );

    var transactions: dns.resolver.FixedTransactions(8) = .{};
    const slot = try transactions.reserve(0x4242, question);
    errdefer transactions.cancel(slot);

    // A real application sends `query` through its own UDP/TCP/TLS/QUIC/HTTP
    // runtime. Here we construct one response only to demonstrate semantics.
    var response_buf: [512]u8 = undefined;
    var response_compression: [24]dns.CompressionEntry = undefined;
    var response_builder = try dns.Builder.init(&response_buf, &response_compression, 0x4242, .{ .response = true });
    try response_builder.addQuestion(question.name, question.qtype, question.qclass);
    try response_builder.addNameRecord(.answer, question.name, .CNAME, 300, "origin.example.net");
    const response_wire = try response_builder.finish();

    const matched = try transactions.match(response_wire);
    const outcome = try dns.resolver.response.classify(matched.response, question);
    switch (outcome) {
        .cname => |rr| {
            var entries: [8]dns.resolver.alias.Entry = undefined;
            var name_storage: [512]u8 = undefined;
            var chain = try dns.resolver.alias.Chain.initPresentation(&entries, &name_storage, question.name);
            try chain.followCname(rr);
            var text: [dns.name.Name.max_presentation_len]u8 = undefined;
            std.debug.print("query={d} bytes; next alias={s}\n", .{ query.len, try chain.writeCurrentPresentation(&text) });
        },
        else => std.debug.print("query={d} bytes; outcome={s}\n", .{ query.len, @tagName(outcome) }),
    }

    // Cache storage and retry policy also remain caller-owned.
    const Cache = dns.cache.Fixed(u32, 16, 128);
    var cache = Cache.init();
    _ = try cache.putPresentation("origin.example.net", .{
        .kind = .positive,
        .rr_type = .A,
        .expires_at = dns.cache.expiresAt(1_000, 300),
    }, 7, 1_000, null);

    const decision = dns.resolver.retry.plan(.{ .queries_sent = 3 }, .timeout);
    std.debug.print("timeout action={s}\n", .{@tagName(decision.action)});
}

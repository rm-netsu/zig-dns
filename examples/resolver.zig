const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    const question: dns.client.QuestionKey = .{ .name = "example.com", .qtype = .AAAA };

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

    // A real application sends `query` over its UDP/TCP/TLS/HTTP/QUIC runtime.
    std.debug.print("built {d}-byte query; transaction slot={d}\n", .{ query.len, slot });
}

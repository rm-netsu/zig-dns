// Deterministic wire corpus built from real-world DNS RRsets observed on 2026-08-20.
// The fixtures are normalized snapshots, not literal packet captures. See
// bench/corpus/README.md for provenance and normalization details.

pub const Case = struct {
    name: []const u8,
    wire: []const u8,
};

pub const cases = [_]Case{
    .{ .name = "cloudflare.com. A", .wire = @embedFile("corpus/cloudflare_com_a.dns") },
    .{ .name = "cloudflare.com. AAAA", .wire = @embedFile("corpus/cloudflare_com_aaaa.dns") },
    .{ .name = "cloudflare.com. NS", .wire = @embedFile("corpus/cloudflare_com_ns.dns") },
    .{ .name = "cloudflare.com. CAA", .wire = @embedFile("corpus/cloudflare_com_caa.dns") },
    .{ .name = "status.openai.com. A", .wire = @embedFile("corpus/status_openai_com_a.dns") },
    .{ .name = "gmail.com. MX", .wire = @embedFile("corpus/gmail_com_mx.dns") },
    .{ .name = "chatgpt.com. TXT", .wire = @embedFile("corpus/chatgpt_com_txt.dns") },
    .{ .name = "dns.google. TXT", .wire = @embedFile("corpus/dns_google_txt.dns") },
    .{ .name = "example.com. DS", .wire = @embedFile("corpus/example_com_ds.dns") },
    .{ .name = "example.com. CNAME/NODATA", .wire = @embedFile("corpus/example_com_cname.dns") },
    .{ .name = "example.com. NXDOMAIN", .wire = @embedFile("corpus/bench_nx_20260820_example_com_a.dns") },
    .{ .name = ". DNSKEY", .wire = @embedFile("corpus/root_dnskey.dns") },
    .{ .name = ".com referral + glue", .wire = @embedFile("corpus/com_referral.dns") },
};

pub const total_wire_bytes: usize = blk: {
    var total: usize = 0;
    for (cases) |case| total += case.wire.len;
    break :blk total;
};

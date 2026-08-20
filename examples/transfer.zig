const std = @import("std");
const dns = @import("dns");

fn consume(
    decoder: *dns.tcp.Decoder,
    transfer: *dns.transfer.axfr.Transfer,
    chunk: []const u8,
) !usize {
    var offset: usize = 0;
    var records: usize = 0;
    while (offset < chunk.len) {
        const fed = try decoder.feed(chunk[offset..]);
        if (fed.consumed == 0) return error.NoProgress;
        offset += fed.consumed;

        switch (fed.event) {
            .need_more => {},
            .message => |wire| {
                const message = try dns.Message.init(wire);
                var cursor = try transfer.openMessage(message);
                while (try cursor.next()) |event| switch (event) {
                    .begin => std.debug.print("AXFR begin\n", .{}),
                    .record => records += 1,
                    .end => std.debug.print("AXFR end\n", .{}),
                    .remote_error => return error.RemoteDnsError,
                };
            },
        }
    }
    return records;
}

pub fn main() !void {
    const id: u16 = 0x5151;

    // Compose the caller-owned request. The Builder remains available for
    // optional EDNS and TSIG before finish().
    var query_packet: [512]u8 = undefined;
    var query_compression: [16]dns.CompressionEntry = undefined;
    var query = try dns.transfer.axfr.queryBuilder(
        &query_packet,
        &query_compression,
        id,
        "example.com",
        .IN,
    );
    var query_frame_storage: [514]u8 = undefined;
    const query_frame = try dns.tcp.frame(try query.finish(), &query_frame_storage);
    std.debug.print("AXFR TCP query: {d} framed bytes\n", .{query_frame.len});

    // The following two messages stand in for bytes received from the caller's
    // TCP/TLS runtime. The transfer receiver itself owns no transport.
    var first_packet: [768]u8 = undefined;
    var first_compression: [24]dns.CompressionEntry = undefined;
    var first = try dns.Builder.init(&first_packet, &first_compression, id, .{
        .response = true,
        .authoritative = true,
    });
    try first.addQuestion("example.com", .AXFR, .IN);
    try first.addSoa(.answer, "example.com", 300, "ns1.example.com", "hostmaster.example.com", 7, 3600, 600, 86400, 300);
    try first.addA(.answer, "www.example.com", 300, .{ 192, 0, 2, 10 });
    var first_frame_storage: [770]u8 = undefined;
    const first_frame = try dns.tcp.frame(try first.finish(), &first_frame_storage);

    var last_packet: [768]u8 = undefined;
    var last_compression: [24]dns.CompressionEntry = undefined;
    var last = try dns.Builder.init(&last_packet, &last_compression, id, .{
        .response = true,
        .authoritative = true,
    });
    try last.addAAAA(.answer, "v6.example.com", 300, .{0} ** 16);
    try last.addSoa(.answer, "example.com", 300, "ns1.example.com", "hostmaster.example.com", 7, 3600, 600, 86400, 300);
    var last_frame_storage: [770]u8 = undefined;
    const last_frame = try dns.tcp.frame(try last.finish(), &last_frame_storage);

    var decoder_storage: [768]u8 = undefined;
    var decoder = dns.tcp.Decoder.init(&decoder_storage);
    var transfer_storage: dns.transfer.axfr.Storage = .{};
    var transfer = try dns.transfer.axfr.Transfer.init(
        &transfer_storage,
        id,
        "example.com",
        .IN,
    );

    var record_count: usize = 0;
    record_count += try consume(&decoder, &transfer, first_frame[0..5]);
    record_count += try consume(&decoder, &transfer, first_frame[5..]);
    record_count += try consume(&decoder, &transfer, last_frame);
    try decoder.finish();
    try transfer.finish();

    std.debug.print("AXFR complete: {d} ordinary records\n", .{record_count});
}

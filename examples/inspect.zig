const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    var packet: [512]u8 = undefined;
    var compression: [32]dns.CompressionEntry = undefined;
    var b = try dns.Builder.init(&packet, &compression, 0x1234, .{ .response = true, .recursion_available = true });
    try b.addQuestion("example.com", .A, .IN);
    try b.addA(.answer, "example.com", 300, .{ 93, 184, 216, 34 });
    const wire = try b.finish();

    const m = try dns.Message.init(wire);
    std.debug.print("id={x} answers={d}\n", .{ m.header.id, m.header.answer_count });
    var answers = try m.records(.answer);
    var name_buf: [253]u8 = undefined;
    while (try answers.next()) |rr| {
        const owner = try rr.name.writePresentation(&name_buf);
        if (rr.rr_type == .A) {
            const ip = try dns.rdata.a(rr);
            std.debug.print("{s} {d} IN A {d}.{d}.{d}.{d}\n", .{ owner, rr.ttl, ip[0], ip[1], ip[2], ip[3] });
        }
    }
}

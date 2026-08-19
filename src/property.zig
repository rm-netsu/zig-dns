const std = @import("std");
const builder = @import("builder.zig");
const message = @import("message.zig");
const validate = @import("validate.zig");
const tcp = @import("tcp.zig");

const Lcg = struct {
    state: u64,
    fn next(self: *Lcg) u64 {
        self.state = self.state *% 6364136223846793005 +% 1442695040888963407;
        return self.state;
    }
    fn byte(self: *Lcg) u8 {
        return @truncate(self.next() >> 24);
    }
};

test "arbitrary packets never escape parser bounds" {
    var rng: Lcg = .{ .state = 0x7a11_c0de_d15c_a11e };
    var bytes: [512]u8 = undefined;
    for (0..4096) |_| {
        const len: usize = @intCast(rng.next() % (bytes.len + 1));
        for (bytes[0..len]) |*b| b.* = rng.byte();
        const m = message.Message.init(bytes[0..len]) catch continue;
        _ = validate.messageStrict(m, .{}) catch continue;
    }
}

test "builder parser round trips deterministic name corpus" {
    var rng: Lcg = .{ .state = 0xdecaf_bad5_eed1234 };
    var packet: [512]u8 = undefined;
    var compression: [32]builder.CompressionEntry = undefined;
    var name_buf: [128]u8 = undefined;

    for (0..512) |round| {
        var pos: usize = 0;
        const labels: usize = 1 + @as(usize, @intCast(rng.next() % 4));
        for (0..labels) |label_i| {
            if (label_i != 0) {
                name_buf[pos] = '.';
                pos += 1;
            }
            const label_len: usize = 1 + @as(usize, @intCast(rng.next() % 12));
            for (0..label_len) |_| {
                name_buf[pos] = 'a' + @as(u8, @intCast(rng.next() % 26));
                pos += 1;
            }
        }
        const qname = name_buf[0..pos];
        var b = try builder.Builder.init(&packet, &compression, @intCast(round), .{ .recursion_desired = true });
        try b.addQuestion(qname, .A, .IN);
        try b.addA(.answer, qname, 60, .{ 192, 0, 2, 1 });
        const wire = try b.finish();
        const m = try message.Message.init(wire);
        try m.validate();
        var qi = m.questions();
        const q = (try qi.next()).?;
        try std.testing.expect(try q.name.eqlPresentationIgnoreCase(qname));
        var ri = try m.records(.answer);
        const rr = (try ri.next()).?;
        try std.testing.expect(try rr.name.eqlPresentationIgnoreCase(qname));
    }
}

test "tcp decoder survives arbitrary fragmentation" {
    var rng: Lcg = .{ .state = 0x5eed_7c00_0000_0001 };
    var msg: [96]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i * 17 + 3);
    var framed: [98]u8 = undefined;
    const wire = try tcp.frame(&msg, &framed);

    for (0..128) |_| {
        var storage: [128]u8 = undefined;
        var decoder = tcp.Decoder.init(&storage);
        var pos: usize = 0;
        var got = false;
        while (pos < wire.len) {
            const chunk = @min(wire.len - pos, 1 + @as(usize, @intCast(rng.next() % 11)));
            var local_pos: usize = 0;
            while (local_pos < chunk) {
                const feed = try decoder.feed(wire[pos + local_pos .. pos + chunk]);
                try std.testing.expect(feed.consumed != 0 or feed.event == .message);
                local_pos += feed.consumed;
                switch (feed.event) {
                    .need_more => {},
                    .message => |decoded| {
                        try std.testing.expect(!got);
                        try std.testing.expectEqualSlices(u8, &msg, decoded);
                        got = true;
                    },
                }
            }
            pos += chunk;
        }
        try std.testing.expect(got);
    }
}

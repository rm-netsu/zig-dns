const std = @import("std");
const builder = @import("builder.zig");
const dnssec = @import("dnssec.zig");
const message = @import("message.zig");
const name = @import("name.zig");
const rdata = @import("rdata.zig");
const validate = @import("validate.zig");
const tcp = @import("tcp.zig");
const types = @import("types.zig");

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

test "dnssec canonical RR is invariant to presentation case" {
    var rng: Lcg = .{ .state = 0xc411_0a1c_4e11_0001 };
    var lower_name: [128]u8 = undefined;
    var mixed_name: [128]u8 = undefined;

    for (0..512) |round| {
        var pos: usize = 0;
        const labels: usize = 1 + @as(usize, @intCast(rng.next() % 4));
        for (0..labels) |label_i| {
            if (label_i != 0) {
                lower_name[pos] = '.';
                mixed_name[pos] = '.';
                pos += 1;
            }
            const label_len: usize = 1 + @as(usize, @intCast(rng.next() % 12));
            for (0..label_len) |_| {
                const c: u8 = 'a' + @as(u8, @intCast(rng.next() % 26));
                lower_name[pos] = c;
                mixed_name[pos] = if ((rng.next() & 1) == 0) c else c - ('a' - 'A');
                pos += 1;
            }
        }

        var lower_packet: [512]u8 = undefined;
        var lower_compression: [32]builder.CompressionEntry = undefined;
        var lower_builder = try builder.Builder.init(&lower_packet, &lower_compression, @intCast(round), .{ .response = true });
        try lower_builder.addQuestion(lower_name[0..pos], .A, .IN);
        try lower_builder.addA(.answer, lower_name[0..pos], 300, .{ 192, 0, 2, 1 });
        const lower_wire = try lower_builder.finish();

        var mixed_packet: [512]u8 = undefined;
        var mixed_compression: [32]builder.CompressionEntry = undefined;
        var mixed_builder = try builder.Builder.init(&mixed_packet, &mixed_compression, @intCast(round), .{ .response = true });
        try mixed_builder.addQuestion(mixed_name[0..pos], .A, .IN);
        try mixed_builder.addA(.answer, mixed_name[0..pos], 300, .{ 192, 0, 2, 1 });
        const mixed_wire = try mixed_builder.finish();

        const lower_message = try message.Message.init(lower_wire);
        var lower_answers = try lower_message.records(.answer);
        const lower_rr = (try lower_answers.next()).?;
        const mixed_message = try message.Message.init(mixed_wire);
        var mixed_answers = try mixed_message.records(.answer);
        const mixed_rr = (try mixed_answers.next()).?;

        var lower_canonical: [512]u8 = undefined;
        var lower_writer = dnssec.CanonicalWriter.init(&lower_canonical);
        try lower_writer.writeRecord(lower_rr, 300);
        var mixed_canonical: [512]u8 = undefined;
        var mixed_writer = dnssec.CanonicalWriter.init(&mixed_canonical);
        try mixed_writer.writeRecord(mixed_rr, 300);

        try std.testing.expectEqualSlices(u8, lower_writer.written(), mixed_writer.written());
    }
}

test "dnssec signed RRset data is invariant to input record order" {
    var rng: Lcg = .{ .state = 0x2253_37d4_0a0d_0001 };
    const signer_wire = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    const signer_name = try name.Name.init(&signer_wire, 0);
    const sig: rdata.Rrsig = .{
        .type_covered = @intFromEnum(types.Type.A),
        .algorithm = 15,
        .labels = 3,
        .original_ttl = 3600,
        .expiration = 2,
        .inception = 1,
        .key_tag = 0x1234,
        .signer_name = signer_name,
        .signature = &.{},
    };

    for (0..256) |round| {
        const count: usize = 2 + @as(usize, @intCast(rng.next() % 7));
        var order_a = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
        var order_b = order_a;
        shuffle(&rng, order_a[0..count]);
        shuffle(&rng, order_b[0..count]);

        var packet_a: [1024]u8 = undefined;
        var compression_a: [32]builder.CompressionEntry = undefined;
        var builder_a = try builder.Builder.init(&packet_a, &compression_a, @intCast(round), .{ .response = true });
        for (order_a[0..count]) |last_octet| {
            try builder_a.addA(.answer, "www.example.com", 30, .{ 192, 0, 2, last_octet });
        }
        const wire_a = try builder_a.finish();

        var packet_b: [1024]u8 = undefined;
        var compression_b: [32]builder.CompressionEntry = undefined;
        var builder_b = try builder.Builder.init(&packet_b, &compression_b, @intCast(round), .{ .response = true });
        for (order_b[0..count]) |last_octet| {
            try builder_b.addA(.answer, "www.example.com", 30, .{ 192, 0, 2, last_octet });
        }
        const wire_b = try builder_b.finish();

        const msg_a = try message.Message.init(wire_a);
        const msg_b = try message.Message.init(wire_b);
        var records_a: [8]message.Record = undefined;
        var records_b: [8]message.Record = undefined;
        var it_a = try msg_a.records(.answer);
        var it_b = try msg_b.records(.answer);
        for (0..count) |i| {
            records_a[i] = (try it_a.next()).?;
            records_b[i] = (try it_b.next()).?;
        }

        const set_a = try dnssec.Rrset.init(records_a[0..count]);
        const set_b = try dnssec.Rrset.init(records_b[0..count]);
        var signed_a: [1024]u8 = undefined;
        var signed_b: [1024]u8 = undefined;
        var writer_a = dnssec.CanonicalWriter.init(&signed_a);
        var writer_b = dnssec.CanonicalWriter.init(&signed_b);
        var sort_a: [8]u16 = undefined;
        var sort_b: [8]u16 = undefined;
        var compare_a: [64]u8 = undefined;
        var compare_b: [64]u8 = undefined;
        try dnssec.rrset.writeSignedData(&writer_a, sig, set_a, sort_a[0..count], &compare_a);
        try dnssec.rrset.writeSignedData(&writer_b, sig, set_b, sort_b[0..count], &compare_b);

        try std.testing.expectEqualSlices(u8, writer_a.written(), writer_b.written());
    }
}

fn shuffle(rng: *Lcg, values: []u8) void {
    var i = values.len;
    while (i > 1) {
        i -= 1;
        const j: usize = @intCast(rng.next() % (i + 1));
        const tmp = values[i];
        values[i] = values[j];
        values[j] = tmp;
    }
}

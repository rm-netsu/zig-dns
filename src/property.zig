const std = @import("std");
const builder = @import("builder.zig");
const dnssec = @import("dnssec.zig");
const edns = @import("edns.zig");
const message = @import("message.zig");
const name = @import("name.zig");
const rdata = @import("rdata.zig");
const validate = @import("validate.zig");
const tcp = @import("tcp.zig");
const tsig = @import("tsig.zig");
const update = @import("update.zig");
const types = @import("types.zig");
const transfer = @import("transfer.zig");
const resolver = @import("resolver.zig");

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

test "operational EDNS parsers survive arbitrary payloads" {
    var rng: Lcg = .{ .state = 0xed05_9660_9664_0001 };
    var payload: [64]u8 = undefined;

    for (0..4096) |_| {
        const len: usize = @intCast(rng.next() % (payload.len + 1));
        for (payload[0..len]) |*b| b.* = rng.byte();
        const data = payload[0..len];

        switch (rng.next() % 10) {
            0 => _ = edns.parseCookie(.{ .code = .COOKIE, .data = data }) catch continue,
            1 => _ = edns.parseKeepalive(.{ .code = .KEEPALIVE, .data = data }) catch continue,
            2 => _ = edns.extendedError(.{ .code = .EDE, .data = data }) catch continue,
            3 => _ = edns.parseUpdateLease(.{ .code = .UPDATE_LEASE, .data = data }) catch continue,
            4 => _ = edns.parseZoneVersion(.{ .code = .ZONEVERSION, .data = data }, false) catch continue,
            5 => _ = edns.parseZoneVersion(.{ .code = .ZONEVERSION, .data = data }, true) catch continue,
            6 => _ = edns.parseExpire(.{ .code = .EXPIRE, .data = data }) catch continue,
            7 => _ = edns.parseMultipleQtypeQuery(.{ .code = .MQTYPE_QUERY, .data = data }) catch continue,
            8 => _ = edns.parseMultipleQtypeResponse(.{ .code = .MQTYPE_RESPONSE, .data = data }) catch continue,
            else => _ = edns.parseReportChannel(.{ .code = .REPORT_CHANNEL, .data = data }) catch continue,
        }
    }
}

test "operational EDNS builders round trip deterministic generated values" {
    var rng: Lcg = .{ .state = 0xed05_c00c_1eaf_0001 };
    var option_bytes: [128]u8 = undefined;

    for (0..512) |_| {
        var options = edns.OptionBuilder.init(&option_bytes);
        switch (rng.next() % 8) {
            0 => {
                var client: [edns.cookie.client_length]u8 = undefined;
                for (&client) |*b| b.* = rng.byte();
                var server: [edns.cookie.server_max_length]u8 = undefined;
                for (&server) |*b| b.* = rng.byte();
                const server_len: usize = edns.cookie.server_min_length + @as(usize, @intCast(rng.next() % (edns.cookie.server_max_length - edns.cookie.server_min_length + 1)));
                try options.addCookie(client, server[0..server_len]);
                var it: edns.Iterator = .{ .bytes = options.bytes() };
                const value = try edns.parseCookie((try it.next()).?);
                try std.testing.expectEqualSlices(u8, &client, &value.client);
                try std.testing.expectEqualSlices(u8, server[0..server_len], value.server.?);
            },
            1 => {
                const timeout: u16 = @truncate(rng.next());
                try options.addKeepaliveResponse(timeout);
                var it: edns.Iterator = .{ .bytes = options.bytes() };
                const value = try edns.parseKeepalive((try it.next()).?);
                try std.testing.expectEqual(timeout, value.timeout);
            },
            2 => {
                const code: edns.ExtendedErrorCode = @enumFromInt(@as(u16, @truncate(rng.next())));
                var text: [24]u8 = undefined;
                const text_len: usize = @intCast(rng.next() % (text.len + 1));
                for (text[0..text_len]) |*b| b.* = 'a' + @as(u8, @intCast(rng.next() % 26));
                try options.addExtendedErrorCode(code, text[0..text_len]);
                var it: edns.Iterator = .{ .bytes = options.bytes() };
                const value = try edns.extendedError((try it.next()).?);
                try std.testing.expectEqual(@as(u16, @intFromEnum(code)), value.info_code);
                try std.testing.expectEqualSlices(u8, text[0..text_len], value.extra_text);
            },
            3 => {
                const value: edns.UpdateLease = .{
                    .lease = @truncate(rng.next()),
                    .key_lease = if ((rng.next() & 1) == 0) null else @as(u32, @truncate(rng.next())),
                };
                try options.addUpdateLease(value);
                var it: edns.Iterator = .{ .bytes = options.bytes() };
                const parsed = try edns.parseUpdateLease((try it.next()).?);
                try std.testing.expectEqual(value.lease, parsed.lease);
                try std.testing.expectEqual(value.key_lease, parsed.key_lease);
            },
            4 => {
                const labels: u8 = @intCast(rng.next() % 16);
                const serial: u32 = @truncate(rng.next());
                try options.addZoneVersionSoaSerial(labels, serial);
                var it: edns.Iterator = .{ .bytes = options.bytes() };
                const parsed = try edns.parseZoneVersion((try it.next()).?, true);
                try std.testing.expectEqual(labels, parsed.response.label_count);
                try std.testing.expectEqual(@as(?u32, serial), parsed.response.soaSerial());
            },
            5 => {
                const remaining: u32 = @truncate(rng.next());
                try options.addExpireResponse(remaining);
                var it: edns.Iterator = .{ .bytes = options.bytes() };
                const parsed = try edns.parseExpire((try it.next()).?);
                try std.testing.expectEqual(remaining, parsed.remaining_seconds);
            },
            6 => {
                const choices = [_]types.Type{ .AAAA, .HTTPS, .TXT, .CAA };
                const first = choices[@intCast(rng.next() % choices.len)];
                var second = choices[@intCast(rng.next() % choices.len)];
                if (second == first) second = choices[(@intFromEnum(first) + 1) % choices.len];
                const requested = [_]types.Type{ first, second };
                try options.addMultipleQtypeQuery(.A, &requested);
                var it: edns.Iterator = .{ .bytes = options.bytes() };
                const parsed = try edns.parseMultipleQtypeQuery((try it.next()).?);
                var scratch: edns.MultipleQtypeScratch = .{};
                try parsed.validate(.A, &scratch);
                try std.testing.expectEqual(@as(usize, 2), parsed.count());
            },
            else => {
                var label: [12]u8 = undefined;
                for (&label) |*b| b.* = 'a' + @as(u8, @intCast(rng.next() % 26));
                var wire: [14]u8 = undefined;
                wire[0] = label.len;
                @memcpy(wire[1..13], &label);
                wire[13] = 0;
                try options.addReportChannel(try name.Uncompressed.init(&wire));
                var it: edns.Iterator = .{ .bytes = options.bytes() };
                const parsed = try edns.parseReportChannel((try it.next()).?);
                try std.testing.expectEqualSlices(u8, &wire, parsed.agent_domain.bytes);
            },
        }
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

test "TSIG parser survives arbitrary RDATA" {
    var rng: Lcg = .{ .state = 0x7516_a8f4_8945_0001 };
    const root_packet = [_]u8{0};
    const root = try name.Name.init(&root_packet, 0);
    var rdata_buf: [512]u8 = undefined;

    for (0..4096) |_| {
        const len: usize = @intCast(rng.next() % (rdata_buf.len + 1));
        for (rdata_buf[0..len]) |*b| b.* = rng.byte();
        const rr: message.Record = .{
            .packet = &root_packet,
            .name = root,
            .rr_type = .TSIG,
            .class = .ANY,
            .ttl = 0,
            .rdata_offset = 0,
            .rdata = rdata_buf[0..len],
        };
        const parsed = tsig.parse(rr) catch continue;
        _ = tsig.validateSemantics(parsed, true) catch continue;
    }
}

test "UPDATE prescan survives arbitrary update-shaped packets" {
    var rng: Lcg = .{ .state = 0x2136_5eed_0000_0001 };
    var bytes: [768]u8 = undefined;

    for (0..4096) |_| {
        const len: usize = @intCast(rng.next() % (bytes.len + 1));
        for (bytes[0..len]) |*b| b.* = rng.byte();
        if (len >= types.Header.wire_len) {
            var flags = std.mem.readInt(u16, bytes[2..4], .big);
            flags &= ~@as(u16, 0xF800); // QR=0 and clear the four opcode bits.
            flags |= @as(u16, @intFromEnum(types.Opcode.update)) << 11;
            std.mem.writeInt(u16, bytes[2..4], flags, .big);
        }
        const m = message.Message.init(bytes[0..len]) catch continue;
        _ = update.validateRequest(m) catch continue;
    }
}

test "UPDATE semantic composer round trips generated operations" {
    var rng: Lcg = .{ .state = 0x2136_c0de_f00d_0001 };
    var packet: [1024]u8 = undefined;
    var compression: [32]builder.CompressionEntry = undefined;

    for (0..256) |round| {
        var composer = try update.Composer.init(&packet, &compression, @intCast(round), "example.com", .IN);
        switch (rng.next() % 4) {
            0 => try composer.requireNameExists("host.example.com"),
            1 => try composer.requireRrsetExists("host.example.com", .A),
            2 => try composer.requireRrsetNotExists("host.example.com", .AAAA),
            else => try composer.requireA("host.example.com", .{ 192, 0, 2, @truncate(rng.next()) }),
        }
        switch (rng.next() % 4) {
            0 => try composer.addA("host.example.com", @truncate(rng.next()), .{ 192, 0, 2, @truncate(rng.next()) }),
            1 => try composer.deleteRrset("host.example.com", .TXT),
            2 => try composer.deleteName("old.example.com"),
            else => try composer.deleteA("old.example.com", .{ 192, 0, 2, @truncate(rng.next()) }),
        }
        const m = try message.Message.init(try composer.finish());
        _ = try update.validateRequest(m);
        _ = try validate.messageStrict(m, .{});
    }
}

test "IXFR state machine round trips generated deltas and survives mutations" {
    var rng: Lcg = .{ .state = 0x1995_5936_9103_0001 };
    var packet: [4096]u8 = undefined;
    var compression: [128]builder.CompressionEntry = undefined;
    var mutated: [4096]u8 = undefined;

    for (0..256) |round| {
        const delta_count: usize = 1 + @as(usize, @intCast(rng.next() % 3));
        const requested: u32 = @truncate(rng.next());
        const current = requested +% @as(u32, @intCast(delta_count));
        var b = try builder.Builder.init(&packet, &compression, @intCast(round), .{
            .response = true,
            .authoritative = true,
        });
        try b.addQuestion("example.com", .IXFR, .IN);
        try b.addSoa(.answer, "example.com", 300, "ns1.example.com", "hostmaster.example.com", current, 3600, 600, 86400, 300);

        var serial = requested;
        for (0..delta_count) |delta| {
            try b.addSoa(.answer, "example.com", 300, "ns1.example.com", "hostmaster.example.com", serial, 3600, 600, 86400, 300);
            try b.addA(.answer, "changed.example.com", 60, .{ 192, 0, @truncate(delta), @truncate(rng.next()) });
            serial +%= 1;
            try b.addSoa(.answer, "example.com", 300, "ns1.example.com", "hostmaster.example.com", serial, 3600, 600, 86400, 300);
            try b.addA(.answer, "changed.example.com", 60, .{ 198, 51, @truncate(delta), @truncate(rng.next()) });
        }
        try b.addSoa(.answer, "example.com", 300, "ns1.example.com", "hostmaster.example.com", current, 3600, 600, 86400, 300);
        const wire = try b.finish();

        var storage: transfer.ixfr.Storage = .{};
        var state = try transfer.ixfr.Transfer.init(&storage, @intCast(round), "example.com", .IN, requested);
        var cursor = try state.openMessage(try message.Message.init(wire));
        var events: usize = 0;
        while (try cursor.next()) |_| events += 1;
        try state.finish();
        try std.testing.expectEqual(2 + 5 * delta_count, events);

        // Replay one deterministic mutation of each otherwise-valid response.
        // Any protocol error is acceptable; memory unsafety or unbounded work is not.
        @memcpy(mutated[0..wire.len], wire);
        const flip_at: usize = @intCast(rng.next() % wire.len);
        mutated[flip_at] ^= @as(u8, 1) << @intCast(rng.next() % 8);
        const mutated_message = message.Message.init(mutated[0..wire.len]) catch continue;
        var mutated_storage: transfer.ixfr.Storage = .{};
        var mutated_state = try transfer.ixfr.Transfer.init(&mutated_storage, @intCast(round), "example.com", .IN, requested);
        var mutated_cursor = mutated_state.openMessage(mutated_message) catch continue;
        while (true) {
            const event = mutated_cursor.next() catch break;
            if (event == null) break;
        }
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

test "resolver response classifier survives arbitrary QUERY-shaped packets" {
    var rng: Lcg = .{ .state = 0x2308_6672_9471_0001 };
    var bytes: [768]u8 = undefined;
    const q: @import("client.zig").QuestionKey = .{ .name = "example.com", .qtype = .A };

    for (0..4096) |_| {
        const len: usize = 12 + @as(usize, @intCast(rng.next() % (bytes.len - 11)));
        for (bytes[0..len]) |*b| b.* = rng.byte();
        // Keep QR=1 and OPCODE=QUERY so successful parses reach resolver
        // semantics rather than being rejected solely by the outer envelope.
        var flags = std.mem.readInt(u16, bytes[2..4], .big);
        flags &= ~(@as(u16, 0xf) << 11);
        flags |= @as(u16, 1) << 15;
        std.mem.writeInt(u16, bytes[2..4], flags, .big);

        const m = message.Message.init(bytes[0..len]) catch continue;
        _ = resolver.response.classify(m, q) catch continue;
    }
}

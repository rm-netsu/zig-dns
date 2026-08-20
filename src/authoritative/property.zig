const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const builder = @import("../builder.zig");
const validate = @import("../validate.zig");
const api = @import("types.zig");
const composer_mod = @import("composer.zig");
const store_mod = @import("store.zig");

fn wire(comptime presentation: []const u8) [presentation.len + 2]u8 {
    var out: [presentation.len + 2]u8 = undefined;
    const value = name_mod.writePresentationWire(presentation, &out) catch unreachable;
    std.debug.assert(value.len == out.len);
    return out;
}

const apex_storage = wire("example");
const www_storage = wire("www.example");
const wildcard_storage = wire("*.example");
const child_storage = wire("child.example");
const ns_child_storage = wire("ns.child.example");
const old_storage = wire("old.example");
const new_storage = wire("new.example");
const ns_storage = wire("ns.example");
const hostmaster_storage = wire("hostmaster.example");

fn soaRdata() [ns_storage.len + hostmaster_storage.len + 20]u8 {
    var out: [ns_storage.len + hostmaster_storage.len + 20]u8 = undefined;
    var pos: usize = 0;
    @memcpy(out[pos..][0..ns_storage.len], &ns_storage);
    pos += ns_storage.len;
    @memcpy(out[pos..][0..hostmaster_storage.len], &hostmaster_storage);
    pos += hostmaster_storage.len;
    inline for (.{ @as(u32, 1), 3600, 600, 86400, 60 }) |v| {
        std.mem.writeInt(u32, out[pos..][0..4], v, .big);
        pos += 4;
    }
    return out;
}
const soa_rdata = soaRdata();

const records = [_]api.ZoneRecord{
    .{ .owner = .{ .bytes = &apex_storage }, .rr_type = .SOA, .class = .IN, .ttl = 60, .rdata = &soa_rdata },
    .{ .owner = .{ .bytes = &www_storage }, .rr_type = .A, .class = .IN, .ttl = 300, .rdata = &.{ 192, 0, 2, 1 } },
    .{ .owner = .{ .bytes = &wildcard_storage }, .rr_type = .A, .class = .IN, .ttl = 120, .rdata = &.{ 192, 0, 2, 9 } },
    .{ .owner = .{ .bytes = &child_storage }, .rr_type = .NS, .class = .IN, .ttl = 600, .rdata = &ns_child_storage },
    .{ .owner = .{ .bytes = &ns_child_storage }, .rr_type = .A, .class = .IN, .ttl = 600, .rdata = &.{ 192, 0, 2, 53 } },
    .{ .owner = .{ .bytes = &old_storage }, .rr_type = .DNAME, .class = .IN, .ttl = 300, .rdata = &new_storage },
};

const names = [_][]const u8{
    "www.example",
    "missing.example",
    "host.child.example",
    "host.old.example",
    "example",
    "outside.test",
};
const qtypes = [_]types.Type{ .A, .AAAA, .DS, .ANY, .TXT, .NS };

test "authoritative deterministic query and truncation replay" {
    var store = store_mod.SliceStore.init(.{ .bytes = &apex_storage }, &records);
    var composer = composer_mod.Composer(store_mod.SliceStore).init(&store);
    var prng = std.Random.DefaultPrng.init(0x617574686f726974);
    const random = prng.random();

    var query_buf: [512]u8 = undefined;
    var query_compression: [32]builder.CompressionEntry = undefined;
    var out: [1400]u8 = undefined;
    var compression: [96]builder.CompressionEntry = undefined;

    for (0..256) |iteration| {
        var qb = try builder.Builder.init(&query_buf, &query_compression, @truncate(iteration), .{ .recursion_desired = true });
        const qname = names[random.uintLessThan(usize, names.len)];
        const qtype = qtypes[random.uintLessThan(usize, qtypes.len)];
        try qb.addQuestion(qname, qtype, .IN);
        const has_edns = random.boolean();
        if (has_edns) {
            const payloads = [_]u16{ 128, 512, 1232, 4096 };
            try qb.addOpt(
                payloads[random.uintLessThan(usize, payloads.len)],
                0,
                if (random.uintLessThan(u8, 8) == 0) 1 else 0,
                .{ .dnssec_ok = random.boolean() },
                &.{},
            );
        }
        const query_wire = try qb.finish();
        const query = try message.Message.init(query_wire);

        const caps = [_]usize{ 32, 64, 128, 256, 512, 1232, 1400 };
        const cap = caps[random.uintLessThan(usize, caps.len)];
        const options: api.Options = .{
            .transport = if (random.boolean()) .datagram else .stream,
            .any_policy = if (random.boolean()) .refuse else .{ .rr_type = .A },
        };
        const result = composer.compose(query, out[0..cap], &compression, options) catch |err| switch (err) {
            error.NoSpace => continue,
            else => return err,
        };
        const response = try message.Message.init(result.bytes);
        _ = try validate.messageStrict(response, .{});
        try std.testing.expect(response.header.flags.response);
        try std.testing.expectEqual(query.header.id, response.header.id);
        try std.testing.expect(result.bytes.len <= cap);

        // Replay one deterministic mutation of attacker-controlled query bytes.
        if (query_wire.len > types.Header.wire_len) {
            var mutated: [512]u8 = undefined;
            @memcpy(mutated[0..query_wire.len], query_wire);
            const at = types.Header.wire_len + random.uintLessThan(usize, query_wire.len - types.Header.wire_len);
            const bit: u3 = @intCast(random.uintLessThan(u8, 8));
            mutated[at] ^= @as(u8, 1) << bit;
            if (message.Message.init(mutated[0..query_wire.len])) |mutated_message| {
                if (composer.compose(mutated_message, &out, &compression, options)) |mutated_result| {
                    const mutated_response = try message.Message.init(mutated_result.bytes);
                    _ = try validate.messageStrict(mutated_response, .{});
                } else |_| {}
            } else |_| {}
        }
    }
}

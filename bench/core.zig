const std = @import("std");
const dns = @import("dns");
const corpus = @import("real_corpus.zig");

const parse_rounds = 80_000;
const validate_rounds = 30_000;
const name_rounds = 45_000;
const build_rounds = 35_000;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    try verifyCorpus();
    try benchParse(io);
    try benchStrictValidate(io);
    try benchNames(io);
    try benchBuild(io);
}

fn verifyCorpus() !void {
    for (corpus.cases) |case| {
        const m = try dns.Message.init(case.wire);
        _ = try dns.validate.messageStrict(m, .{});
    }
}

fn benchParse(io: std.Io) !void {
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..parse_rounds) |_| {
        for (corpus.cases) |case| {
            const m = try dns.Message.init(case.wire);
            checksum +%= m.header.answer_count + m.header.authority_count + m.header.additional_count;

            var questions = m.questions();
            while (try questions.next()) |q| checksum +%= @intFromEnum(q.qtype);
            inline for (.{ dns.Section.answer, dns.Section.authority, dns.Section.additional }) |section| {
                var records = try m.records(section);
                while (try records.next()) |rr| checksum +%= @intFromEnum(rr.rr_type) + rr.rdata.len;
            }
        }
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report(
        "core.parse_real_corpus",
        parse_rounds * corpus.cases.len,
        parse_rounds * corpus.total_wire_bytes,
        elapsed,
    );
}

fn benchStrictValidate(io: std.Io) !void {
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..validate_rounds) |_| {
        for (corpus.cases) |case| {
            const m = try dns.Message.init(case.wire);
            const result = try dns.validate.messageStrict(m, .{});
            checksum +%= @intFromBool(result.opt != null) + m.header.answer_count;
        }
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report(
        "core.validate_real_corpus",
        validate_rounds * corpus.cases.len,
        validate_rounds * corpus.total_wire_bytes,
        elapsed,
    );
}

fn benchNames(io: std.Io) !void {
    var out: [dns.name.Name.max_wire_len]u8 = undefined;

    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..name_rounds) |_| {
        for (corpus.cases) |case| {
            const m = try dns.Message.init(case.wire);
            var questions = m.questions();
            while (try questions.next()) |q| {
                const wire = try q.name.writeWire(&out);
                checksum +%= wire.len + wire[wire.len - 1];
                std.mem.doNotOptimizeAway(out);
            }
            inline for (.{ dns.Section.answer, dns.Section.authority, dns.Section.additional }) |section| {
                var records = try m.records(section);
                while (try records.next()) |rr| {
                    const wire = try rr.name.writeWire(&out);
                    checksum +%= wire.len + wire[wire.len - 1];
                    std.mem.doNotOptimizeAway(out);
                }
            }
        }
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report(
        "core.materialize_real_names",
        name_rounds * corpus.cases.len,
        name_rounds * corpus.total_wire_bytes,
        elapsed,
    );
}

fn benchBuild(io: std.Io) !void {
    var packet: [2048]u8 = undefined;
    var compression: [128]dns.CompressionEntry = undefined;

    var bytes_per_round: usize = 0;
    for (0..corpus.cases.len) |case_index| {
        bytes_per_round += (try buildCase(case_index, @intCast(case_index), &packet, &compression)).len;
    }

    const start = std.Io.Clock.awake.now(io).nanoseconds;
    var checksum: usize = 0;
    for (0..build_rounds) |round| {
        for (0..corpus.cases.len) |case_index| {
            const id: u16 = @truncate(round * corpus.cases.len + case_index);
            const wire = try buildCase(case_index, id, &packet, &compression);
            checksum +%= wire.len + wire[wire.len - 1];
            std.mem.doNotOptimizeAway(packet);
        }
    }
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
    std.mem.doNotOptimizeAway(checksum);
    report(
        "core.build_real_corpus",
        build_rounds * corpus.cases.len,
        build_rounds * bytes_per_round,
        elapsed,
    );
}

fn buildCase(case_index: usize, id: u16, packet: []u8, compression: []dns.CompressionEntry) ![]const u8 {
    var flags: dns.Flags = .{
        .response = true,
        .recursion_desired = true,
        .recursion_available = true,
    };
    if (case_index == 8) flags.authenticated_data = true;
    if (case_index == 10) flags.rcode_low = 3;
    if (case_index == 11) {
        flags.authoritative = true;
        flags.authenticated_data = true;
        flags.recursion_desired = false;
        flags.recursion_available = false;
    }
    if (case_index == 12) {
        flags.recursion_desired = false;
        flags.recursion_available = false;
    }

    var b = try dns.Builder.init(packet, compression, id, flags);
    switch (case_index) {
        0 => {
            try b.addQuestion("cloudflare.com", .A, .IN);
            try b.addA(.answer, "cloudflare.com", 300, .{ 104, 16, 132, 229 });
            try b.addA(.answer, "cloudflare.com", 300, .{ 104, 16, 133, 229 });
        },
        1 => {
            try b.addQuestion("cloudflare.com", .AAAA, .IN);
            try b.addAAAA(.answer, "cloudflare.com", 300, .{ 0x26, 0x06, 0x47, 0x00 } ++ .{0} ** 8 ++ .{ 0x68, 0x10, 0x85, 0xe5 });
            try b.addAAAA(.answer, "cloudflare.com", 300, .{ 0x26, 0x06, 0x47, 0x00 } ++ .{0} ** 8 ++ .{ 0x68, 0x10, 0x84, 0xe5 });
        },
        2 => {
            try b.addQuestion("cloudflare.com", .NS, .IN);
            inline for (.{ "ns7.cloudflare.com", "ns6.cloudflare.com", "ns3.cloudflare.com", "ns5.cloudflare.com", "ns4.cloudflare.com" }) |target| {
                try b.addNameRecord(.answer, "cloudflare.com", .NS, 21600, target);
            }
        },
        3 => {
            try b.addQuestion("cloudflare.com", .CAA, .IN);
            try b.addCaa(.answer, "cloudflare.com", 1, 0, "issuewild", "comodoca.com");
            try b.addCaa(.answer, "cloudflare.com", 1, 0, "issue", "letsencrypt.org");
            try b.addCaa(.answer, "cloudflare.com", 1, 0, "issue", "comodoca.com");
            try b.addCaa(.answer, "cloudflare.com", 1, 0, "issuewild", "letsencrypt.org");
            try b.addCaa(.answer, "cloudflare.com", 1, 0, "issue", "ssl.com");
        },
        4 => {
            try b.addQuestion("status.openai.com", .A, .IN);
            try b.addNameRecord(.answer, "status.openai.com", .CNAME, 300, "cname.vercel-dns.com");
            try b.addA(.answer, "cname.vercel-dns.com", 300, .{ 66, 33, 60, 194 });
            try b.addA(.answer, "cname.vercel-dns.com", 300, .{ 76, 76, 21, 93 });
        },
        5 => {
            try b.addQuestion("gmail.com", .MX, .IN);
            try b.addMx(.answer, "gmail.com", 11, 20, "alt2.gmail-smtp-in.l.google.com");
            try b.addMx(.answer, "gmail.com", 11, 10, "alt1.gmail-smtp-in.l.google.com");
            try b.addMx(.answer, "gmail.com", 11, 5, "gmail-smtp-in.l.google.com");
            try b.addMx(.answer, "gmail.com", 11, 40, "alt4.gmail-smtp-in.l.google.com");
            try b.addMx(.answer, "gmail.com", 11, 30, "alt3.gmail-smtp-in.l.google.com");
        },
        6 => {
            try b.addQuestion("chatgpt.com", .TXT, .IN);
            try b.addTxt(.answer, "chatgpt.com", 300, &.{"cerner-client-id=ff69e1b6-5936-420e-92dd-f14f67869424"});
            try b.addTxt(.answer, "chatgpt.com", 300, &.{"google-site-verification=3p_zWfTXlQ4Mbxvq51ylW59LjgneYCB_vXpS-DLIEwM"});
            try b.addTxt(.answer, "chatgpt.com", 300, &.{"google-site-verification=HJikIAHI_Z6zkRXg-TWAceem39v2AhOSwPwUWaTNt9E"});
            try b.addTxt(.answer, "chatgpt.com", 300, &.{"google-site-verification=qz8yKZH1f2h4Dl7S-nRAo0immoInmiosRhyjUxXuUOs"});
        },
        7 => {
            try b.addQuestion("dns.google", .TXT, .IN);
            try b.addTxt(.answer, "dns.google", 300, &.{"v=spf1 -all"});
            try b.addTxt(.answer, "dns.google", 300, &.{"https://xkcd.com/1361/"});
        },
        8 => {
            try b.addQuestion("example.com", .DS, .IN);
            try b.addDs(.answer, "example.com", 14054, 2371, 13, 2, &example_ds_digest);
        },
        9 => {
            try b.addQuestion("example.com", .CNAME, .IN);
            try addExampleSoa(&b);
        },
        10 => {
            try b.addQuestion("bench-nx-20260820.example.com", .A, .IN);
            try addExampleSoa(&b);
        },
        11 => {
            try b.addQuestion(".", .DNSKEY, .IN);
            inline for (root_dnskey_rdatas) |rdata| {
                try b.addRawRecord(.answer, ".", .DNSKEY, .IN, 3600, rdata);
            }
        },
        12 => {
            try b.addQuestion("example.com", .A, .IN);
            inline for (com_servers) |server| {
                try b.addNameRecord(.authority, "com", .NS, 172800, server.name);
            }
            try b.addDs(.authority, "com", 86400, 19718, 13, 2, &com_ds_digest);
            inline for (com_servers) |server| {
                try b.addA(.additional, server.name, 172800, server.ipv4);
                try b.addAAAA(.additional, server.name, 172800, server.ipv6);
            }
        },
        else => unreachable,
    }
    const edns_flags: dns.edns.Flags = if (case_index >= 11) .{ .dnssec_ok = true } else .{};
    try b.addOpt(1232, 0, 0, edns_flags, &.{});
    return b.finish();
}

fn addExampleSoa(b: *dns.Builder) !void {
    try b.addSoa(
        .authority,
        "example.com",
        1720,
        "elliott.ns.cloudflare.com",
        "dns.cloudflare.com",
        2411783310,
        10000,
        2400,
        604800,
        1800,
    );
}

const root_dnskey_rdatas = [_][]const u8{
    @embedFile("corpus/root_dnskey_1.rdata"),
    @embedFile("corpus/root_dnskey_2.rdata"),
    @embedFile("corpus/root_dnskey_3.rdata"),
};

const ComServer = struct {
    name: []const u8,
    ipv4: [4]u8,
    ipv6: [16]u8,
};

const com_servers = [_]ComServer{
    .{ .name = "a.gtld-servers.net", .ipv4 = .{ 192, 5, 6, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x03, 0xa8, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x30 } },
    .{ .name = "b.gtld-servers.net", .ipv4 = .{ 192, 33, 14, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x03, 0x23, 0x1d, 0, 0, 0, 0, 0, 0, 0, 0x02, 0, 0x30 } },
    .{ .name = "c.gtld-servers.net", .ipv4 = .{ 192, 26, 92, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x03, 0x83, 0xeb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30 } },
    .{ .name = "d.gtld-servers.net", .ipv4 = .{ 192, 31, 80, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x00, 0x85, 0x6e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30 } },
    .{ .name = "e.gtld-servers.net", .ipv4 = .{ 192, 12, 94, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x02, 0x1c, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30 } },
    .{ .name = "f.gtld-servers.net", .ipv4 = .{ 192, 35, 51, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x03, 0xd4, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30 } },
    .{ .name = "g.gtld-servers.net", .ipv4 = .{ 192, 42, 93, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x03, 0xee, 0xa3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30 } },
    .{ .name = "h.gtld-servers.net", .ipv4 = .{ 192, 54, 112, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x02, 0x08, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30 } },
    .{ .name = "i.gtld-servers.net", .ipv4 = .{ 192, 43, 172, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x03, 0x39, 0xc1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30 } },
    .{ .name = "j.gtld-servers.net", .ipv4 = .{ 192, 48, 79, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x02, 0x70, 0x94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30 } },
    .{ .name = "k.gtld-servers.net", .ipv4 = .{ 192, 52, 178, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x03, 0x0d, 0x2d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30 } },
    .{ .name = "l.gtld-servers.net", .ipv4 = .{ 192, 41, 162, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x00, 0xd9, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30 } },
    .{ .name = "m.gtld-servers.net", .ipv4 = .{ 192, 55, 83, 30 }, .ipv6 = .{ 0x20, 0x01, 0x05, 0x01, 0xb1, 0xf9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30 } },
};

const com_ds_digest = [_]u8{
    0x8a, 0xcb, 0xb0, 0xcd, 0x28, 0xf4, 0x12, 0x50,
    0xa8, 0x0a, 0x49, 0x13, 0x89, 0x42, 0x4d, 0x34,
    0x15, 0x22, 0xd9, 0x46, 0xb0, 0xda, 0x0c, 0x02,
    0x91, 0xf2, 0xd3, 0xd7, 0x71, 0xd7, 0x80, 0x5a,
};

const example_ds_digest = [_]u8{
    0xc9, 0x88, 0xec, 0x42, 0x3e, 0x38, 0x80, 0xeb,
    0x8d, 0xd8, 0xa4, 0x6f, 0xe0, 0x6c, 0xa2, 0x30,
    0xee, 0x23, 0xf3, 0x5b, 0x57, 0x8d, 0x64, 0xe7,
    0x8b, 0x29, 0xc3, 0xe1, 0xc8, 0x3d, 0x24, 0x5a,
};

fn report(name: []const u8, operations: usize, bytes: usize, elapsed_ns: i96) void {
    const elapsed: u64 = @intCast(elapsed_ns);
    const ops_u64: u64 = @intCast(operations);
    const bytes_u64: u64 = @intCast(bytes);
    const ns_per_op = elapsed / @max(ops_u64, 1);
    const ops_per_s = ops_u64 * std.time.ns_per_s / @max(elapsed, 1);
    const bytes_per_s = bytes_u64 * std.time.ns_per_s / @max(elapsed, 1);
    const mib_per_s = bytes_per_s / (1024 * 1024);
    std.debug.print(
        "{s}: {d} ns/op, {d} ops/s, {d} MiB/s ({d} ops, {d} bytes, {d} ns)\n",
        .{ name, ns_per_op, ops_per_s, mib_per_s, operations, bytes, elapsed },
    );
}

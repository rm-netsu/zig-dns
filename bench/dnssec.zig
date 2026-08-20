const std = @import("std");
const dns = @import("dns");

const canonical_iterations = 500_000;
const verify_iterations = 20_000;
const digest_iterations = 500_000;
const nsec3_iterations = 200_000;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var fixture = try Fixture.init();

    try fixture.benchCanonical(io);
    try fixture.benchVerify(io);
    try fixture.benchDigest(io);
    try fixture.benchNsec3(io);

    std.debug.print("dnssec.workspace: {d} bytes caller storage, {d} bytes descriptor\n", .{
        fixture.signed_data.len + fixture.order.len * @sizeOf(u16) + fixture.compare.len,
        @sizeOf(dns.dnssec.verify.Workspace),
    });
}

const Fixture = struct {
    packet: [1024]u8 = undefined,
    packet_len: usize,
    rrset_records: [1]dns.Record,
    rrsig: dns.Record,
    dnskey: dns.Record,
    signed_data: [512]u8 = undefined,
    order: [1]u16 = undefined,
    compare: [256]u8 = undefined,
    digest: [48]u8 = undefined,

    fn init() !Fixture {
        var fixture: Fixture = undefined;
        var compression: [32]dns.CompressionEntry = undefined;
        var public_key_storage: [32]u8 = undefined;
        const public_key = try decodeBase64("l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=", &public_key_storage);
        var signature_storage: [64]u8 = undefined;
        const signature = try decodeBase64("oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==", &signature_storage);

        var b = try dns.Builder.init(&fixture.packet, &compression, 1, .{ .response = true });
        try b.addMx(.answer, "example.com", 3600, 10, "mail.example.com");
        var signer_buf: [dns.name.Name.max_wire_len]u8 = undefined;
        const signer_wire = try dns.name.writePresentationWire("example.com", &signer_buf);
        var rw = try b.beginRecord(.answer, "example.com", .RRSIG, .IN, 3600);
        try rw.writeU16(@intFromEnum(dns.Type.MX));
        try rw.writeByte(15);
        try rw.writeByte(2);
        try rw.writeU32(3600);
        try rw.writeU32(1440021600);
        try rw.writeU32(1438207200);
        try rw.writeU16(3613);
        try rw.writeWireName(try dns.name.Uncompressed.init(signer_wire));
        try rw.writeBytes(signature);
        try rw.finish();
        try b.addDnskey(.additional, "example.com", 3600, 257, 15, public_key);
        const wire = try b.finish();
        fixture.packet_len = wire.len;

        // Rebind zero-copy views after the fixture has reached its final address.
        // `rebind` is called by each benchmark before timing.
        fixture.rrset_records = undefined;
        fixture.rrsig = undefined;
        fixture.dnskey = undefined;
        return fixture;
    }

    fn rebind(self: *Fixture) !dns.dnssec.Rrset {
        const m = try dns.Message.init(self.packet[0..self.packet_len]);
        var answers = try m.records(.answer);
        self.rrset_records[0] = (try answers.next()).?;
        self.rrsig = (try answers.next()).?;
        var additional = try m.records(.additional);
        self.dnskey = (try additional.next()).?;
        return dns.dnssec.Rrset.init(&self.rrset_records);
    }

    fn benchCanonical(self: *Fixture, io: std.Io) !void {
        const set = try self.rebind();
        const sig = try dns.rdata.rrsig(self.rrsig);
        const start = std.Io.Clock.awake.now(io).nanoseconds;
        var checksum: usize = 0;
        for (0..canonical_iterations) |_| {
            var writer = dns.dnssec.CanonicalWriter.init(&self.signed_data);
            try dns.dnssec.rrset.writeSignedData(&writer, sig, set, &self.order, &self.compare);
            const written = writer.written();
            checksum +%= written.len + written[written.len - 1];
            std.mem.doNotOptimizeAway(self.signed_data);
        }
        const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
        std.mem.doNotOptimizeAway(checksum);
        report("dnssec.canonical_signed_data", canonical_iterations, elapsed);
    }

    fn benchVerify(self: *Fixture, io: std.Io) !void {
        const set = try self.rebind();
        const start = std.Io.Clock.awake.now(io).nanoseconds;
        for (0..verify_iterations) |_| {
            try dns.dnssec.verify.verifyRrset(self.rrsig, self.dnskey, set, 1438207200, .{
                .signed_data = &self.signed_data,
                .order = &self.order,
                .compare = &self.compare,
            }, .{});
        }
        const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
        report("dnssec.verify_ed25519", verify_iterations, elapsed);
    }

    fn benchDigest(self: *Fixture, io: std.Io) !void {
        _ = try self.rebind();
        const start = std.Io.Clock.awake.now(io).nanoseconds;
        var checksum: u8 = 0;
        for (0..digest_iterations) |_| {
            const digest = try dns.dnssec.ds.digestDnskey(self.dnskey.name, self.dnskey.rdata, 2, &self.digest);
            checksum ^= digest[0];
            std.mem.doNotOptimizeAway(digest);
        }
        const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
        std.mem.doNotOptimizeAway(checksum);
        report("dnssec.ds_sha256", digest_iterations, elapsed);
    }

    fn benchNsec3(self: *Fixture, io: std.Io) !void {
        _ = try self.rebind();
        const params: dns.dnssec.denial.nsec3.Parameters = .{
            .hash_algorithm = 1,
            .iterations = 0,
            .salt = &.{},
        };
        const start = std.Io.Clock.awake.now(io).nanoseconds;
        var checksum: u8 = 0;
        for (0..nsec3_iterations) |_| {
            const hash = try dns.dnssec.denial.nsec3.hashName(self.rrset_records[0].name, params, 0);
            checksum ^= hash[0];
            std.mem.doNotOptimizeAway(hash);
        }
        const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
        std.mem.doNotOptimizeAway(checksum);
        report("dnssec.nsec3_sha1_iter0", nsec3_iterations, elapsed);
    }
};

fn decodeBase64(encoded: []const u8, out: []u8) ![]const u8 {
    const len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    if (len > out.len) return error.NoSpaceLeft;
    try std.base64.standard.Decoder.decode(out[0..len], encoded);
    return out[0..len];
}

fn report(name: []const u8, iterations: usize, elapsed_ns: i96) void {
    const elapsed: u64 = @intCast(elapsed_ns);
    const ns_per_op = elapsed / iterations;
    const ops_per_s = @as(u64, @intCast(iterations)) * std.time.ns_per_s / @max(elapsed, 1);
    std.debug.print("{s}: {d} ns/op, {d} ops/s ({d} iterations)\n", .{ name, ns_per_op, ops_per_s, iterations });
}

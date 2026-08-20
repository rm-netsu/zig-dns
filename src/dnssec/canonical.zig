const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");

pub const Error = name_mod.Error || error{
    NoSpace,
    InvalidRdata,
    RdataTooLong,
};

/// Allocation-free DNSSEC canonical RR writer.
///
/// Each record write is transactional with respect to the output position.
/// The caller owns the output buffer and may reuse the writer after NoSpace
/// or malformed-RDATA errors.
pub const Writer = struct {
    out: []u8,
    pos: usize = 0,

    pub fn init(out: []u8) Writer {
        return .{ .out = out };
    }

    pub fn reset(self: *Writer) void {
        self.pos = 0;
    }

    pub fn written(self: Writer) []const u8 {
        return self.out[0..self.pos];
    }

    /// Write one RFC 4034/3597 canonical RR using `original_ttl` instead of
    /// the TTL carried by the received RR.
    pub fn writeRecord(self: *Writer, rr: message.Record, original_ttl: u32) Error!void {
        const mark = self.pos;
        errdefer self.pos = mark;

        try self.writeCanonicalName(rr.name);
        try self.writeU16(@intFromEnum(rr.rr_type));
        try self.writeU16(@intFromEnum(rr.class));
        try self.writeU32(original_ttl);

        const rdlength_pos = self.pos;
        try self.writeU16(0);
        const rdata_start = self.pos;
        try self.writeCanonicalRdata(rr);
        const rdata_len = self.pos - rdata_start;
        if (rdata_len > std.math.maxInt(u16)) return error.RdataTooLong;
        std.mem.writeInt(u16, self.out[rdlength_pos..][0..2], @intCast(rdata_len), .big);
    }

    fn writeCanonicalRdata(self: *Writer, rr: message.Record) Error!void {
        switch (rr.rr_type) {
            // RFC 3597 section 7 retains pre-3597 DNSSEC downcasing rules for
            // these name-bearing RR types.
            .NS, .MD, .MF, .CNAME, .MB, .MG, .MR, .PTR, .DNAME => {
                const consumed = try self.writeNameAt(rr, 0, true);
                if (consumed != rr.rdata.len) return error.InvalidRdata;
            },
            .SOA => {
                var relative: usize = 0;
                relative += try self.writeNameAt(rr, relative, true);
                relative += try self.writeNameAt(rr, relative, true);
                if (rr.rdata.len - relative != 20) return error.InvalidRdata;
                try self.writeAll(rr.rdata[relative..]);
            },
            .MINFO, .RP => {
                var relative: usize = 0;
                relative += try self.writeNameAt(rr, relative, true);
                relative += try self.writeNameAt(rr, relative, true);
                if (relative != rr.rdata.len) return error.InvalidRdata;
            },
            .MX, .AFSDB, .RT, .KX => {
                if (rr.rdata.len < 3) return error.InvalidRdata;
                try self.writeAll(rr.rdata[0..2]);
                const consumed = try self.writeNameAt(rr, 2, true);
                if (2 + consumed != rr.rdata.len) return error.InvalidRdata;
            },
            .SIG => try self.writeSigLike(rr),
            .PX => {
                if (rr.rdata.len < 4) return error.InvalidRdata;
                try self.writeAll(rr.rdata[0..2]);
                var relative: usize = 2;
                relative += try self.writeNameAt(rr, relative, true);
                relative += try self.writeNameAt(rr, relative, true);
                if (relative != rr.rdata.len) return error.InvalidRdata;
            },
            .NXT => {
                const consumed = try self.writeNameAt(rr, 0, true);
                if (consumed >= rr.rdata.len) return error.InvalidRdata;
                try self.writeAll(rr.rdata[consumed..]);
            },
            .NAPTR => try self.writeNaptr(rr),
            .SRV => {
                if (rr.rdata.len < 7) return error.InvalidRdata;
                try self.writeAll(rr.rdata[0..6]);
                const consumed = try self.writeNameAt(rr, 6, true);
                if (6 + consumed != rr.rdata.len) return error.InvalidRdata;
            },
            .A6 => try self.writeA6(rr),

            // RFC 6840 section 5.1: unlike other post-RFC3597 record types,
            // the RRSIG signer name is lowercased in canonical form.
            .RRSIG => try self.writeRrsig(rr),

            // RFC 6840 section 5.1: the NSEC next-domain name is *not*
            // lowercased. RFC 4034 requires it to be uncompressed, so after
            // validating that invariant the entire RDATA is already in the
            // required canonical byte representation.
            .NSEC => {
                if (rr.rdata.len < 2) return error.InvalidRdata;
                const name_len = try uncompressedNameLen(rr, 0);
                if (name_len >= rr.rdata.len) return error.InvalidRdata;
                try self.writeAll(rr.rdata);
            },

            // RFC 3597: record types specified after RFC 3597 retain embedded
            // domain-name case in DNSSEC canonical form. Their specifications
            // prohibit compression for embedded names, so opaque copying is
            // intentional here (e.g. SVCB/HTTPS TargetName).
            else => try self.writeAll(rr.rdata),
        }
    }

    fn writeSigLike(self: *Writer, rr: message.Record) Error!void {
        if (rr.rdata.len < 19) return error.InvalidRdata;
        try self.writeAll(rr.rdata[0..18]);
        const consumed = try self.writeNameAt(rr, 18, true);
        const signature_off = 18 + consumed;
        if (signature_off > rr.rdata.len) return error.InvalidRdata;
        try self.writeAll(rr.rdata[signature_off..]);
    }

    fn writeRrsig(self: *Writer, rr: message.Record) Error!void {
        if (rr.rdata.len < 19) return error.InvalidRdata;
        const signer_len = try uncompressedNameLen(rr, 18);
        try self.writeAll(rr.rdata[0..18]);
        _ = try self.writeNameAt(rr, 18, true);
        try self.writeAll(rr.rdata[18 + signer_len ..]);
    }

    fn writeNaptr(self: *Writer, rr: message.Record) Error!void {
        if (rr.rdata.len < 8) return error.InvalidRdata;
        try self.writeAll(rr.rdata[0..4]);
        var relative: usize = 4;
        for (0..3) |_| {
            const char_len = try charStringLen(rr.rdata, relative);
            try self.writeAll(rr.rdata[relative..][0..char_len]);
            relative += char_len;
        }
        const consumed = try self.writeNameAt(rr, relative, true);
        if (relative + consumed != rr.rdata.len) return error.InvalidRdata;
    }

    fn writeA6(self: *Writer, rr: message.Record) Error!void {
        if (rr.rdata.len < 1) return error.InvalidRdata;
        const prefix_len = rr.rdata[0];
        if (prefix_len > 128) return error.InvalidRdata;
        const suffix_len: usize = (128 - @as(usize, prefix_len) + 7) / 8;
        const fixed_len = 1 + suffix_len;
        if (fixed_len > rr.rdata.len) return error.InvalidRdata;
        try self.writeAll(rr.rdata[0..fixed_len]);
        if (prefix_len == 0) {
            if (fixed_len != rr.rdata.len) return error.InvalidRdata;
            return;
        }
        const consumed = try self.writeNameAt(rr, fixed_len, true);
        if (fixed_len + consumed != rr.rdata.len) return error.InvalidRdata;
    }

    fn writeNameAt(self: *Writer, rr: message.Record, relative: usize, canonical_case: bool) Error!usize {
        if (relative >= rr.rdata.len) return error.InvalidRdata;
        const absolute = @as(usize, rr.rdata_offset) + relative;
        const n = try name_mod.Name.init(rr.packet, absolute);
        const consumed = try n.consumed();
        if (consumed > rr.rdata.len - relative) return error.InvalidRdata;
        if (canonical_case) {
            try self.writeCanonicalName(n);
        } else {
            try self.writeName(n);
        }
        return consumed;
    }

    fn writeCanonicalName(self: *Writer, n: name_mod.Name) Error!void {
        var buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const wire = try n.writeCanonicalWire(&buf);
        try self.writeAll(wire);
    }

    fn writeName(self: *Writer, n: name_mod.Name) Error!void {
        var buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const wire = try n.writeWire(&buf);
        try self.writeAll(wire);
    }

    fn writeAll(self: *Writer, bytes: []const u8) Error!void {
        if (bytes.len > self.out.len - self.pos) return error.NoSpace;
        @memcpy(self.out[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn writeU16(self: *Writer, value: u16) Error!void {
        if (self.out.len - self.pos < 2) return error.NoSpace;
        std.mem.writeInt(u16, self.out[self.pos..][0..2], value, .big);
        self.pos += 2;
    }

    fn writeU32(self: *Writer, value: u32) Error!void {
        if (self.out.len - self.pos < 4) return error.NoSpace;
        std.mem.writeInt(u32, self.out[self.pos..][0..4], value, .big);
        self.pos += 4;
    }
};

fn charStringLen(bytes: []const u8, relative: usize) Error!usize {
    if (relative >= bytes.len) return error.InvalidRdata;
    const len: usize = bytes[relative];
    if (len > bytes.len - relative - 1) return error.InvalidRdata;
    return 1 + len;
}

fn uncompressedNameLen(rr: message.Record, relative: usize) Error!usize {
    if (relative >= rr.rdata.len) return error.InvalidRdata;
    const absolute = @as(usize, rr.rdata_offset) + relative;
    const len = try name_mod.uncompressedConsumedLen(rr.packet, absolute);
    if (len > rr.rdata.len - relative) return error.InvalidRdata;
    return len;
}

fn firstRecord(packet: []const u8) !message.Record {
    const m = try message.Message.init(packet);
    var it = try m.records(.answer);
    return (try it.next()).?;
}

test "canonical RR expands CNAME RDATA, lowercases names, and overrides TTL" {
    const packet = [_]u8{
        0,  1,   0x80, 0,    0,  0,   0,   1,   0,   0,   0,   0,
        3,  'W', 'W',  'W',  7,  'E', 'x', 'a', 'm', 'p', 'l', 'e',
        3,  'C', 'O',  'M',  0,  0,   5,   0,   1,   0,   0,   0,
        60, 0,   2,    0xc0, 12,
    };
    const rr = try firstRecord(&packet);
    var out: [128]u8 = undefined;
    var w = Writer.init(&out);
    try w.writeRecord(rr, 3600);

    const expected_name = [_]u8{ 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const got = w.written();
    try std.testing.expectEqualSlices(u8, &expected_name, got[0..expected_name.len]);
    try std.testing.expectEqual(@as(u16, 5), std.mem.readInt(u16, got[expected_name.len..][0..2], .big));
    try std.testing.expectEqual(@as(u32, 3600), std.mem.readInt(u32, got[expected_name.len + 4 ..][0..4], .big));
    try std.testing.expectEqual(@as(u16, expected_name.len), std.mem.readInt(u16, got[expected_name.len + 8 ..][0..2], .big));
    try std.testing.expectEqualSlices(u8, &expected_name, got[expected_name.len + 10 ..]);
}

test "canonical RRSIG lowercases signer while NSEC preserves next-domain case" {
    const rrsig_packet = [_]u8{
        0,    1,   0x80, 0,   0,   0,   0,    1,   0,   0, 0,   0,
        7,    'E', 'X',  'A', 'M', 'P', 'L',  'E', 0,   0, 46,  0,
        1,    0,   0,    0,   1,   0,   31,   0,   1,   8, 1,   0,
        0,    0,   1,    0,   0,   0,   2,    0,   0,   0, 1,   0x12,
        0x34, 7,   'S',  'I', 'G', 'N', 'E',  'R', 'S', 7, 'E', 'X',
        'A',  'M', 'P',  'L', 'E', 0,   0xaa,
    };
    const rr = try firstRecord(&rrsig_packet);
    var out: [128]u8 = undefined;
    var w = Writer.init(&out);
    try w.writeRecord(rr, 1);
    const got = w.written();
    try std.testing.expect(std.mem.indexOf(u8, got, &.{ 7, 's', 'i', 'g', 'n', 'e', 'r', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }) != null);

    const nsec_packet = [_]u8{
        0, 1,   0x80, 0,    0,   0,   0,   1,   0,   0,   0,   0,
        7, 'E', 'X',  'A',  'M', 'P', 'L', 'E', 0,   0,   47,  0,
        1, 0,   0,    0,    1,   0,   12,  4,   'N', 'e', 'X', 't',
        0, 0,   4,    0x40, 0,   0,   0,
    };
    const nsec_rr = try firstRecord(&nsec_packet);
    w.reset();
    try w.writeRecord(nsec_rr, 1);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), &.{ 4, 'N', 'e', 'X', 't', 0 }) != null);
}

test "post-RFC3597 SVCB TargetName case is preserved" {
    const packet = [_]u8{
        0,   1,   0x80, 0,   0,   0,   0,   1,   0, 0, 0,   0,
        7,   'E', 'X',  'A', 'M', 'P', 'L', 'E', 0, 0, 64,  0,
        1,   0,   0,    0,   1,   0,   10,  0,   1, 3, 'S', 'v',
        'C', 3,   'N',  'E', 'T', 0,
    };
    const rr = try firstRecord(&packet);
    var out: [128]u8 = undefined;
    var w = Writer.init(&out);
    try w.writeRecord(rr, 1);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), &.{ 3, 'S', 'v', 'C', 3, 'N', 'E', 'T', 0 }) != null);
}

test "canonical record write rolls back on NoSpace" {
    const packet = [_]u8{
        0, 1,   0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0,
        1, 'A', 0,    0, 1, 0, 1, 0, 0, 0, 1, 0,
        4, 1,   2,    3, 4,
    };
    const rr = try firstRecord(&packet);
    var out: [8]u8 = undefined;
    var w = Writer.init(&out);
    try std.testing.expectError(error.NoSpace, w.writeRecord(rr, 1));
    try std.testing.expectEqual(@as(usize, 0), w.pos);
}

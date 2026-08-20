const std = @import("std");
const types = @import("types.zig");
const name_mod = @import("name.zig");
const edns = @import("edns.zig");

pub const Error = name_mod.Error || error{ NoSpace, TooManyRecords, SectionOrder, RecordOpen, NoRecordOpen, RdataTooLong };

pub const CompressionEntry = struct { hash: u64, offset: u16 };

pub const Builder = struct {
    out: []u8,
    pos: usize = types.Header.wire_len,
    header: types.Header,
    compression: []CompressionEntry,
    compression_len: usize = 0,
    phase: Phase = .questions,
    record_open: bool = false,

    const Phase = enum(u2) { questions, answer, authority, additional };

    pub fn init(out: []u8, compression: []CompressionEntry, id: u16, flags: types.Flags) Error!Builder {
        if (out.len < types.Header.wire_len) return error.NoSpace;
        @memset(out[0..types.Header.wire_len], 0);
        return .{
            .out = out[0..@min(out.len, std.math.maxInt(u16))],
            .compression = compression,
            .header = .{ .id = id, .flags = flags, .question_count = 0, .answer_count = 0, .authority_count = 0, .additional_count = 0 },
        };
    }

    const Checkpoint = struct { pos: usize, compression_len: usize, phase: Phase };
    fn checkpoint(self: *const Builder) Checkpoint {
        return .{ .pos = self.pos, .compression_len = self.compression_len, .phase = self.phase };
    }
    fn rollback(self: *Builder, cp: Checkpoint) void {
        self.pos = cp.pos;
        self.compression_len = cp.compression_len;
        self.phase = cp.phase;
        self.record_open = false;
    }

    /// Update the response TC bit without disturbing transactional builder state.
    /// Useful to turn a bounded response into an explicit truncation after a
    /// complete RRset failed to fit.
    pub fn setTruncated(self: *Builder, truncated: bool) void {
        self.header.flags.truncated = truncated;
    }

    pub fn addQuestionWire(self: *Builder, qname: name_mod.Uncompressed, qtype: types.Type, qclass: types.Class) Error!void {
        if (self.record_open) return error.RecordOpen;
        if (self.phase != .questions) return error.SectionOrder;
        const cp = self.checkpoint();
        errdefer self.rollback(cp);
        try self.writeBytes(qname.bytes);
        try self.writeU16(@intFromEnum(qtype));
        try self.writeU16(@intFromEnum(qclass));
        self.header.question_count = std.math.add(u16, self.header.question_count, 1) catch return error.TooManyRecords;
    }

    pub fn addQuestion(self: *Builder, qname: []const u8, qtype: types.Type, qclass: types.Class) Error!void {
        if (self.record_open) return error.RecordOpen;
        if (self.phase != .questions) return error.SectionOrder;
        const cp = self.checkpoint();
        errdefer self.rollback(cp);
        try self.writeName(qname);
        try self.writeU16(@intFromEnum(qtype));
        try self.writeU16(@intFromEnum(qclass));
        self.header.question_count = std.math.add(u16, self.header.question_count, 1) catch return error.TooManyRecords;
    }

    pub fn beginRecord(self: *Builder, section: types.Section, owner: []const u8, rr_type: types.Type, class: types.Class, ttl: u32) Error!RecordWriter {
        if (self.record_open) return error.RecordOpen;
        const wanted: Phase = switch (section) {
            .answer => .answer,
            .authority => .authority,
            .additional => .additional,
        };
        if (@intFromEnum(wanted) < @intFromEnum(self.phase)) return error.SectionOrder;
        const cp = self.checkpoint();
        errdefer self.rollback(cp);
        self.phase = wanted;
        try self.writeName(owner);
        try self.writeU16(@intFromEnum(rr_type));
        try self.writeU16(@intFromEnum(class));
        try self.writeU32(ttl);
        const len_offset = self.pos;
        try self.writeU16(0);
        self.record_open = true;
        return .{ .builder = self, .section = section, .len_offset = len_offset, .rdata_start = self.pos, .checkpoint = cp };
    }

    pub fn beginRecordWire(self: *Builder, section: types.Section, owner: name_mod.Uncompressed, rr_type: types.Type, class: types.Class, ttl: u32) Error!RecordWriter {
        if (self.record_open) return error.RecordOpen;
        const wanted: Phase = switch (section) {
            .answer => .answer,
            .authority => .authority,
            .additional => .additional,
        };
        if (@intFromEnum(wanted) < @intFromEnum(self.phase)) return error.SectionOrder;
        const cp = self.checkpoint();
        errdefer self.rollback(cp);
        self.phase = wanted;
        try self.writeBytes(owner.bytes);
        try self.writeU16(@intFromEnum(rr_type));
        try self.writeU16(@intFromEnum(class));
        try self.writeU32(ttl);
        const len_offset = self.pos;
        try self.writeU16(0);
        self.record_open = true;
        return .{ .builder = self, .section = section, .len_offset = len_offset, .rdata_start = self.pos, .checkpoint = cp };
    }

    pub fn addRawRecordWire(self: *Builder, section: types.Section, owner: name_mod.Uncompressed, rr_type: types.Type, class: types.Class, ttl: u32, rdata: []const u8) Error!void {
        var w = try self.beginRecordWire(section, owner, rr_type, class, ttl);
        errdefer w.abort();
        try w.writeBytes(rdata);
        try w.finish();
    }

    pub fn addRawRecord(self: *Builder, section: types.Section, owner: []const u8, rr_type: types.Type, class: types.Class, ttl: u32, rdata: []const u8) Error!void {
        var w = try self.beginRecord(section, owner, rr_type, class, ttl);
        errdefer w.abort();
        try w.writeBytes(rdata);
        try w.finish();
    }

    pub fn addA(self: *Builder, section: types.Section, owner: []const u8, ttl: u32, addr: [4]u8) Error!void {
        try self.addRawRecord(section, owner, .A, .IN, ttl, &addr);
    }

    pub fn addAAAA(self: *Builder, section: types.Section, owner: []const u8, ttl: u32, addr: [16]u8) Error!void {
        try self.addRawRecord(section, owner, .AAAA, .IN, ttl, &addr);
    }

    pub fn addNameRecord(self: *Builder, section: types.Section, owner: []const u8, rr_type: types.Type, ttl: u32, target: []const u8) Error!void {
        var w = try self.beginRecord(section, owner, rr_type, .IN, ttl);
        errdefer w.abort();
        if (rr_type == .DNAME) {
            // RFC 6672 section 2.1: DNAME target names are never compressed.
            var wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
            const wire = try name_mod.writePresentationWire(target, &wire_buf);
            try w.writeWireName(try name_mod.Uncompressed.init(wire));
        } else {
            try w.writeName(target);
        }
        try w.finish();
    }

    pub fn addSoa(self: *Builder, section: types.Section, owner: []const u8, ttl: u32, mname: []const u8, rname: []const u8, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32) Error!void {
        var w = try self.beginRecord(section, owner, .SOA, .IN, ttl);
        errdefer w.abort();
        try w.writeName(mname);
        try w.writeName(rname);
        try w.writeU32(serial);
        try w.writeU32(refresh);
        try w.writeU32(retry);
        try w.writeU32(expire);
        try w.writeU32(minimum);
        try w.finish();
    }

    pub fn addMx(self: *Builder, section: types.Section, owner: []const u8, ttl: u32, preference: u16, exchange: []const u8) Error!void {
        var w = try self.beginRecord(section, owner, .MX, .IN, ttl);
        errdefer w.abort();
        try w.writeU16(preference);
        try w.writeName(exchange);
        try w.finish();
    }

    pub fn addSrv(self: *Builder, section: types.Section, owner: []const u8, ttl: u32, priority: u16, weight: u16, port: u16, target: []const u8) Error!void {
        var w = try self.beginRecord(section, owner, .SRV, .IN, ttl);
        errdefer w.abort();
        try w.writeU16(priority);
        try w.writeU16(weight);
        try w.writeU16(port);
        try w.writeName(target);
        try w.finish();
    }

    pub fn addTxt(self: *Builder, section: types.Section, owner: []const u8, ttl: u32, strings: []const []const u8) Error!void {
        var w = try self.beginRecord(section, owner, .TXT, .IN, ttl);
        errdefer w.abort();
        for (strings) |s| {
            if (s.len > 255) return error.RdataTooLong;
            try w.writeByte(@intCast(s.len));
            try w.writeBytes(s);
        }
        try w.finish();
    }

    pub fn addCaa(self: *Builder, section: types.Section, owner: []const u8, ttl: u32, flags: u8, tag: []const u8, value: []const u8) Error!void {
        if (tag.len > 255) return error.RdataTooLong;
        var w = try self.beginRecord(section, owner, .CAA, .IN, ttl);
        errdefer w.abort();
        try w.writeByte(flags);
        try w.writeByte(@intCast(tag.len));
        try w.writeBytes(tag);
        try w.writeBytes(value);
        try w.finish();
    }

    pub fn addDs(self: *Builder, section: types.Section, owner: []const u8, ttl: u32, key_tag: u16, algorithm: u8, digest_type: u8, digest: []const u8) Error!void {
        if (digest.len == 0) return error.RdataTooLong;
        var w = try self.beginRecord(section, owner, .DS, .IN, ttl);
        errdefer w.abort();
        try w.writeU16(key_tag);
        try w.writeByte(algorithm);
        try w.writeByte(digest_type);
        try w.writeBytes(digest);
        try w.finish();
    }

    pub fn addDnskey(self: *Builder, section: types.Section, owner: []const u8, ttl: u32, flags: u16, algorithm: u8, public_key: []const u8) Error!void {
        if (public_key.len == 0) return error.RdataTooLong;
        var w = try self.beginRecord(section, owner, .DNSKEY, .IN, ttl);
        errdefer w.abort();
        try w.writeU16(flags);
        try w.writeByte(3);
        try w.writeByte(algorithm);
        try w.writeBytes(public_key);
        try w.finish();
    }

    pub fn addTlsa(self: *Builder, section: types.Section, owner: []const u8, ttl: u32, usage: u8, selector: u8, matching_type: u8, association_data: []const u8) Error!void {
        var w = try self.beginRecord(section, owner, .TLSA, .IN, ttl);
        errdefer w.abort();
        try w.writeByte(usage);
        try w.writeByte(selector);
        try w.writeByte(matching_type);
        try w.writeBytes(association_data);
        try w.finish();
    }

    pub fn addSshfp(self: *Builder, section: types.Section, owner: []const u8, ttl: u32, algorithm: u8, fingerprint_type: u8, fingerprint: []const u8) Error!void {
        var w = try self.beginRecord(section, owner, .SSHFP, .IN, ttl);
        errdefer w.abort();
        try w.writeByte(algorithm);
        try w.writeByte(fingerprint_type);
        try w.writeBytes(fingerprint);
        try w.finish();
    }

    pub fn addUri(self: *Builder, section: types.Section, owner: []const u8, class: types.Class, ttl: u32, priority: u16, weight: u16, target: []const u8) Error!void {
        if (target.len == 0) return error.RdataTooLong;
        var w = try self.beginRecord(section, owner, .URI, class, ttl);
        errdefer w.abort();
        try w.writeU16(priority);
        try w.writeU16(weight);
        try w.writeBytes(target);
        try w.finish();
    }

    pub fn addZonemd(self: *Builder, section: types.Section, owner: []const u8, class: types.Class, ttl: u32, serial: u32, scheme: u8, hash_algorithm: u8, digest: []const u8) Error!void {
        if (digest.len < 12) return error.RdataTooLong;
        if ((hash_algorithm == 1 and digest.len != 48) or (hash_algorithm == 2 and digest.len != 64)) return error.RdataTooLong;
        var w = try self.beginRecord(section, owner, .ZONEMD, class, ttl);
        errdefer w.abort();
        try w.writeU32(serial);
        try w.writeByte(scheme);
        try w.writeByte(hash_algorithm);
        try w.writeBytes(digest);
        try w.finish();
    }

    pub fn addSvcb(self: *Builder, section: types.Section, owner: []const u8, rr_type: types.Type, ttl: u32, priority: u16, target: name_mod.Uncompressed, params: []const u8) Error!void {
        if (rr_type != .SVCB and rr_type != .HTTPS) return error.RdataTooLong;
        var w = try self.beginRecord(section, owner, rr_type, .IN, ttl);
        errdefer w.abort();
        try w.writeU16(priority);
        // RFC 9460 TargetName is never compressed.
        try w.writeWireName(target);
        try w.writeBytes(params);
        try w.finish();
    }

    pub fn addOpt(self: *Builder, udp_payload_size: u16, extended_rcode: u8, version: u8, flags: edns.Flags, options: []const u8) Error!void {
        const ttl: u32 = (@as(u32, extended_rcode) << 24) | (@as(u32, version) << 16) | flags.toInt();
        try self.addRawRecord(.additional, ".", .OPT, @enumFromInt(udp_payload_size), ttl, options);
    }

    pub fn finish(self: *Builder) Error![]const u8 {
        if (self.record_open) return error.RecordOpen;
        try self.header.write(self.out[0..types.Header.wire_len]);
        return self.out[0..self.pos];
    }

    fn writeName(self: *Builder, presentation: []const u8) Error!void {
        try name_mod.validatePresentation(presentation);
        if (presentation.len == 0 or std.mem.eql(u8, presentation, ".")) return self.writeByte(0);
        const clean = if (presentation[presentation.len - 1] == '.') presentation[0 .. presentation.len - 1] else presentation;
        var start: usize = 0;
        while (start < clean.len) {
            const suffix = clean[start..];
            if (self.findCompression(suffix)) |target| {
                if (self.pos + 2 > self.out.len) return error.NoSpace;
                const ptr: u16 = 0xc000 | target;
                try self.writeU16(ptr);
                return;
            }
            const dot = std.mem.indexOfScalarPos(u8, clean, start, '.') orelse clean.len;
            const label = clean[start..dot];
            if (label.len == 0) return error.InvalidPresentation;
            if (label.len > 63) return error.LabelTooLong;
            self.rememberSuffix(suffix);
            try self.writeByte(@intCast(label.len));
            try self.writeBytes(label);
            start = if (dot == clean.len) clean.len else dot + 1;
        }
        try self.writeByte(0);
    }

    fn findCompression(self: *Builder, suffix: []const u8) ?u16 {
        const h = suffixHash(suffix);
        var i: usize = self.compression_len;
        var tmp: [name_mod.Name.max_presentation_len]u8 = undefined;
        while (i > 0) {
            i -= 1;
            const e = self.compression[i];
            if (e.hash != h) continue;
            const n = name_mod.Name.init(self.out[0..self.pos], e.offset) catch continue;
            const p = n.writePresentation(&tmp) catch continue;
            if (std.ascii.eqlIgnoreCase(p, suffix)) return e.offset;
        }
        return null;
    }

    fn rememberSuffix(self: *Builder, suffix: []const u8) void {
        if (self.compression_len == self.compression.len or self.pos >= 0x4000) return;
        self.compression[self.compression_len] = .{ .hash = suffixHash(suffix), .offset = @intCast(self.pos) };
        self.compression_len += 1;
    }

    fn writeByte(self: *Builder, value: u8) Error!void {
        if (self.pos >= self.out.len) return error.NoSpace;
        self.out[self.pos] = value;
        self.pos += 1;
    }
    fn writeBytes(self: *Builder, value: []const u8) Error!void {
        if (self.pos + value.len > self.out.len) return error.NoSpace;
        @memcpy(self.out[self.pos..][0..value.len], value);
        self.pos += value.len;
    }
    fn writeU16(self: *Builder, value: u16) Error!void {
        if (self.pos + 2 > self.out.len) return error.NoSpace;
        std.mem.writeInt(u16, self.out[self.pos..][0..2], value, .big);
        self.pos += 2;
    }
    fn writeU32(self: *Builder, value: u32) Error!void {
        if (self.pos + 4 > self.out.len) return error.NoSpace;
        std.mem.writeInt(u32, self.out[self.pos..][0..4], value, .big);
        self.pos += 4;
    }
};

pub const RecordWriter = struct {
    builder: *Builder,
    section: types.Section,
    len_offset: usize,
    rdata_start: usize,
    checkpoint: Builder.Checkpoint,
    finished: bool = false,

    pub fn writeByte(self: *RecordWriter, v: u8) Error!void {
        try self.builder.writeByte(v);
    }
    pub fn writeBytes(self: *RecordWriter, v: []const u8) Error!void {
        try self.builder.writeBytes(v);
    }
    pub fn writeU16(self: *RecordWriter, v: u16) Error!void {
        try self.builder.writeU16(v);
    }
    pub fn writeU32(self: *RecordWriter, v: u32) Error!void {
        try self.builder.writeU32(v);
    }
    pub fn writeName(self: *RecordWriter, v: []const u8) Error!void {
        try self.builder.writeName(v);
    }
    pub fn writeWireName(self: *RecordWriter, v: name_mod.Uncompressed) Error!void {
        try self.builder.writeBytes(v.bytes);
    }

    pub fn abort(self: *RecordWriter) void {
        if (self.finished) return;
        self.builder.rollback(self.checkpoint);
        self.finished = true;
    }
    pub fn finish(self: *RecordWriter) Error!void {
        if (self.finished or !self.builder.record_open) return error.NoRecordOpen;
        const len = self.builder.pos - self.rdata_start;
        if (len > std.math.maxInt(u16)) return error.RdataTooLong;
        std.mem.writeInt(u16, self.builder.out[self.len_offset..][0..2], @intCast(len), .big);
        switch (self.section) {
            .answer => self.builder.header.answer_count = std.math.add(u16, self.builder.header.answer_count, 1) catch return error.TooManyRecords,
            .authority => self.builder.header.authority_count = std.math.add(u16, self.builder.header.authority_count, 1) catch return error.TooManyRecords,
            .additional => self.builder.header.additional_count = std.math.add(u16, self.builder.header.additional_count, 1) catch return error.TooManyRecords,
        }
        self.builder.record_open = false;
        self.finished = true;
    }
};

fn suffixHash(bytes: []const u8) u64 {
    var h: u64 = 14695981039346656037;
    for (bytes) |c| {
        h ^= std.ascii.toLower(c);
        h *%= 1099511628211;
    }
    return h;
}

test "builder compresses repeated suffixes" {
    var out: [512]u8 = undefined;
    var entries: [32]CompressionEntry = undefined;
    var b = try Builder.init(&out, &entries, 0xbeef, .{ .response = true, .recursion_available = true });
    try b.addQuestion("www.example.com", .A, .IN);
    try b.addA(.answer, "www.example.com", 60, .{ 1, 2, 3, 4 });
    try b.addNameRecord(.answer, "alias.example.com", .CNAME, 60, "www.example.com");
    const packet = try b.finish();
    const Message = @import("message.zig").Message;
    const m = try Message.init(packet);
    try m.validate();
    try std.testing.expect(packet.len < 100);
}

test "failed record write rolls builder back transactionally" {
    var out: [40]u8 = undefined;
    var entries: [8]CompressionEntry = undefined;
    var b = try Builder.init(&out, &entries, 7, .{});
    try b.addQuestion("a.example", .A, .IN);
    const before = b.pos;
    try std.testing.expectError(error.NoSpace, b.addRawRecord(.answer, "a.example", .TXT, .IN, 60, &([_]u8{0xaa} ** 24)));
    try std.testing.expectEqual(before, b.pos);
    try std.testing.expect(!b.record_open);
}

test "wire owner preserves arbitrary label octets" {
    var out: [128]u8 = undefined;
    var entries: [4]CompressionEntry = undefined;
    const owner_bytes = [_]u8{ 3, 0, '.', 0xff, 0 };
    const owner = try name_mod.Uncompressed.init(&owner_bytes);
    var b = try Builder.init(&out, &entries, 9, .{ .response = true });
    try b.addRawRecordWire(.answer, owner, .A, .IN, 1, &.{ 127, 0, 0, 1 });
    const packet = try b.finish();
    const m = try @import("message.zig").Message.init(packet);
    var it = try m.records(.answer);
    const rr = (try it.next()).?;
    var expanded: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &owner_bytes, try rr.name.writeWire(&expanded));
}

test "typed modern record helpers produce strictly valid message" {
    var out: [2048]u8 = undefined;
    var entries: [64]CompressionEntry = undefined;
    var b = try Builder.init(&out, &entries, 42, .{ .response = true });
    try b.addQuestion("example.com", .SOA, .IN);
    try b.addSoa(.answer, "example.com", 300, "ns1.example.com", "hostmaster.example.com", 1, 3600, 600, 86400, 300);
    try b.addDs(.additional, "example.com", 300, 1234, 13, 2, &([_]u8{0x42} ** 32));
    try b.addDnskey(.additional, "example.com", 300, 257, 13, &([_]u8{0x11} ** 32));
    try b.addTlsa(.additional, "_443._tcp.example.com", 300, 3, 1, 1, &([_]u8{0x22} ** 32));
    try b.addSshfp(.additional, "host.example.com", 300, 4, 2, &([_]u8{0x33} ** 32));
    try b.addUri(.additional, "_svc.example.com", .IN, 300, 10, 1, "https://example.com/");
    try b.addZonemd(.additional, "example.com", .IN, 300, 1, 1, 1, &([_]u8{0x44} ** 48));
    const target = try name_mod.Uncompressed.init(&.{ 3, 's', 'v', 'c', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 });
    const port_param = [_]u8{ 0, 3, 0, 2, 1, 0xbb };
    try b.addSvcb(.additional, "_https.example.com", .HTTPS, 300, 1, target, &port_param);
    const packet = try b.finish();
    const m = try @import("message.zig").Message.init(packet);
    _ = try @import("validate.zig").messageStrict(m, .{});
}

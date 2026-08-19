const std = @import("std");
const types = @import("types.zig");
const name_mod = @import("name.zig");

pub const ParseError = name_mod.Error || error{ Truncated, TrailingData, MessageTooLong };

pub const Question = struct {
    name: name_mod.Name,
    qtype: types.Type,
    qclass: types.Class,
};

pub const Record = struct {
    packet: []const u8,
    name: name_mod.Name,
    rr_type: types.Type,
    class: types.Class,
    ttl: u32,
    rdata_offset: u16,
    rdata: []const u8,

    pub fn rdataName(self: Record) ParseError!name_mod.Name {
        return name_mod.Name.init(self.packet, self.rdata_offset);
    }
};

pub const Message = struct {
    bytes: []const u8,
    header: types.Header,

    pub const max_wire_len = std.math.maxInt(u16);

    pub fn init(bytes: []const u8) ParseError!Message {
        if (bytes.len > max_wire_len) return error.MessageTooLong;
        return .{ .bytes = bytes, .header = try types.Header.parse(bytes) };
    }

    pub fn rcode(self: Message) ParseError!types.Rcode {
        var value: u12 = self.header.flags.rcode_low;
        var it = try self.records(.additional);
        while (try it.next()) |rr| {
            if (rr.rr_type == .OPT) {
                value |= @as(u12, @intCast((rr.ttl >> 24) & 0xff)) << 4;
                break;
            }
        }
        return @enumFromInt(value);
    }

    pub fn questions(self: Message) QuestionIterator {
        return .{ .packet = self.bytes, .remaining = self.header.question_count, .offset = types.Header.wire_len };
    }

    pub fn records(self: Message, section: types.Section) ParseError!RecordIterator {
        var offset: usize = types.Header.wire_len;
        var qi = QuestionIterator{ .packet = self.bytes, .remaining = self.header.question_count, .offset = offset };
        while (try qi.next()) |_| {}
        offset = qi.offset;
        const skip_answer: u16 = switch (section) {
            .answer => 0,
            .authority, .additional => self.header.answer_count,
        };
        const skip_authority: u16 = switch (section) {
            .additional => self.header.authority_count,
            else => 0,
        };
        var skipper = RecordIterator{ .packet = self.bytes, .remaining = skip_answer + skip_authority, .offset = offset };
        while (try skipper.next()) |_| {}
        offset = skipper.offset;
        return .{ .packet = self.bytes, .remaining = switch (section) {
            .answer => self.header.answer_count,
            .authority => self.header.authority_count,
            .additional => self.header.additional_count,
        }, .offset = offset };
    }

    pub fn validate(self: Message) ParseError!void {
        var q = self.questions();
        while (try q.next()) |_| {}
        var a = try self.records(.answer);
        while (try a.next()) |_| {}
        var ns = try self.records(.authority);
        while (try ns.next()) |_| {}
        var ar = try self.records(.additional);
        while (try ar.next()) |_| {}
        if (ar.offset != self.bytes.len) return error.TrailingData;
    }
};

pub const QuestionIterator = struct {
    packet: []const u8,
    remaining: u16,
    offset: usize,

    pub fn next(self: *QuestionIterator) ParseError!?Question {
        if (self.remaining == 0) return null;
        const n = try name_mod.Name.init(self.packet, self.offset);
        const consumed = try n.consumed();
        const p = self.offset + consumed;
        if (p + 4 > self.packet.len) return error.Truncated;
        self.offset = p + 4;
        self.remaining -= 1;
        return .{ .name = n, .qtype = @enumFromInt(std.mem.readInt(u16, self.packet[p..][0..2], .big)), .qclass = @enumFromInt(std.mem.readInt(u16, self.packet[p + 2 ..][0..2], .big)) };
    }
};

pub const RecordIterator = struct {
    packet: []const u8,
    remaining: u16,
    offset: usize,

    pub fn next(self: *RecordIterator) ParseError!?Record {
        if (self.remaining == 0) return null;
        const n = try name_mod.Name.init(self.packet, self.offset);
        const consumed = try n.consumed();
        const p = self.offset + consumed;
        if (p + 10 > self.packet.len) return error.Truncated;
        const rdlen = std.mem.readInt(u16, self.packet[p + 8 ..][0..2], .big);
        const rdata_offset = p + 10;
        if (rdata_offset + rdlen > self.packet.len or rdata_offset > std.math.maxInt(u16)) return error.Truncated;
        self.offset = rdata_offset + rdlen;
        self.remaining -= 1;
        return .{
            .packet = self.packet,
            .name = n,
            .rr_type = @enumFromInt(std.mem.readInt(u16, self.packet[p..][0..2], .big)),
            .class = @enumFromInt(std.mem.readInt(u16, self.packet[p + 2 ..][0..2], .big)),
            .ttl = std.mem.readInt(u32, self.packet[p + 4 ..][0..4], .big),
            .rdata_offset = @intCast(rdata_offset),
            .rdata = self.packet[rdata_offset..][0..rdlen],
        };
    }
};

test "parse basic answer" {
    const packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0,   1,    0,    1,   0, 0,   0,   0,
        7,    'e',  'x',  'a',  'm', 'p',  'l',  'e', 3, 'c', 'o', 'm',
        0,    0,    1,    0,    1,   0xc0, 0x0c, 0,   1, 0,   1,   0,
        0,    0,    60,   0,    4,   1,    2,    3,   4,
    };
    const m = try Message.init(&packet);
    var qs = m.questions();
    const q = (try qs.next()).?;
    var name_buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("example.com", try q.name.writePresentation(&name_buf));
    var rs = try m.records(.answer);
    const rr = (try rs.next()).?;
    try std.testing.expectEqual(types.Type.A, rr.rr_type);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, rr.rdata);
    try m.validate();
}

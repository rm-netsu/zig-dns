const std = @import("std");
const types = @import("types.zig");
const builder = @import("builder.zig");
const message = @import("message.zig");
const client = @import("client.zig");
const edns = @import("edns.zig");

pub const response = @import("resolver/response.zig");
pub const alias = @import("resolver/alias.zig");
pub const referral = @import("resolver/referral.zig");
pub const retry = @import("resolver/retry.zig");

pub const QueryOptions = struct {
    recursion_desired: bool = true,
    checking_disabled: bool = false,
    dnssec_ok: bool = false,
    compact_answers_ok: bool = false,
    udp_payload_size: ?u16 = null,
};

pub fn buildQuery(out: []u8, compression: []builder.CompressionEntry, id: u16, q: client.QuestionKey, options: QueryOptions, edns_options: []const u8) builder.Error![]const u8 {
    var b = try builder.Builder.init(out, compression, id, .{ .recursion_desired = options.recursion_desired, .checking_disabled = options.checking_disabled });
    try b.addQuestion(q.name, q.qtype, q.qclass);
    if (options.udp_payload_size) |size| try b.addOpt(size, 0, 0, .{
        .dnssec_ok = options.dnssec_ok,
        .compact_answers_ok = options.compact_answers_ok,
    }, edns_options);
    return b.finish();
}

pub const ResponseDisposition = enum { accept, retry_tcp };
pub fn disposition(m: message.Message) ResponseDisposition {
    return if (m.header.flags.truncated) .retry_tcp else .accept;
}

pub fn FixedTransactions(comptime capacity: usize) type {
    return struct {
        const Self = @This();
        pub const Entry = struct {
            id: u16 = 0,
            active: bool = false,
            qtype: types.Type = .A,
            qclass: types.Class = .IN,
            name_len: u8 = 0,
            name: [253]u8 = undefined,
        };
        entries: [capacity]Entry = [_]Entry{.{}} ** capacity,

        pub const Error = error{ Full, DuplicateId, NameTooLong, UnknownTransaction } || client.Error;

        pub fn reserve(self: *Self, id: u16, q: client.QuestionKey) Error!usize {
            var free: ?usize = null;
            for (&self.entries, 0..) |*e, i| {
                if (e.active and e.id == id) return error.DuplicateId;
                if (!e.active and free == null) free = i;
            }
            const idx = free orelse return error.Full;
            const clean = if (q.name.len > 0 and q.name[q.name.len - 1] == '.') q.name[0 .. q.name.len - 1] else q.name;
            if (clean.len > 253) return error.NameTooLong;
            var e = &self.entries[idx];
            e.* = .{ .id = id, .active = true, .qtype = q.qtype, .qclass = q.qclass, .name_len = @intCast(clean.len) };
            for (clean, 0..) |c, j| e.name[j] = std.ascii.toLower(c);
            return idx;
        }

        pub fn cancel(self: *Self, index: usize) void {
            if (index < capacity) self.entries[index].active = false;
        }

        pub fn match(self: *Self, bytes: []const u8) Error!struct { index: usize, response: message.Message } {
            const parsed = try message.Message.init(bytes);
            var found: ?usize = null;
            for (&self.entries, 0..) |*e, i| if (e.active and e.id == parsed.header.id) {
                found = i;
                break;
            };
            const idx = found orelse return error.UnknownTransaction;
            var e = &self.entries[idx];
            const parsed_response = try client.validateResponse(e.id, .{ .name = e.name[0..e.name_len], .qtype = e.qtype, .qclass = e.qclass }, bytes);
            e.active = false;
            return .{ .index = idx, .response = parsed_response };
        }

        pub fn activeCount(self: *const Self) usize {
            var n: usize = 0;
            for (&self.entries) |*e| n += @intFromBool(e.active);
            return n;
        }
    };
}

test "fixed transactions match out of order responses" {
    var tx: FixedTransactions(2) = .{};
    const q1: client.QuestionKey = .{ .name = "a.example", .qtype = .A };
    const q2: client.QuestionKey = .{ .name = "b.example", .qtype = .AAAA };
    _ = try tx.reserve(10, q1);
    _ = try tx.reserve(11, q2);
    var buf: [256]u8 = undefined;
    var ce: [16]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&buf, &ce, 11, .{ .response = true });
    try b.addQuestion(q2.name, q2.qtype, q2.qclass);
    const bytes = try b.finish();
    const got = try tx.match(bytes);
    try std.testing.expectEqual(@as(usize, 1), got.index);
    try std.testing.expectEqual(@as(usize, 1), tx.activeCount());
}

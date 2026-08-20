const std = @import("std");
const types = @import("../types.zig");
const message = @import("../message.zig");
const rdata = @import("../rdata.zig");
const canonical = @import("canonical.zig");

pub const Error = canonical.Error || error{
    EmptyRrset,
    MixedOwner,
    MixedType,
    MixedClass,
    TooManyRecords,
    OrderScratchTooSmall,
    CompareScratchTooSmall,
    DuplicateRecord,
    SignatureTypeMismatch,
};

/// Borrowed, allocation-free RRset view. Records may originate from different
/// DNS messages as long as owner, class, and type match.
pub const Rrset = struct {
    records: []const message.Record,

    pub fn init(records: []const message.Record) Error!Rrset {
        if (records.len == 0) return error.EmptyRrset;
        if (records.len > std.math.maxInt(u16)) return error.TooManyRecords;
        const first = records[0];
        for (records[1..]) |rr| {
            if (rr.rr_type != first.rr_type) return error.MixedType;
            if (rr.class != first.class) return error.MixedClass;
            if (!(try rr.name.eqlIgnoreCase(first.name))) return error.MixedOwner;
        }
        return .{ .records = records };
    }

    pub fn rrType(self: Rrset) types.Type {
        return self.records[0].rr_type;
    }

    pub fn class(self: Rrset) types.Class {
        return self.records[0].class;
    }

    /// Produce RFC 4034 section 6.3 order as indexes into `records`.
    ///
    /// `compare_scratch` is split into two equal canonical-RDATA buffers and
    /// reused for each comparison. This keeps memory bounded independently of
    /// RRset count without hidden allocation.
    pub fn canonicalOrder(self: Rrset, order: []u16, compare_scratch: []u8) Error![]const u16 {
        if (order.len < self.records.len) return error.OrderScratchTooSmall;
        if (compare_scratch.len < 2) return error.CompareScratchTooSmall;
        const half = compare_scratch.len / 2;
        if (half == 0) return error.CompareScratchTooSmall;
        const a_buf = compare_scratch[0..half];
        const b_buf = compare_scratch[half .. half * 2];

        for (self.records, 0..) |_, i| order[i] = @intCast(i);

        // RRsets are normally tiny; insertion sort avoids allocator/state
        // overhead and lets the comparator return detailed parse/scratch errors.
        var i: usize = 1;
        while (i < self.records.len) : (i += 1) {
            const key = order[i];
            var j = i;
            while (j > 0) {
                const previous = order[j - 1];
                const relation = compareRdata(self.records[key], self.records[previous], a_buf, b_buf) catch |err| switch (err) {
                    error.NoSpace => return error.CompareScratchTooSmall,
                    else => return err,
                };
                if (relation == .eq) return error.DuplicateRecord;
                if (relation != .lt) break;
                order[j] = previous;
                j -= 1;
            }
            order[j] = key;
        }
        return order[0..self.records.len];
    }
};

/// Stream reconstructed RFC 4035 signed data into a caller-owned canonical
/// writer. Only two canonical RDATA values are materialized at a time for
/// sorting; complete canonical RRs are emitted directly into `writer`.
pub fn writeSignedData(
    writer: *canonical.Writer,
    sig: rdata.Rrsig,
    rrset: Rrset,
    order_scratch: []u16,
    compare_scratch: []u8,
) Error!void {
    if (@intFromEnum(rrset.rrType()) != sig.type_covered) return error.SignatureTypeMismatch;
    const mark = writer.pos;
    errdefer writer.pos = mark;

    const order = try rrset.canonicalOrder(order_scratch, compare_scratch);
    try writer.writeRrsigPrefix(sig);
    for (order) |index| {
        try writer.writeSignedRecord(rrset.records[index], sig.original_ttl, sig.labels);
    }
}

fn compareRdata(a: message.Record, b: message.Record, a_buf: []u8, b_buf: []u8) canonical.Error!std.math.Order {
    var aw = canonical.Writer.init(a_buf);
    var bw = canonical.Writer.init(b_buf);
    try aw.writeRdata(a);
    try bw.writeRdata(b);
    return std.mem.order(u8, aw.written(), bw.written());
}

test "rrset validates grouping and sorts by canonical RDATA" {
    const builder = @import("../builder.zig");
    var packet: [512]u8 = undefined;
    var compression: [16]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 1, .{ .response = true });
    try b.addA(.answer, "WWW.Example", 30, .{ 192, 0, 2, 20 });
    try b.addA(.answer, "www.example", 30, .{ 192, 0, 2, 3 });
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    var it = try m.records(.answer);
    var records: [2]message.Record = undefined;
    records[0] = (try it.next()).?;
    records[1] = (try it.next()).?;

    const set = try Rrset.init(&records);
    var order: [2]u16 = undefined;
    var compare: [64]u8 = undefined;
    const sorted = try set.canonicalOrder(&order, &compare);
    try std.testing.expectEqual(@as(u16, 1), sorted[0]);
    try std.testing.expectEqual(@as(u16, 0), sorted[1]);
}

test "signed data reconstructs wildcard owner and original TTL" {
    const builder = @import("../builder.zig");
    const name_mod = @import("../name.zig");
    var packet: [512]u8 = undefined;
    var compression: [16]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 1, .{ .response = true });
    try b.addA(.answer, "a.z.w.example", 30, .{ 192, 0, 2, 20 });
    try b.addA(.answer, "a.z.w.example", 30, .{ 192, 0, 2, 3 });
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    var it = try m.records(.answer);
    var records: [2]message.Record = undefined;
    records[0] = (try it.next()).?;
    records[1] = (try it.next()).?;
    const set = try Rrset.init(&records);

    const signer_wire = [_]u8{ 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0 };
    const signer = try name_mod.Name.init(&signer_wire, 0);
    const sig: rdata.Rrsig = .{
        .type_covered = @intFromEnum(types.Type.A),
        .algorithm = 8,
        .labels = 2,
        .original_ttl = 3600,
        .expiration = 2,
        .inception = 1,
        .key_tag = 0x1234,
        .signer_name = signer,
        .signature = &.{},
    };

    var out: [512]u8 = undefined;
    var writer = canonical.Writer.init(&out);
    var order: [2]u16 = undefined;
    var compare: [64]u8 = undefined;
    try writeSignedData(&writer, sig, set, &order, &compare);

    const signed = writer.written();
    const prefix_len = 18 + signer_wire.len;
    try std.testing.expectEqualSlices(u8, &.{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, signed[18..prefix_len]);
    const wildcard = [_]u8{ 1, '*', 1, 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    try std.testing.expectEqualSlices(u8, &wildcard, signed[prefix_len..][0..wildcard.len]);
    const ttl_off = prefix_len + wildcard.len + 4;
    try std.testing.expectEqual(@as(u32, 3600), std.mem.readInt(u32, signed[ttl_off..][0..4], .big));
    const first_rdata_off = prefix_len + wildcard.len + 10;
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 3 }, signed[first_rdata_off..][0..4]);
}

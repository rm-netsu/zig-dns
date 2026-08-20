const std = @import("std");
const types = @import("types.zig");
const name_mod = @import("name.zig");
const message = @import("message.zig");
const builder_mod = @import("builder.zig");

pub const max_time_signed: u64 = (1 << 48) - 1;
pub const recommended_fudge: u16 = 300;

pub const ErrorCode = enum(u16) {
    no_error = 0,
    bad_signature = 16,
    bad_key = 17,
    bad_time = 18,
    bad_truncation = 22,
    _,
};

pub const Error = name_mod.Error || builder_mod.Error || error{
    NotTsig,
    InvalidClass,
    InvalidTtl,
    InvalidRdata,
    TimeSignedOutOfRange,
    FieldTooLong,
    RequestErrorMustBeZero,
    InvalidBadTimeData,
    UnexpectedOtherData,
};

/// Borrowed, structurally parsed TSIG record. The algorithm name is retained
/// in its required uncompressed wire representation; the key name is the RR
/// owner and may have been compressed in the containing DNS message.
pub const Record = struct {
    rr: message.Record,
    algorithm: name_mod.Uncompressed,
    time_signed: u64,
    fudge: u16,
    mac: []const u8,
    original_id: u16,
    error_code: ErrorCode,
    other_data: []const u8,

    pub fn keyName(self: Record) name_mod.Name {
        return self.rr.name;
    }
};

pub fn parse(rr: message.Record) Error!Record {
    if (rr.rr_type != .TSIG) return error.NotTsig;
    if (rr.class != .ANY) return error.InvalidClass;
    if (rr.ttl != 0) return error.InvalidTtl;

    var pos: usize = 0;
    const algorithm_len = name_mod.uncompressedConsumedLen(rr.rdata, pos) catch |err| switch (err) {
        error.Truncated, error.InvalidLabel => return error.InvalidRdata,
        else => return err,
    };
    if (algorithm_len > rr.rdata.len) return error.InvalidRdata;
    const algorithm = name_mod.Uncompressed.init(rr.rdata[0..algorithm_len]) catch return error.InvalidRdata;
    pos = algorithm_len;

    // Time Signed(6), Fudge(2), MAC Size(2), Original ID(2), Error(2),
    // Other Len(2) are required even when MAC/Other Data are empty.
    if (rr.rdata.len - pos < 16) return error.InvalidRdata;
    const time_signed: u64 = std.mem.readInt(u48, rr.rdata[pos..][0..6], .big);
    pos += 6;
    const fudge = std.mem.readInt(u16, rr.rdata[pos..][0..2], .big);
    pos += 2;
    const mac_len: usize = std.mem.readInt(u16, rr.rdata[pos..][0..2], .big);
    pos += 2;
    if (mac_len > rr.rdata.len - pos) return error.InvalidRdata;
    const mac = rr.rdata[pos..][0..mac_len];
    pos += mac_len;

    if (rr.rdata.len - pos < 6) return error.InvalidRdata;
    const original_id = std.mem.readInt(u16, rr.rdata[pos..][0..2], .big);
    pos += 2;
    const error_code: ErrorCode = @enumFromInt(std.mem.readInt(u16, rr.rdata[pos..][0..2], .big));
    pos += 2;
    const other_len: usize = std.mem.readInt(u16, rr.rdata[pos..][0..2], .big);
    pos += 2;
    if (other_len != rr.rdata.len - pos) return error.InvalidRdata;

    return .{
        .rr = rr,
        .algorithm = algorithm,
        .time_signed = time_signed,
        .fudge = fudge,
        .mac = mac,
        .original_id = original_id,
        .error_code = error_code,
        .other_data = rr.rdata[pos..],
    };
}

/// Apply QR-dependent RFC 8945 field rules after structural parsing.
pub fn validateSemantics(record: Record, is_response: bool) Error!void {
    if (!is_response) {
        if (record.error_code != .no_error) return error.RequestErrorMustBeZero;
        return;
    }
    if (record.error_code == .bad_time) {
        if (record.other_data.len != 6) return error.InvalidBadTimeData;
    } else if (record.other_data.len != 0) {
        return error.UnexpectedOtherData;
    }
}

pub const Fields = struct {
    algorithm: name_mod.Uncompressed,
    time_signed: u64,
    fudge: u16 = recommended_fudge,
    mac: []const u8,
    original_id: u16,
    error_code: ErrorCode = .no_error,
    other_data: []const u8 = &.{},
};

/// Append a TSIG RR using a presentation-format key name. The operation is
/// transactional through Builder.RecordWriter. Callers are expected to append
/// TSIG only after every other Additional record; strict validation enforces
/// that it is the final Additional RR.
pub fn append(builder: *builder_mod.Builder, key_name: []const u8, fields: Fields) Error!void {
    var w = try builder.beginRecord(.additional, key_name, .TSIG, .ANY, 0);
    errdefer w.abort();
    try writeRdata(&w, fields);
    try w.finish();
}

/// Full-wire-name variant for key names that cannot use the presentation
/// helper without loss.
pub fn appendWire(builder: *builder_mod.Builder, key_name: name_mod.Uncompressed, fields: Fields) Error!void {
    var w = try builder.beginRecordWire(.additional, key_name, .TSIG, .ANY, 0);
    errdefer w.abort();
    try writeRdata(&w, fields);
    try w.finish();
}

fn writeRdata(w: *builder_mod.RecordWriter, fields: Fields) Error!void {
    if (fields.time_signed > max_time_signed) return error.TimeSignedOutOfRange;
    if (fields.mac.len > std.math.maxInt(u16) or fields.other_data.len > std.math.maxInt(u16)) return error.FieldTooLong;

    try w.writeWireName(fields.algorithm);
    var time_buf: [6]u8 = undefined;
    std.mem.writeInt(u48, &time_buf, @intCast(fields.time_signed), .big);
    try w.writeBytes(&time_buf);
    try w.writeU16(fields.fudge);
    try w.writeU16(@intCast(fields.mac.len));
    try w.writeBytes(fields.mac);
    try w.writeU16(fields.original_id);
    try w.writeU16(@intFromEnum(fields.error_code));
    try w.writeU16(@intCast(fields.other_data.len));
    try w.writeBytes(fields.other_data);
}

fn wireName(presentation: []const u8, out: []u8) !name_mod.Uncompressed {
    return name_mod.Uncompressed.init(try name_mod.writePresentationWire(presentation, out));
}

test "TSIG parser and typed builder round trip RFC 8945 fields" {
    var algorithm_buf: [64]u8 = undefined;
    const algorithm = try wireName("hmac-sha256", &algorithm_buf);
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 0x1234, .{});
    try b.addQuestion("example.com", .A, .IN);
    try append(&b, "key.example", .{
        .algorithm = algorithm,
        .time_signed = 1_700_000_000,
        .fudge = 300,
        .mac = &.{ 1, 2, 3, 4 },
        .original_id = 0x1234,
    });
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    var additional = try m.records(.additional);
    const parsed = try parse((try additional.next()).?);
    try std.testing.expectEqual(@as(u64, 1_700_000_000), parsed.time_signed);
    try std.testing.expectEqual(@as(u16, 300), parsed.fudge);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, parsed.mac);
    try std.testing.expectEqual(@as(u16, 0x1234), parsed.original_id);
    try std.testing.expectEqual(ErrorCode.no_error, parsed.error_code);
    try std.testing.expectEqual(@as(usize, 0), parsed.other_data.len);
}

test "TSIG rejects compressed algorithm name and bad response Other Data" {
    // The algorithm field starts with a compression pointer, forbidden by
    // RFC 8945/RFC 3597 even when it would otherwise resolve correctly.
    const packet = [_]u8{
        0, // root key owner at offset 0
        0xc0, 0x00, // compressed Algorithm Name
        0, 0, 0, 0, 0, 1, // time
        0, 1, // fudge
        0, 0, // MAC size
        0, 1, // original ID
        0, 0, // error
        0, 0, // other len
    };
    const owner = try name_mod.Name.init(&packet, 0);
    const rr: message.Record = .{
        .packet = &packet,
        .name = owner,
        .rr_type = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata_offset = 1,
        .rdata = packet[1..],
    };
    try std.testing.expectError(error.InvalidRdata, parse(rr));

    var algorithm_buf: [64]u8 = undefined;
    const algorithm = try wireName("hmac-sha256", &algorithm_buf);
    var buf: [256]u8 = undefined;
    var entries: [8]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&buf, &entries, 1, .{ .response = true });
    try append(&b, "key.example", .{
        .algorithm = algorithm,
        .time_signed = 1,
        .mac = &.{},
        .original_id = 1,
        .error_code = .bad_time,
        .other_data = &.{ 1, 2 },
    });
    const m = try message.Message.init(try b.finish());
    var additional = try m.records(.additional);
    const parsed = try parse((try additional.next()).?);
    try std.testing.expectError(error.InvalidBadTimeData, validateSemantics(parsed, true));
}

test "failed TSIG append rolls builder back" {
    var algorithm_buf: [64]u8 = undefined;
    const algorithm = try wireName("hmac-sha256", &algorithm_buf);
    var packet: [40]u8 = undefined;
    var compression: [8]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 1, .{});
    const before = b.pos;
    try std.testing.expectError(error.NoSpace, append(&b, "key.example", .{
        .algorithm = algorithm,
        .time_signed = 1,
        .mac = &([_]u8{0xaa} ** 32),
        .original_id = 1,
    }));
    try std.testing.expectEqual(before, b.pos);
    try std.testing.expect(!b.record_open);
}

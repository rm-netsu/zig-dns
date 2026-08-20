const std = @import("std");
const message = @import("message.zig");

pub const AttributeError = error{InvalidAttribute};
pub const KnownValueError = error{ InvalidExtendedError, InvalidInfoUrl };
pub const Error = AttributeError || KnownValueError || error{WrongType};

pub const KnownKey = enum {
    qnamemin,
    exterr,
    infourl,
    unknown,
};

/// One DNS-SD-style key/value constituent string from RFC 9606 RESINFO RDATA.
///
/// `value == null` means the attribute had no '=' at all. An empty non-null
/// value represents `key=` and remains distinguishable from the boolean form.
pub const Attribute = struct {
    key: []const u8,
    value: ?[]const u8,

    pub fn knownKey(self: Attribute) KnownKey {
        if (std.ascii.eqlIgnoreCase(self.key, "qnamemin")) return .qnamemin;
        if (std.ascii.eqlIgnoreCase(self.key, "exterr")) return .exterr;
        if (std.ascii.eqlIgnoreCase(self.key, "infourl")) return .infourl;
        return .unknown;
    }

    pub fn isLocal(self: Attribute) bool {
        return self.key.len >= 5 and std.ascii.eqlIgnoreCase(self.key[0..5], "temp-");
    }
};

pub const Iterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(self: *Iterator) AttributeError!?Attribute {
        if (self.pos == self.bytes.len) return null;

        const len: usize = self.bytes[self.pos];
        self.pos += 1;
        if (len > self.bytes.len - self.pos) return error.InvalidAttribute;

        const text = self.bytes[self.pos..][0..len];
        self.pos += len;
        return @as(?Attribute, try parseAttribute(text));
    }
};

pub fn iterator(rr: message.Record) error{WrongType}!Iterator {
    if (rr.rr_type != .RESINFO) return error.WrongType;
    return .{ .bytes = rr.rdata };
}

pub fn parseAttribute(text: []const u8) AttributeError!Attribute {
    const equals = std.mem.indexOfScalar(u8, text, '=');
    const key = if (equals) |at| text[0..at] else text;
    try validateKey(key);
    return .{
        .key = key,
        .value = if (equals) |at| text[at + 1 ..] else null,
    };
}

pub fn validateKey(key: []const u8) AttributeError!void {
    if (key.len == 0) return error.InvalidAttribute;
    for (key) |c| {
        if (c < 0x20 or c > 0x7e or c == '=') return error.InvalidAttribute;
    }
}

/// Finds the first occurrence of a key, matching with DNS-SD's
/// case-insensitive key semantics. Later duplicates are intentionally ignored.
pub fn find(rr: message.Record, key: []const u8) Error!?Attribute {
    try validateKey(key);
    var it = try iterator(rr);
    while (try it.next()) |attribute| {
        if (std.ascii.eqlIgnoreCase(attribute.key, key)) return attribute;
    }
    return null;
}

pub const ExtendedErrorRange = struct {
    first: u16,
    last: u16,
};

pub const ExtendedErrorIterator = struct {
    value: []const u8,
    pos: usize = 0,

    pub fn next(self: *ExtendedErrorIterator) error{InvalidExtendedError}!?ExtendedErrorRange {
        if (self.pos == self.value.len) return null;

        const comma = std.mem.indexOfScalarPos(u8, self.value, self.pos, ',') orelse self.value.len;
        const token = self.value[self.pos..comma];
        if (token.len == 0) return error.InvalidExtendedError;
        if (comma != self.value.len and comma + 1 == self.value.len) return error.InvalidExtendedError;
        self.pos = if (comma == self.value.len) self.value.len else comma + 1;

        const dash = std.mem.indexOfScalar(u8, token, '-');
        if (dash) |at| {
            if (at == 0 or at + 1 == token.len) return error.InvalidExtendedError;
            if (std.mem.indexOfScalar(u8, token[at + 1 ..], '-') != null) return error.InvalidExtendedError;
            const first = parseDecimalU16(token[0..at]) catch return error.InvalidExtendedError;
            const last = parseDecimalU16(token[at + 1 ..]) catch return error.InvalidExtendedError;
            if (last < first) return error.InvalidExtendedError;
            return .{ .first = first, .last = last };
        }

        const value = parseDecimalU16(token) catch return error.InvalidExtendedError;
        return .{ .first = value, .last = value };
    }
};

pub fn extendedErrors(attribute: Attribute) error{InvalidExtendedError}!ExtendedErrorIterator {
    if (attribute.knownKey() != .exterr) return error.InvalidExtendedError;
    const value = attribute.value orelse return error.InvalidExtendedError;
    if (value.len == 0) return error.InvalidExtendedError;
    return .{ .value = value };
}

/// Validates and returns the HTTPS information URI from an `infourl` attribute.
/// No allocation is performed; all URI components continue to borrow the RDATA.
pub fn infoUrl(attribute: Attribute) error{InvalidInfoUrl}!std.Uri {
    if (attribute.knownKey() != .infourl) return error.InvalidInfoUrl;
    const value = attribute.value orelse return error.InvalidInfoUrl;
    if (value.len == 0) return error.InvalidInfoUrl;
    const uri = std.Uri.parse(value) catch return error.InvalidInfoUrl;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https") or uri.host == null) return error.InvalidInfoUrl;
    return uri;
}

/// Checks the syntax that a typed RESINFO builder can guarantee locally.
/// Unknown/future keys remain valid; only current known value syntax is checked.
pub fn validateForBuild(attribute: Attribute) (AttributeError || KnownValueError)!void {
    try validateKey(attribute.key);
    if (attribute.key.len > 255) return error.InvalidAttribute;
    if (attribute.value) |value| {
        if (attribute.key.len == 255 or value.len > 254 - attribute.key.len) return error.InvalidAttribute;
    }

    switch (attribute.knownKey()) {
        .exterr => {
            var it = try extendedErrors(attribute);
            while (try it.next()) |_| {}
        },
        .infourl => _ = try infoUrl(attribute),
        .qnamemin, .unknown => {},
    }
}

fn parseDecimalU16(text: []const u8) error{InvalidExtendedError}!u16 {
    if (text.len == 0) return error.InvalidExtendedError;
    var value: u32 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return error.InvalidExtendedError;
        value = value * 10 + (c - '0');
        if (value > std.math.maxInt(u16)) return error.InvalidExtendedError;
    }
    return @intCast(value);
}

test "RFC 9606 RESINFO parses borrowed key value attributes" {
    const wire = [_]u8{
        8,   'q', 'n', 'a', 'm', 'e', 'm', 'i', 'n',
        12,  'e', 'x', 't', 'e', 'r', 'r', '=', '1',
        '5', '-', '1', '7', 42,  'i', 'n', 'f', 'o',
        'u', 'r', 'l', '=', 'h', 't', 't', 'p', 's',
        ':', '/', '/', 'r', 'e', 's', 'o', 'l', 'v',
        'e', 'r', '.', 'e', 'x', 'a', 'm', 'p', 'l',
        'e', '.', 'c', 'o', 'm', '/', 'g', 'u', 'i',
        'd', 'e',
    };
    var it: Iterator = .{ .bytes = &wire };

    const qname = (try it.next()).?;
    try std.testing.expectEqual(KnownKey.qnamemin, qname.knownKey());
    try std.testing.expect(qname.value == null);

    const exterr = (try it.next()).?;
    var errors = try extendedErrors(exterr);
    try std.testing.expectEqual(ExtendedErrorRange{ .first = 15, .last = 17 }, (try errors.next()).?);
    try std.testing.expect((try errors.next()) == null);

    const url = try infoUrl((try it.next()).?);
    try std.testing.expect(std.ascii.eqlIgnoreCase(url.scheme, "https"));
    try std.testing.expect((try it.next()) == null);
}

test "RESINFO preserves future and local keys and distinguishes empty value" {
    const future = try parseAttribute("future-key=opaque=bytes");
    try std.testing.expectEqual(KnownKey.unknown, future.knownKey());
    try std.testing.expectEqualStrings("opaque=bytes", future.value.?);

    const local = try parseAttribute("TEMP-vendor=");
    try std.testing.expect(local.isLocal());
    try std.testing.expectEqual(@as(usize, 0), local.value.?.len);
}

test "RESINFO rejects malformed key and known value syntax" {
    try std.testing.expectError(error.InvalidAttribute, parseAttribute("=missing"));
    try std.testing.expectError(error.InvalidAttribute, parseAttribute(&.{ 'b', 'a', 0x1f, 'd' }));

    const exterr = try parseAttribute("exterr=17-15");
    var ranges = try extendedErrors(exterr);
    try std.testing.expectError(error.InvalidExtendedError, ranges.next());

    const trailing = try parseAttribute("exterr=15,");
    var trailing_ranges = try extendedErrors(trailing);
    try std.testing.expectError(error.InvalidExtendedError, trailing_ranges.next());

    try std.testing.expectError(error.InvalidInfoUrl, infoUrl(try parseAttribute("infourl=http://resolver.example/")));
}

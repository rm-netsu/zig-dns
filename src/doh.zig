const std = @import("std");

pub const media_type = "application/dns-message";
pub const default_path = "/dns-query";

pub fn encodedLen(message_len: usize) usize {
    return std.base64.url_safe_no_pad.Encoder.calcSize(message_len);
}

pub fn encodeGetParam(message: []const u8, out: []u8) error{BufferTooSmall}![]const u8 {
    const len = encodedLen(message.len);
    if (out.len < len) return error.BufferTooSmall;
    return std.base64.url_safe_no_pad.Encoder.encode(out[0..len], message);
}

pub fn decodeGetParam(encoded: []const u8, out: []u8) (std.base64.Error || error{BufferTooSmall})![]const u8 {
    const len = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded);
    if (out.len < len) return error.BufferTooSmall;
    try std.base64.url_safe_no_pad.Decoder.decode(out[0..len], encoded);
    return out[0..len];
}

test "RFC 8484 GET example encoding" {
    const wire = [_]u8{
        0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
    };
    var out: [64]u8 = undefined;
    const encoded = try encodeGetParam(&wire, &out);
    try std.testing.expectEqualStrings("AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB", encoded);
}

const std = @import("std");

pub const Error = error{InvalidPadding};

/// RFC 8467 experimental block-length recommendations for encrypted DNS.
pub const recommended_query_block_length: usize = 128;
pub const recommended_response_block_length: usize = 468;
pub const option_header_length: usize = 4;

/// Borrowed RFC 7830 padding payload. Received octets are intentionally not
/// constrained to zero: RFC 7830 requires receivers to accept any values.
pub const Padding = struct {
    bytes: []const u8,

    pub fn len(self: Padding) usize {
        return self.bytes.len;
    }
};

pub fn parse(data: []const u8) Padding {
    return .{ .bytes = data };
}

/// Calculate RFC 8467 block-length padding for one EDNS Padding option.
///
/// `unpadded_len` is the caller-selected length before the 4-byte option
/// header and padding payload. It may be the DNS message length alone or may
/// include transport framing when that is the policy being applied.
///
/// Returns null when even the nearest padded block would exceed `max_len`.
/// No allocation or mutation is performed.
pub fn blockLength(unpadded_len: usize, block_len: usize, max_len: usize) Error!?usize {
    if (block_len == 0) return error.InvalidPadding;
    if (unpadded_len > max_len) return null;
    if (max_len - unpadded_len < option_header_length) return null;

    const available_after_header = max_len - unpadded_len - option_header_length;
    const base_mod = unpadded_len % block_len;
    const header_mod = option_header_length % block_len;
    const sum_mod = if (base_mod >= block_len - header_mod and header_mod != 0)
        base_mod - (block_len - header_mod)
    else
        base_mod + header_mod;
    const padding_len = if (sum_mod == 0) 0 else block_len - sum_mod;

    if (padding_len > std.math.maxInt(u16)) return error.InvalidPadding;
    if (padding_len > available_after_header) return null;
    return padding_len;
}

test "RFC 8467 block padding includes the four-byte option header" {
    try std.testing.expectEqual(@as(?usize, 65), try blockLength(59, 128, 512));
    try std.testing.expectEqual(@as(?usize, 31), try blockLength(61, 96, 512));
    try std.testing.expectEqual(@as(?usize, 0), try blockLength(124, 128, 512));
}

test "block padding obeys payload limit and rejects invalid policy" {
    try std.testing.expectEqual(@as(?usize, null), try blockLength(125, 128, 128));
    try std.testing.expectEqual(@as(?usize, null), try blockLength(129, 128, 128));
    try std.testing.expectError(error.InvalidPadding, blockLength(10, 0, 512));
}

test "RFC 7830 accepts non-zero received padding" {
    const value = parse(&.{ 0xde, 0xad, 0xbe, 0xef });
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, value.bytes);
}

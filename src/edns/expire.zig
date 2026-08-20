const std = @import("std");

pub const Error = error{InvalidExpire};

/// RFC 7314 EDNS EXPIRE wire form.
/// Query form is empty; response form carries the remaining expire timer in
/// seconds in network byte order.
pub const Expire = union(enum) {
    request,
    remaining_seconds: u32,
};

pub fn parse(data: []const u8) Error!Expire {
    return switch (data.len) {
        0 => .request,
        4 => .{ .remaining_seconds = std.mem.readInt(u32, data[0..4], .big) },
        else => error.InvalidExpire,
    };
}

/// RFC 7314 secondary refresh behavior when an EXPIRE response is present:
/// preserve the greater current/advertised remaining time, but never exceed
/// the zone's SOA EXPIRE field.
pub fn refreshRemaining(current_remaining: u32, advertised_remaining: u32, soa_expire: u32) u32 {
    return @min(@max(current_remaining, advertised_remaining), soa_expire);
}

/// RFC 7314 transfer/update initialization when an EXPIRE response is present:
/// prefer the advertised timer while treating SOA EXPIRE as the hard maximum.
pub fn transferRemaining(advertised_remaining: u32, soa_expire: u32) u32 {
    return @min(advertised_remaining, soa_expire);
}

test "RFC 7314 query and response forms" {
    try std.testing.expectEqual(Expire.request, try parse(&.{}));
    const value = try parse(&.{ 0x00, 0x01, 0x51, 0x80 });
    try std.testing.expectEqual(@as(u32, 86_400), value.remaining_seconds);
    try std.testing.expectError(error.InvalidExpire, parse(&.{ 0, 1, 2 }));
}

test "RFC 7314 timer helpers cap at SOA EXPIRE" {
    try std.testing.expectEqual(@as(u32, 3000), refreshRemaining(1000, 3000, 3600));
    try std.testing.expectEqual(@as(u32, 3000), refreshRemaining(3000, 1000, 3600));
    try std.testing.expectEqual(@as(u32, 3600), refreshRemaining(4000, 5000, 3600));
    try std.testing.expectEqual(@as(u32, 3600), transferRemaining(7200, 3600));
    try std.testing.expectEqual(@as(u32, 1800), transferRemaining(1800, 3600));
}

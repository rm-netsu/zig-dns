const std = @import("std");

pub const Type = enum(u16) {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    X25 = 19,
    ISDN = 20,
    RT = 21,
    NSAP = 22,
    NSAP_PTR = 23,
    SIG = 24,
    KEY = 25,
    PX = 26,
    GPOS = 27,
    AAAA = 28,
    LOC = 29,
    NXT = 30,
    SRV = 33,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    A6 = 38,
    DNAME = 39,
    OPT = 41,
    APL = 42,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SMIMEA = 53,
    HIP = 55,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    CSYNC = 62,
    ZONEMD = 63,
    SVCB = 64,
    HTTPS = 65,
    NXNAME = 128,
    TKEY = 249,
    TSIG = 250,
    IXFR = 251,
    AXFR = 252,
    ANY = 255,
    URI = 256,
    CAA = 257,
    _,
};

/// True when `rr_type` is usable as ordinary DNS zone/data RRTYPE.
///
/// This follows the IANA split used by RFC 6895-family protocols: zero,
/// OPT, the 128..255 QTYPE/Meta-TYPE range, 61440..65279, and 65535 are
/// not data RRTYPEs. 65280..65534 remains Private Use and is valid data.
pub fn isDataRrType(rr_type: Type) bool {
    const value = @intFromEnum(rr_type);
    return value != 0 and rr_type != .OPT and
        !(value >= 128 and value <= 255) and
        !(value >= 61440 and value <= 65279) and
        value != 65535;
}

pub const Class = enum(u16) {
    IN = 1,
    CH = 3,
    HS = 4,
    NONE = 254,
    ANY = 255,
    _,
};

pub const Opcode = enum(u4) { query = 0, iquery = 1, status = 2, notify = 4, update = 5, dso = 6, _ };
pub const Rcode = enum(u12) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    name_error = 3,
    not_implemented = 4,
    refused = 5,
    yx_domain = 6,
    yx_rrset = 7,
    nx_rrset = 8,
    not_auth = 9,
    not_zone = 10,
    bad_version_or_signature = 16,
    bad_key = 17,
    bad_time = 18,
    bad_mode = 19,
    bad_name = 20,
    bad_alg = 21,
    bad_trunc = 22,
    bad_cookie = 23,
    _,
};

pub const Section = enum { answer, authority, additional };

pub const Flags = packed struct(u16) {
    rcode_low: u4 = 0,
    checking_disabled: bool = false,
    authenticated_data: bool = false,
    zero: bool = false,
    recursion_available: bool = false,
    recursion_desired: bool = false,
    truncated: bool = false,
    authoritative: bool = false,
    opcode: Opcode = .query,
    response: bool = false,

    pub fn fromInt(value: u16) Flags {
        return @bitCast(value);
    }
    pub fn toInt(self: Flags) u16 {
        return @bitCast(self);
    }
    pub fn rcode(self: Flags) Rcode {
        return @enumFromInt(self.rcode_low);
    }
};

pub const Header = struct {
    id: u16,
    flags: Flags,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,

    pub const wire_len = 12;

    pub fn parse(bytes: []const u8) error{Truncated}!Header {
        if (bytes.len < wire_len) return error.Truncated;
        return .{
            .id = std.mem.readInt(u16, bytes[0..2], .big),
            .flags = .fromInt(std.mem.readInt(u16, bytes[2..4], .big)),
            .question_count = std.mem.readInt(u16, bytes[4..6], .big),
            .answer_count = std.mem.readInt(u16, bytes[6..8], .big),
            .authority_count = std.mem.readInt(u16, bytes[8..10], .big),
            .additional_count = std.mem.readInt(u16, bytes[10..12], .big),
        };
    }

    pub fn write(self: Header, out: []u8) error{NoSpace}!void {
        if (out.len < wire_len) return error.NoSpace;
        std.mem.writeInt(u16, out[0..2], self.id, .big);
        std.mem.writeInt(u16, out[2..4], self.flags.toInt(), .big);
        std.mem.writeInt(u16, out[4..6], self.question_count, .big);
        std.mem.writeInt(u16, out[6..8], self.answer_count, .big);
        std.mem.writeInt(u16, out[8..10], self.authority_count, .big);
        std.mem.writeInt(u16, out[10..12], self.additional_count, .big);
    }
};

test "header round trip" {
    const h: Header = .{ .id = 0x1234, .flags = .{ .recursion_desired = true }, .question_count = 1, .answer_count = 2, .authority_count = 0, .additional_count = 1 };
    var buf: [12]u8 = undefined;
    try h.write(&buf);
    const p = try Header.parse(&buf);
    try std.testing.expectEqual(h.id, p.id);
    try std.testing.expect(p.flags.recursion_desired);
    try std.testing.expectEqual(@as(u16, 2), p.answer_count);
}

test "data RRTYPE classification preserves private use and rejects meta ranges" {
    try std.testing.expect(isDataRrType(.A));
    try std.testing.expect(isDataRrType(.HTTPS));
    try std.testing.expect(isDataRrType(@enumFromInt(65280)));
    try std.testing.expect(!isDataRrType(@enumFromInt(0)));
    try std.testing.expect(!isDataRrType(.OPT));
    try std.testing.expect(!isDataRrType(.NXNAME));
    try std.testing.expect(!isDataRrType(.ANY));
    try std.testing.expect(!isDataRrType(@enumFromInt(61440)));
    try std.testing.expect(!isDataRrType(@enumFromInt(65535)));
}

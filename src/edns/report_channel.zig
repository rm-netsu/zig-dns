const std = @import("std");
const name = @import("../name.zig");

pub const Error = error{InvalidReportChannel};

/// RFC 9567 EDNS0 Report-Channel option payload.
///
/// The agent domain is borrowed directly from the OPT RDATA and is always a
/// complete, fully-qualified, uncompressed DNS wire name. The root name is
/// rejected because RFC 9567 forbids advertising it as an agent domain.
pub const ReportChannel = struct {
    agent_domain: name.Uncompressed,
};

pub fn parse(data: []const u8) Error!ReportChannel {
    if (data.len == 0) return error.InvalidReportChannel;
    const agent_domain = name.Uncompressed.init(data) catch return error.InvalidReportChannel;
    try validateAgentDomain(agent_domain);
    return .{ .agent_domain = agent_domain };
}

pub fn validateAgentDomain(agent_domain: name.Uncompressed) Error!void {
    if (agent_domain.bytes.len == 1 and agent_domain.bytes[0] == 0) return error.InvalidReportChannel;
}

test "RFC 9567 report channel accepts one complete uncompressed agent domain" {
    const wire = [_]u8{ 3, 'e', 'r', 'r', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    const value = try parse(&wire);
    try std.testing.expectEqualSlices(u8, &wire, value.agent_domain.bytes);
}

test "RFC 9567 report channel rejects empty root compressed and trailing data" {
    try std.testing.expectError(error.InvalidReportChannel, parse(&.{}));
    try std.testing.expectError(error.InvalidReportChannel, parse(&.{0}));
    try std.testing.expectError(error.InvalidReportChannel, parse(&.{ 0xc0, 0x00 }));
    try std.testing.expectError(error.InvalidReportChannel, parse(&.{ 1, 'a', 0, 0 }));
}

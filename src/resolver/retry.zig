const std = @import("std");
const client = @import("../client.zig");
const message = @import("../message.zig");
const builder = @import("../builder.zig");
const response_mod = @import("response.zig");

pub const Transport = enum { udp, tcp };

pub const Action = enum {
    retry_udp,
    fallback_tcp,
    retry_other_server,
    retry_without_edns,
    terminal,
};

pub const Reason = enum {
    timeout,
    transport_failure,
    malformed_response,
    truncated,
    edns_unsupported,
    server_failure,
    protocol_failure,
    retry_budget_exhausted,
    accepted,
};

pub const Decision = struct {
    action: Action,
    reason: Reason,
};

/// Facts about the attempt that just completed. `queries_sent` includes the
/// current query. RFC 9520 caps a query to one server address over one DNS
/// transport at three total transmissions (initial + at most two retries).
pub const Attempt = struct {
    transport: Transport = .udp,
    queries_sent: u8 = 1,
    other_servers_available: bool = true,
    edns_used: bool = true,
    /// DNSSEC DO or another required EDNS feature prevents EDNS fallback.
    edns_required: bool = false,
};

pub const Response = struct {
    outcome: response_mod.Outcome,
    /// Whether the response contains an OPT RR. For FORMERR, RFC 6891 uses
    /// this to distinguish an EDNS syntax error from an unextended server.
    has_opt: bool,
};

pub const Event = union(enum) {
    timeout,
    transport_failure,
    malformed_response,
    response: Response,
};

pub const max_queries_per_server_transport: u8 = 3;

/// Produce one transport-neutral retry action. No timers, sockets, server
/// selection, or query mutation are owned by this layer.
pub fn plan(attempt: Attempt, event: Event) Decision {
    return switch (event) {
        .timeout => planTimeout(attempt),
        .transport_failure => otherOrTerminal(attempt, .transport_failure),
        .malformed_response => otherOrTerminal(attempt, .malformed_response),
        .response => |r| planResponse(attempt, r),
    };
}

/// Classify a parsed response and record whether it carried EDNS. This helper
/// keeps the FORMERR/OPT distinction out of application code while preserving
/// caller ownership of the DNS bytes.
pub fn inspect(m: message.Message, q: client.QuestionKey) response_mod.Error!Response {
    var has_opt = false;
    var additional = try m.records(.additional);
    while (try additional.next()) |rr| {
        if (rr.rr_type == .OPT) {
            has_opt = true;
            break;
        }
    }
    return .{ .outcome = try response_mod.classify(m, q), .has_opt = has_opt };
}

fn planTimeout(attempt: Attempt) Decision {
    if (attempt.transport == .udp and attempt.queries_sent < max_queries_per_server_transport) {
        return .{ .action = .retry_udp, .reason = .timeout };
    }
    if (attempt.other_servers_available) return .{ .action = .retry_other_server, .reason = .retry_budget_exhausted };
    return .{ .action = .terminal, .reason = .retry_budget_exhausted };
}

fn planResponse(attempt: Attempt, r: Response) Decision {
    return switch (r.outcome) {
        .truncated => if (attempt.transport == .udp)
            .{ .action = .fallback_tcp, .reason = .truncated }
        else
            otherOrTerminal(attempt, .protocol_failure),
        .formerr => if (attempt.edns_used and !attempt.edns_required and !r.has_opt)
            .{ .action = .retry_without_edns, .reason = .edns_unsupported }
        else
            otherOrTerminal(attempt, .protocol_failure),
        .servfail, .failure => otherOrTerminal(attempt, .server_failure),
        .answer, .cname, .dname, .referral, .nodata, .nxdomain => .{ .action = .terminal, .reason = .accepted },
    };
}

fn otherOrTerminal(attempt: Attempt, reason: Reason) Decision {
    if (attempt.other_servers_available) return .{ .action = .retry_other_server, .reason = reason };
    return .{ .action = .terminal, .reason = reason };
}

fn expectDecision(action: Action, reason: Reason, actual: Decision) !void {
    try std.testing.expectEqual(action, actual.action);
    try std.testing.expectEqual(reason, actual.reason);
}

test "UDP timeout retries at most twice before moving servers" {
    try expectDecision(.retry_udp, .timeout, plan(.{ .queries_sent = 1 }, .timeout));
    try expectDecision(.retry_udp, .timeout, plan(.{ .queries_sent = 2 }, .timeout));
    try expectDecision(.retry_other_server, .retry_budget_exhausted, plan(.{ .queries_sent = 3 }, .timeout));
    try expectDecision(.terminal, .retry_budget_exhausted, plan(.{ .queries_sent = 3, .other_servers_available = false }, .timeout));
}

test "truncated UDP falls back to TCP but truncated TCP changes server" {
    const truncated: Response = .{ .outcome = .truncated, .has_opt = true };
    try expectDecision(.fallback_tcp, .truncated, plan(.{ .transport = .udp }, .{ .response = truncated }));
    try expectDecision(.retry_other_server, .protocol_failure, plan(.{ .transport = .tcp }, .{ .response = truncated }));
}

test "FORMERR without OPT permits EDNS fallback only when optional" {
    const formerr_no_opt: Response = .{ .outcome = .formerr, .has_opt = false };
    try expectDecision(.retry_without_edns, .edns_unsupported, plan(.{
        .edns_used = true,
        .edns_required = false,
    }, .{ .response = formerr_no_opt }));
    try expectDecision(.retry_other_server, .protocol_failure, plan(.{
        .edns_used = true,
        .edns_required = true,
    }, .{ .response = formerr_no_opt }));

    const formerr_with_opt: Response = .{ .outcome = .formerr, .has_opt = true };
    try expectDecision(.retry_other_server, .protocol_failure, plan(.{}, .{ .response = formerr_with_opt }));
}

test "successful semantic outcomes stop retry planning" {
    inline for (.{
        response_mod.Outcome.answer,
        response_mod.Outcome.referral,
        response_mod.Outcome.nodata,
        response_mod.Outcome.nxdomain,
    }) |outcome| {
        try expectDecision(.terminal, .accepted, plan(.{}, .{ .response = .{ .outcome = outcome, .has_opt = false } }));
    }
    try expectDecision(.retry_other_server, .server_failure, plan(.{}, .{ .response = .{ .outcome = .servfail, .has_opt = false } }));
}

test "inspect distinguishes EDNS FORMERR response from unextended server" {
    var packet: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    const q: client.QuestionKey = .{ .name = "example", .qtype = .A };

    var no_opt = try builder.Builder.init(&packet, &compression, 1, .{ .response = true, .rcode_low = 1 });
    try no_opt.addQuestion(q.name, q.qtype, q.qclass);
    const unextended = try inspect(try message.Message.init(try no_opt.finish()), q);
    try std.testing.expect(!unextended.has_opt);
    try expectDecision(.retry_without_edns, .edns_unsupported, plan(.{}, .{ .response = unextended }));

    var with_opt = try builder.Builder.init(&packet, &compression, 2, .{ .response = true, .rcode_low = 1 });
    try with_opt.addQuestion(q.name, q.qtype, q.qclass);
    try with_opt.addOpt(1232, 0, 0, .{}, &.{});
    const edns_error = try inspect(try message.Message.init(try with_opt.finish()), q);
    try std.testing.expect(edns_error.has_opt);
    try expectDecision(.retry_other_server, .protocol_failure, plan(.{}, .{ .response = edns_error }));
}

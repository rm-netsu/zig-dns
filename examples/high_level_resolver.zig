const std = @import("std");
const dns = @import("dns");

const R = dns.high_level.Resolver(.{
    .max_queries = 8,
    .max_alias_depth = 8,
    .alias_storage_bytes = 512,
});

pub fn main() !void {
    var storage: R.Storage = undefined;
    var resolver = R.initInPlace(&storage);

    const first = try resolver.beginPresentation(.{
        .name = "www.example.com",
        .qtype = .A,
    }, .{
        .server_count = 2,
        .transport = .udp,
        .query = .{ .udp_payload_size = 1232, .dnssec_ok = true },
    });
    const initial = dispatchFrom(first) orelse return error.UnexpectedAction;

    var query_buf: [1232]u8 = undefined;
    var query_compression: [32]dns.CompressionEntry = undefined;
    const query = try resolver.writeQuery(initial.handle, &query_buf, &query_compression, &.{});
    std.debug.print("send {d} bytes over {s} to server[{d}]\n", .{
        query.len,
        @tagName(initial.transport),
        initial.server_index,
    });

    // Networking remains caller-owned. These packets only stand in for two
    // responses received from the selected upstream.
    var response_buf: [512]u8 = undefined;
    var response_compression: [24]dns.CompressionEntry = undefined;
    var b = try dns.Builder.init(&response_buf, &response_compression, initial.id, .{ .response = true });
    try b.addQuestion("www.example.com", .A, .IN);
    try b.addNameRecord(.answer, "www.example.com", .CNAME, 300, "origin.example.net");
    const cname_response = try b.finish();

    const alias_action = try resolver.onValidatedResponse(initial.handle, cname_response, 1_000, .secure);
    const alias_dispatch = dispatchFrom(alias_action) orelse return error.UnexpectedAction;

    var alias_name: [dns.name.Name.max_presentation_len]u8 = undefined;
    std.debug.print("follow alias -> {s}\n", .{try resolver.writeCurrentNamePresentation(alias_dispatch.handle, &alias_name)});

    b = try dns.Builder.init(&response_buf, &response_compression, alias_dispatch.id, .{ .response = true });
    try b.addQuestion("origin.example.net", .A, .IN);
    try b.addRawRecord(.answer, "origin.example.net", .A, .IN, 60, &.{ 192, 0, 2, 1 });
    const answer = try b.finish();

    const completed = try resolver.onValidatedResponse(alias_dispatch.handle, answer, 1_001, .secure);
    switch (completed) {
        .complete => |result| {
            std.debug.print("complete: {s}, security={s}, server[{d}]\n", .{
                @tagName(result.kind),
                @tagName(result.security),
                result.server_index,
            });
            try resolver.release(result.handle);
        },
        else => return error.UnexpectedAction,
    }
}

fn dispatchFrom(action: dns.high_level.Action) ?dns.high_level.Dispatch {
    return switch (action) {
        .send => |d| d,
        .retry => |d| d,
        .connect_tcp => |d| d,
        .connect_dot => |d| d,
        .open_doq_stream => |d| d,
        .perform_doh => |d| d,
        else => null,
    };
}

const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const builder = @import("../builder.zig");
const client = @import("../client.zig");
const retry_mod = @import("../resolver/retry.zig");
const high = @import("resolver.zig");

const Resolver = high.Resolver;
const Action = high.Action;
const Dispatch = high.Dispatch;
const DispatchReason = high.DispatchReason;
const CompletionKind = high.CompletionKind;
const FailureReason = high.FailureReason;

fn expectActionTag(expected: std.meta.Tag(Action), action: Action) !void {
    try std.testing.expectEqual(expected, std.meta.activeTag(action));
}

fn responsePacket(out: []u8, compression: []builder.CompressionEntry, dispatch: Dispatch, q: client.WireQuestionKey, flags: types.Flags) ![]const u8 {
    var b = try builder.Builder.init(out, compression, dispatch.id, flags);
    try b.addQuestionWire(q.name, q.qtype, q.qclass);
    return b.finish();
}

test "bounded resolver allocates unique ids and matches out-of-order responses" {
    const R = Resolver(.{ .max_queries = 2, .max_alias_depth = 4, .alias_storage_bytes = 128 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);

    const a = (try r.beginPresentation(.{ .name = "a.example", .qtype = .A }, .{})).send;
    const b = (try r.beginPresentation(.{ .name = "b.example", .qtype = .AAAA }, .{})).send;
    try std.testing.expect(a.id != b.id);
    try std.testing.expectEqual(@as(usize, 2), r.activeCount());

    var packet: [256]u8 = undefined;
    var compression: [12]builder.CompressionEntry = undefined;
    const bq = try r.currentQuestion(b.handle);
    var bb = try builder.Builder.init(&packet, &compression, b.id, .{ .response = true });
    try bb.addQuestionWire(bq.name, bq.qtype, bq.qclass);
    try bb.addAAAA(.answer, "b.example", 60, [_]u8{0} ** 15 ++ .{1});
    const bytes = try bb.finish();

    const matched = try r.matchResponse(bytes);
    try std.testing.expectEqual(b.handle, matched);
    const done = try r.onMatchedResponse(bytes);
    try expectActionTag(.complete, done);
    try std.testing.expectEqual(CompletionKind.answer, done.complete.kind);
    try r.release(done.complete.handle);
    try std.testing.expectEqual(@as(usize, 1), r.activeCount());
}

test "UDP truncation switches to TCP with a fresh transaction id" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 2, .alias_storage_bytes = 64 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const first = (try r.beginPresentation(.{ .name = "example", .qtype = .A }, .{})).send;
    const q = try r.currentQuestion(first.handle);

    var packet: [256]u8 = undefined;
    var compression: [12]builder.CompressionEntry = undefined;
    const bytes = try responsePacket(&packet, &compression, first, q, .{ .response = true, .truncated = true });
    const next = try r.onResponse(first.handle, bytes);
    try expectActionTag(.connect_tcp, next);
    try std.testing.expectEqual(retry_mod.Transport.tcp, next.connect_tcp.transport);
    try std.testing.expect(first.id != next.connect_tcp.id);

    var query_packet: [256]u8 = undefined;
    const query = try r.writeQuery(next.connect_tcp.handle, &query_packet, &compression, &.{});
    const parsed = try message.Message.init(query);
    try std.testing.expectEqual(next.connect_tcp.id, parsed.header.id);
}

test "CNAME continuation updates the current query and detects loops" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 3, .alias_storage_bytes = 96 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const first = (try r.beginPresentation(.{ .name = "a.example", .qtype = .A }, .{})).send;

    var packet: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, first.id, .{ .response = true });
    try b.addQuestion("a.example", .A, .IN);
    try b.addNameRecord(.answer, "a.example", .CNAME, 60, "b.example");
    const alias_action = try r.onResponse(first.handle, try b.finish());
    try expectActionTag(.send, alias_action);
    try std.testing.expectEqual(DispatchReason.alias, alias_action.send.reason);
    var presentation: [64]u8 = undefined;
    try std.testing.expectEqualStrings("b.example", try r.writeCurrentNamePresentation(first.handle, &presentation));

    var b2 = try builder.Builder.init(&packet, &compression, alias_action.send.id, .{ .response = true });
    try b2.addQuestion("b.example", .A, .IN);
    try b2.addNameRecord(.answer, "b.example", .CNAME, 60, "a.example");
    const loop = try r.onResponse(first.handle, try b2.finish());
    try expectActionTag(.fail, loop);
    try std.testing.expectEqual(FailureReason.alias_loop, loop.fail.reason);
}

test "optional EDNS FORMERR retries once without OPT" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 2, .alias_storage_bytes = 64 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const first = (try r.beginPresentation(.{ .name = "example", .qtype = .A }, .{ .query = .{ .udp_payload_size = 1232 } })).send;

    var packet: [256]u8 = undefined;
    var compression: [12]builder.CompressionEntry = undefined;
    const q = try r.currentQuestion(first.handle);
    const formerr = try responsePacket(&packet, &compression, first, q, .{ .response = true, .rcode_low = 1 });
    const retried = try r.onResponse(first.handle, formerr);
    try expectActionTag(.retry, retried);
    try std.testing.expectEqual(DispatchReason.edns_fallback, retried.retry.reason);
    try std.testing.expect(!retried.retry.edns_enabled);
    try std.testing.expect(first.id != retried.retry.id);

    var query_packet: [256]u8 = undefined;
    const wire = try r.writeQuery(first.handle, &query_packet, &compression, &.{});
    const m = try message.Message.init(wire);
    try std.testing.expectEqual(@as(u16, 0), m.header.additional_count);
}

test "timeout budget rotates to the next caller-owned server" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 2, .alias_storage_bytes = 64 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const first = (try r.beginPresentation(.{ .name = "example", .qtype = .A }, .{ .server_count = 2 })).send;

    const retry1 = try r.onTimeout(first.handle);
    try expectActionTag(.retry, retry1);
    const retry2 = try r.onTimeout(first.handle);
    try expectActionTag(.retry, retry2);
    const next_server = try r.onTimeout(first.handle);
    try expectActionTag(.send, next_server);
    try std.testing.expectEqual(@as(usize, 1), next_server.send.server_index);
    try std.testing.expectEqual(DispatchReason.other_server, next_server.send.reason);
    try std.testing.expect(first.id != next_server.send.id);
}

test "wire-name lifecycle preserves embedded zero octets" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 2, .alias_storage_bytes = 64 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const wire_name = [_]u8{ 3, 'a', 0, 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    const qname = try name_mod.Uncompressed.init(&wire_name);
    const action = (try r.beginWire(.{ .name = qname, .qtype = .AAAA }, .{})).send;

    var packet: [256]u8 = undefined;
    var compression: [12]builder.CompressionEntry = undefined;
    const bytes = try r.writeQuery(action.handle, &packet, &compression, &.{});
    const m = try message.Message.init(bytes);
    var questions = m.questions();
    const q = (try questions.next()).?;
    const expected = try name_mod.Name.init(qname.bytes, 0);
    try std.testing.expect(try q.name.eqlIgnoreCase(expected));
}

test "stale handles cannot release a reused slot" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 1, .alias_storage_bytes = 32 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const first = (try r.beginPresentation(.{ .name = "a", .qtype = .A }, .{})).send;
    try r.release(first.handle);
    const second = (try r.beginPresentation(.{ .name = "b", .qtype = .A }, .{})).send;
    try std.testing.expectError(error.InvalidHandle, r.release(first.handle));
    try std.testing.expectEqual(@as(usize, 1), r.activeCount());
    try r.release(second.handle);
}

test "capacity and EDNS-required policy fail before leaking query state" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 2, .alias_storage_bytes = 64 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);

    try std.testing.expectError(error.EdnsFeatureWithoutOpt, r.beginPresentation(
        .{ .name = "secure.example", .qtype = .A },
        .{ .query = .{ .dnssec_ok = true, .udp_payload_size = null } },
    ));
    try std.testing.expectEqual(@as(usize, 0), r.activeCount());

    const first = (try r.beginPresentation(.{ .name = "a.example", .qtype = .A }, .{})).send;
    try std.testing.expectError(error.Full, r.beginPresentation(.{ .name = "b.example", .qtype = .A }, .{}));
    try std.testing.expectEqual(@as(usize, 1), r.activeCount());
    try r.release(first.handle);
}

test "DNAME continuation validates synthesized CNAME before advancing" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 3, .alias_storage_bytes = 128 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const first = (try r.beginPresentation(.{ .name = "host.old.example", .qtype = .A }, .{})).send;

    var packet: [768]u8 = undefined;
    var compression: [32]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, first.id, .{ .response = true });
    try b.addQuestion("host.old.example", .A, .IN);
    try b.addNameRecord(.answer, "old.example", .DNAME, 300, "new.example");
    try b.addNameRecord(.answer, "host.old.example", .CNAME, 300, "host.new.example");
    const next = try r.onResponse(first.handle, try b.finish());
    try expectActionTag(.send, next);
    try std.testing.expectEqual(DispatchReason.alias, next.send.reason);

    var presentation: [64]u8 = undefined;
    try std.testing.expectEqualStrings("host.new.example", try r.writeCurrentNamePresentation(first.handle, &presentation));
}

test "malformed alias retries another server without mutating the chain" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 3, .alias_storage_bytes = 96 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const first = (try r.beginPresentation(.{ .name = "a.example", .qtype = .A }, .{ .server_count = 2 })).send;

    var packet: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, first.id, .{ .response = true });
    try b.addQuestion("a.example", .A, .IN);
    try b.addRawRecord(.answer, "a.example", .CNAME, .IN, 60, &.{ 3, 'x' });
    const next = try r.onResponse(first.handle, try b.finish());
    try expectActionTag(.send, next);
    try std.testing.expectEqual(DispatchReason.other_server, next.send.reason);

    var presentation: [64]u8 = undefined;
    try std.testing.expectEqualStrings("a.example", try r.writeCurrentNamePresentation(first.handle, &presentation));
}

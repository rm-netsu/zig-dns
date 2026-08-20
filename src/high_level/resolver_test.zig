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
const Transport = high.Transport;
const SecurityStatus = high.SecurityStatus;
const CompletionSource = high.CompletionSource;

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
    try std.testing.expectEqual(Transport.tcp, next.connect_tcp.transport);
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

test "DoT DoQ and DoH produce transport-specific caller actions" {
    const R = Resolver(.{ .max_queries = 4, .max_alias_depth = 2, .alias_storage_bytes = 64 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);

    const dot = try r.beginPresentation(.{ .name = "dot.example", .qtype = .A }, .{ .transport = .dot });
    try expectActionTag(.connect_dot, dot);
    try std.testing.expect(dot.connect_dot.id != 0);

    const doq_a = try r.beginPresentation(.{ .name = "a.doq.example", .qtype = .A }, .{ .transport = .doq });
    const doq_b = try r.beginPresentation(.{ .name = "b.doq.example", .qtype = .AAAA }, .{ .transport = .doq });
    try expectActionTag(.open_doq_stream, doq_a);
    try expectActionTag(.open_doq_stream, doq_b);
    try std.testing.expectEqual(@as(u16, 0), doq_a.open_doq_stream.id);
    try std.testing.expectEqual(@as(u16, 0), doq_b.open_doq_stream.id);

    const doh = try r.beginPresentation(.{ .name = "doh.example", .qtype = .A }, .{ .transport = .doh });
    try expectActionTag(.perform_doh, doh);
    try std.testing.expectEqual(@as(u16, 0), doh.perform_doh.id);
}

test "stream-correlated zero-ID transports require the caller handle" {
    const R = Resolver(.{ .max_queries = 2, .max_alias_depth = 2, .alias_storage_bytes = 64 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const first = (try r.beginPresentation(.{ .name = "a.example", .qtype = .A }, .{ .transport = .doq })).open_doq_stream;
    _ = try r.beginPresentation(.{ .name = "b.example", .qtype = .A }, .{ .transport = .doq });

    const q = try r.currentQuestion(first.handle);
    var packet: [256]u8 = undefined;
    var compression: [12]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 0, .{ .response = true });
    try b.addQuestionWire(q.name, q.qtype, q.qclass);
    try b.addA(.answer, "a.example", 60, .{ 192, 0, 2, 1 });
    const bytes = try b.finish();

    try std.testing.expectError(error.CorrelationHandleRequired, r.matchResponse(bytes));
    const done = try r.onResponse(first.handle, bytes);
    try expectActionTag(.complete, done);
    try std.testing.expectEqual(CompletionKind.answer, done.complete.kind);
}

test "referral pauses for caller server selection and resumes without changing QNAME" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 3, .alias_storage_bytes = 128 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const first = (try r.beginPresentation(.{ .name = "host.child.example", .qtype = .A }, .{})).send;

    var packet: [1024]u8 = undefined;
    var compression: [48]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, first.id, .{ .response = true });
    try b.addQuestion("host.child.example", .A, .IN);
    try b.addNameRecord(.authority, "child.example", .NS, 3600, "ns1.child.example");
    try b.addA(.additional, "ns1.child.example", 3600, .{ 192, 0, 2, 53 });
    const action = try r.onResponse(first.handle, try b.finish());
    try expectActionTag(.referral, action);

    var ns = try action.referral.view.nameServers();
    const first_ns = (try ns.next()).?;
    var ns_name: [64]u8 = undefined;
    try std.testing.expectEqualStrings("ns1.child.example", try first_ns.target.writePresentation(&ns_name));

    try std.testing.expectError(error.NoServers, r.followReferral(first.handle, 0, .udp));
    const next = try r.followReferral(first.handle, 2, .udp);
    try expectActionTag(.send, next);
    try std.testing.expectEqual(DispatchReason.referral, next.send.reason);
    try std.testing.expectEqual(@as(usize, 0), next.send.server_index);
    try std.testing.expect(first.id != next.send.id);

    var qname: [64]u8 = undefined;
    try std.testing.expectEqualStrings("host.child.example", try r.writeCurrentNamePresentation(first.handle, &qname));
}

test "stub integration can accept a referral as terminal" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 2, .alias_storage_bytes = 96 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const first = (try r.beginPresentation(.{ .name = "host.child.example", .qtype = .A }, .{})).send;

    var packet: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, first.id, .{ .response = true });
    try b.addQuestion("host.child.example", .A, .IN);
    try b.addNameRecord(.authority, "child.example", .NS, 300, "ns.child.example");
    const referral = try r.onResponse(first.handle, try b.finish());
    try expectActionTag(.referral, referral);
    try std.testing.expectError(error.UnexpectedState, r.onTimeout(first.handle));

    const done = try r.acceptReferral(first.handle);
    try expectActionTag(.complete, done);
    try std.testing.expectEqual(CompletionKind.referral, done.complete.kind);
}

const TestCache = struct {
    hit: ?high.CacheHit = null,
    stores: usize = 0,
    stored_kind: high.CompletionKind = .answer,
    stored_security: SecurityStatus = .indeterminate,
    stored_now: u64 = 0,

    fn lookup(context: *anyopaque, q: client.WireQuestionKey, now: u64) ?high.CacheHit {
        _ = q;
        _ = now;
        const self: *TestCache = @ptrCast(@alignCast(context));
        return self.hit;
    }

    fn store(context: *anyopaque, q: client.WireQuestionKey, kind: high.CompletionKind, security: SecurityStatus, msg: message.Message, now: u64) void {
        _ = q;
        _ = msg;
        const self: *TestCache = @ptrCast(@alignCast(context));
        self.stores += 1;
        self.stored_kind = kind;
        self.stored_security = security;
        self.stored_now = now;
    }

    fn hooks(self: *TestCache) high.CacheHooks {
        return .{ .context = self, .lookup = lookup, .store = store };
    }
};

test "cache hook can complete before any network dispatch" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 2, .alias_storage_bytes = 64 });
    var storage: R.Storage = undefined;
    var cache: TestCache = .{ .hit = .{ .kind = .answer, .security = .secure, .token = 7 } };
    var r = R.initInPlaceWithCache(&storage, cache.hooks());

    const action = try r.beginPresentation(.{ .name = "cached.example", .qtype = .A }, .{ .now = 100 });
    try expectActionTag(.complete, action);
    try std.testing.expectEqual(CompletionSource.cache, action.complete.source);
    try std.testing.expectEqual(SecurityStatus.secure, action.complete.security);
    try std.testing.expectEqual(@as(?usize, 7), action.complete.cache_token);

    var packet: [128]u8 = undefined;
    var compression: [8]builder.CompressionEntry = undefined;
    try std.testing.expectError(error.UnexpectedState, r.writeQuery(action.complete.handle, &packet, &compression, &.{}));
    try r.release(action.complete.handle);
}

test "validated network completion stores security and injected response time" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 2, .alias_storage_bytes = 64 });
    var storage: R.Storage = undefined;
    var cache: TestCache = .{};
    var r = R.initInPlaceWithCache(&storage, cache.hooks());
    const first = (try r.beginPresentation(.{ .name = "secure.example", .qtype = .A }, .{ .now = 10 })).send;

    const q = try r.currentQuestion(first.handle);
    var packet: [256]u8 = undefined;
    var compression: [12]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, first.id, .{ .response = true });
    try b.addQuestionWire(q.name, q.qtype, q.qclass);
    try b.addA(.answer, "secure.example", 60, .{ 192, 0, 2, 1 });
    const done = try r.onValidatedResponse(first.handle, try b.finish(), 25, .secure);

    try expectActionTag(.complete, done);
    try std.testing.expectEqual(CompletionSource.network, done.complete.source);
    try std.testing.expectEqual(SecurityStatus.secure, done.complete.security);
    try std.testing.expectEqual(@as(usize, 1), cache.stores);
    try std.testing.expectEqual(high.CompletionKind.answer, cache.stored_kind);
    try std.testing.expectEqual(SecurityStatus.secure, cache.stored_security);
    try std.testing.expectEqual(@as(u64, 25), cache.stored_now);
}

test "DNSSEC status is conservatively composed across alias hops" {
    const R = Resolver(.{ .max_queries = 1, .max_alias_depth = 3, .alias_storage_bytes = 96 });
    var storage: R.Storage = undefined;
    var r = R.initInPlace(&storage);
    const first = (try r.beginPresentation(.{ .name = "a.example", .qtype = .A }, .{})).send;

    var packet: [512]u8 = undefined;
    var compression: [24]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, first.id, .{ .response = true });
    try b.addQuestion("a.example", .A, .IN);
    try b.addNameRecord(.answer, "a.example", .CNAME, 60, "b.example");
    const alias_action = try r.onValidatedResponse(first.handle, try b.finish(), 1, .secure);
    try expectActionTag(.send, alias_action);

    var b2 = try builder.Builder.init(&packet, &compression, alias_action.send.id, .{ .response = true });
    try b2.addQuestion("b.example", .A, .IN);
    try b2.addA(.answer, "b.example", 60, .{ 192, 0, 2, 2 });
    const done = try r.onValidatedResponse(first.handle, try b2.finish(), 2, .insecure);
    try expectActionTag(.complete, done);
    try std.testing.expectEqual(SecurityStatus.insecure, done.complete.security);
}

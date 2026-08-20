const std = @import("std");
const types = @import("../types.zig");
const builder = @import("../builder.zig");
const high = @import("resolver.zig");

const Resolver = high.Resolver;
const Action = high.Action;
const Dispatch = high.Dispatch;
const Handle = high.Handle;

const names = [_][]const u8{
    "a.example",
    "b.example",
    "c.example",
    "d.example",
    "e.example",
    "f.example",
    "g.example",
    "h.example",
};

const ModelSlot = struct {
    handle: ?Handle = null,
    dispatch: ?Dispatch = null,
};

fn next(state: *u64) u64 {
    state.* = state.* *% 6364136223846793005 +% 1442695040888963407;
    return state.*;
}

fn dispatchFrom(action: Action) ?Dispatch {
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

fn recordAction(model: *[4]ModelSlot, action: Action) !void {
    switch (action) {
        .send, .retry, .connect_tcp, .connect_dot, .open_doq_stream, .perform_doh => {
            const d = dispatchFrom(action).?;
            try std.testing.expect(d.handle.index < model.len);
            model[d.handle.index].handle = d.handle;
            model[d.handle.index].dispatch = d;
        },
        .referral => |r| {
            try std.testing.expect(r.handle.index < model.len);
            model[r.handle.index].handle = r.handle;
            model[r.handle.index].dispatch = null;
        },
        .complete => |c| {
            try std.testing.expect(c.handle.index < model.len);
            model[c.handle.index].handle = c.handle;
            model[c.handle.index].dispatch = null;
        },
        .fail => |f| {
            try std.testing.expect(f.handle.index < model.len);
            model[f.handle.index].handle = f.handle;
            model[f.handle.index].dispatch = null;
        },
    }
}

fn validAnswer(R: type, resolver: *R, d: Dispatch, packet: []u8, compression: []builder.CompressionEntry) ![]const u8 {
    const q = try resolver.currentQuestion(d.handle);
    var b = try builder.Builder.init(packet, compression, d.id, .{ .response = true, .authoritative = true });
    try b.addQuestionWire(q.name, q.qtype, q.qclass);
    try b.addRawRecordWire(.answer, q.name, .A, .IN, 60, &.{ 192, 0, 2, 1 });
    return b.finish();
}

test "high-level resolver deterministic lifecycle replay" {
    const R = Resolver(.{ .max_queries = 4, .max_alias_depth = 4, .alias_storage_bytes = 128 });

    // Multiple seeds intentionally exercise different slot reuse, retry, and
    // generation patterns while remaining deterministic in normal CI.
    for (0..32) |seed_index| {
        var storage: R.Storage = undefined;
        var resolver = R.initInPlace(&storage);
        var model = [_]ModelSlot{.{}} ** 4;
        var stale: ?Handle = null;
        var state: u64 = 0x9e3779b97f4a7c15 ^ @as(u64, @intCast(seed_index));

        for (0..256) |_| {
            const roll = next(&state);
            const active = resolver.activeCount();

            if ((roll & 3) == 0 and active < model.len) {
                const transport: high.Transport = switch ((roll >> 8) % 5) {
                    0 => .udp,
                    1 => .tcp,
                    2 => .dot,
                    3 => .doq,
                    else => .doh,
                };
                const name = names[@intCast((roll >> 16) % names.len)];
                const action = try resolver.beginPresentation(.{ .name = name, .qtype = .A }, .{
                    .server_count = 1 + @as(usize, @intCast((roll >> 24) % 3)),
                    .transport = transport,
                });
                try recordAction(&model, action);
            } else if (active != 0) {
                var index: usize = @intCast((roll >> 32) % model.len);
                var attempts: usize = 0;
                while (model[index].handle == null and attempts < model.len) : (attempts += 1) {
                    index = (index + 1) % model.len;
                }
                const handle = model[index].handle orelse continue;
                const op = (roll >> 40) % 5;

                if (model[index].dispatch) |d| {
                    const action = switch (op) {
                        0 => try resolver.onTimeout(handle),
                        1 => try resolver.onTransportFailure(handle),
                        2 => blk: {
                            var packet: [512]u8 = undefined;
                            var compression: [24]builder.CompressionEntry = undefined;
                            const bytes = try validAnswer(R, &resolver, d, &packet, &compression);
                            break :blk try resolver.onResponse(handle, bytes);
                        },
                        3 => try resolver.onResponse(handle, &.{ 0, 1, 2 }),
                        else => {
                            var out: [512]u8 = undefined;
                            var compression: [24]builder.CompressionEntry = undefined;
                            const query = try resolver.writeQuery(handle, &out, &compression, &.{});
                            try std.testing.expect(query.len >= 12);
                            continue;
                        },
                    };
                    try recordAction(&model, action);
                    switch (action) {
                        .complete, .fail => {
                            stale = handle;
                            try resolver.release(handle);
                            model[index] = .{};
                        },
                        .referral => {
                            // This replay does not manufacture referrals, but
                            // keep its state model correct if that changes.
                        },
                        else => {},
                    }
                }
            }

            try std.testing.expect(resolver.activeCount() <= model.len);
            var model_active: usize = 0;
            for (model) |slot| model_active += @intFromBool(slot.handle != null);
            try std.testing.expectEqual(model_active, resolver.activeCount());

            if (stale) |old| {
                // Once a terminal slot has been released, a generation-checked
                // stale handle must never address a later occupant of it.
                try std.testing.expectError(error.InvalidHandle, resolver.currentQuestion(old));
                stale = null;
            }
        }

        // Drain all still-active queries through explicit release and verify
        // no slot remains retained after the replay.
        for (&model) |*slot| {
            if (slot.handle) |handle| {
                try resolver.release(handle);
                slot.* = .{};
            }
        }
        try std.testing.expectEqual(@as(usize, 0), resolver.activeCount());
    }
}

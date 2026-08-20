const std = @import("std");
const types = @import("types.zig");
const name_mod = @import("name.zig");
const dnssec = @import("dnssec.zig");

pub const Kind = enum {
    positive,
    nxdomain,
    nodata,
    delegation,
};

pub const Meta = struct {
    kind: Kind,
    rr_type: types.Type = .A,
    class: types.Class = .IN,
    security: dnssec.SecurityStatus = .indeterminate,
    expires_at: u64,
};

pub fn expiresAt(now: u64, ttl_seconds: u32) u64 {
    return now +| @as(u64, ttl_seconds);
}

pub const Error = name_mod.Error || error{
    Full,
    InvalidReplacement,
    NameTooLong,
};

/// Fixed-capacity cache metadata/value store with no allocator or timer
/// ownership. `Payload` is caller-defined: it can be an RRset handle, an
/// offset into a caller-owned arena, or an inline bounded value.
///
/// The cache stores canonical wire names in each slot. When all slots are
/// live, callers choose replacement policy explicitly by passing a slot index
/// to `put*`; `null` returns `error.Full` instead of silently evicting data.
pub fn Fixed(comptime Payload: type, comptime capacity: usize, comptime max_name_wire: usize) type {
    if (max_name_wire == 0 or max_name_wire > name_mod.Name.max_wire_len)
        @compileError("max_name_wire must be in 1..255");

    return struct {
        const Self = @This();

        const Slot = struct {
            active: bool,
            meta: Meta = undefined,
            name_len: u16 = 0,
            name: [max_name_wire]u8 = undefined,
            payload: Payload = undefined,
        };

        pub const Hit = struct {
            index: usize,
            meta: Meta,
            name: []const u8,
            payload: *Payload,
        };

        pub const SlotView = struct {
            index: usize,
            meta: Meta,
            name: []const u8,
            expired: bool,
        };

        slots: [capacity]Slot,

        pub fn init() Self {
            var self: Self = undefined;
            for (&self.slots) |*slot| slot.active = false;
            return self;
        }

        pub fn activeCount(self: *const Self, now: u64) usize {
            var count: usize = 0;
            for (&self.slots) |*slot| {
                if (slot.active and slot.meta.expires_at > now) count += 1;
            }
            return count;
        }

        /// Mark expired entries reusable and return how many were removed.
        pub fn expire(self: *Self, now: u64) usize {
            var removed: usize = 0;
            for (&self.slots) |*slot| {
                if (slot.active and slot.meta.expires_at <= now) {
                    slot.active = false;
                    removed += 1;
                }
            }
            return removed;
        }

        /// Inspect one slot so a caller can implement any replacement policy.
        /// Inactive slots return null; expired slots remain visible until
        /// `expire()` or a subsequent cache operation reuses them.
        pub fn slotView(self: *const Self, index: usize, now: u64) ?SlotView {
            if (index >= capacity) return null;
            const slot = &self.slots[index];
            if (!slot.active) return null;
            return .{
                .index = index,
                .meta = slot.meta,
                .name = slot.name[0..slot.name_len],
                .expired = slot.meta.expires_at <= now,
            };
        }

        /// Return the first inactive or expired slot. This is a convenience,
        /// not an eviction policy; callers may inspect all slots instead.
        pub fn reusableSlot(self: *const Self, now: u64) ?usize {
            for (&self.slots, 0..) |*slot, i| {
                if (!slot.active or slot.meta.expires_at <= now) return i;
            }
            return null;
        }

        pub fn putPresentation(
            self: *Self,
            presentation: []const u8,
            meta: Meta,
            payload: Payload,
            now: u64,
            replacement: ?usize,
        ) Error!usize {
            var wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
            const wire = try name_mod.writePresentationWire(presentation, &wire_buf);
            return self.putWire(try name_mod.Uncompressed.init(wire), meta, payload, now, replacement);
        }

        pub fn putWire(
            self: *Self,
            name: name_mod.Uncompressed,
            meta: Meta,
            payload: Payload,
            now: u64,
            replacement: ?usize,
        ) Error!usize {
            var canonical_buf: [name_mod.Name.max_wire_len]u8 = undefined;
            const canonical = try (try name_mod.Name.init(name.bytes, 0)).writeCanonicalWire(&canonical_buf);
            if (canonical.len > max_name_wire) return error.NameTooLong;

            var index = self.findLogicalKey(canonical, meta);
            if (index == null) index = self.reusableSlot(now);
            if (index == null) {
                const requested = replacement orelse return error.Full;
                if (requested >= capacity) return error.InvalidReplacement;
                index = requested;
            }

            const i = index.?;
            var slot = &self.slots[i];
            @memcpy(slot.name[0..canonical.len], canonical);
            slot.name_len = @intCast(canonical.len);
            slot.meta = meta;
            slot.payload = payload;
            slot.active = true;
            return i;
        }

        /// Lookup positive/NODATA/NXDOMAIN data for one query. NXDOMAIN is
        /// name-wide and therefore matches any query type; positive/NODATA are
        /// qtype-specific. Expired entries are lazily invalidated.
        pub fn lookupPresentation(self: *Self, presentation: []const u8, rr_type: types.Type, class: types.Class, now: u64) Error!?Hit {
            var wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
            const wire = try name_mod.writePresentationWire(presentation, &wire_buf);
            return self.lookupWire(try name_mod.Uncompressed.init(wire), rr_type, class, now);
        }

        pub fn lookupWire(self: *Self, name: name_mod.Uncompressed, rr_type: types.Type, class: types.Class, now: u64) Error!?Hit {
            var canonical_buf: [name_mod.Name.max_wire_len]u8 = undefined;
            const canonical = try (try name_mod.Name.init(name.bytes, 0)).writeCanonicalWire(&canonical_buf);

            // Name-wide NXDOMAIN wins over any contradictory per-type entry.
            for (&self.slots, 0..) |*slot, i| {
                if (!self.live(slot, now)) continue;
                if (slot.meta.kind != .nxdomain or slot.meta.class != class) continue;
                if (std.mem.eql(u8, slot.name[0..slot.name_len], canonical)) return hit(slot, i);
            }
            for (&self.slots, 0..) |*slot, i| {
                if (!self.live(slot, now)) continue;
                if (slot.meta.class != class or slot.meta.rr_type != rr_type) continue;
                if (slot.meta.kind != .positive and slot.meta.kind != .nodata) continue;
                if (std.mem.eql(u8, slot.name[0..slot.name_len], canonical)) return hit(slot, i);
            }
            return null;
        }

        /// Return the deepest cached delegation containing `qname`.
        pub fn findDelegationPresentation(self: *Self, presentation: []const u8, class: types.Class, now: u64) Error!?Hit {
            var wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
            const wire = try name_mod.writePresentationWire(presentation, &wire_buf);
            return self.findDelegationWire(try name_mod.Uncompressed.init(wire), class, now);
        }

        pub fn findDelegationWire(self: *Self, qname: name_mod.Uncompressed, class: types.Class, now: u64) Error!?Hit {
            const query = try name_mod.Name.init(qname.bytes, 0);
            var best: ?usize = null;
            var best_len: usize = 0;
            for (&self.slots, 0..) |*slot, i| {
                if (!self.live(slot, now)) continue;
                if (slot.meta.kind != .delegation or slot.meta.class != class) continue;
                const zone = try name_mod.Name.init(slot.name[0..slot.name_len], 0);
                if (!try query.isSubdomainOf(zone)) continue;
                if (slot.name_len > best_len) {
                    best = i;
                    best_len = slot.name_len;
                }
            }
            if (best) |i| return hit(&self.slots[i], i);
            return null;
        }

        fn live(self: *Self, slot: *Slot, now: u64) bool {
            _ = self;
            if (!slot.active) return false;
            if (slot.meta.expires_at <= now) {
                slot.active = false;
                return false;
            }
            return true;
        }

        fn findLogicalKey(self: *const Self, canonical: []const u8, meta: Meta) ?usize {
            for (&self.slots, 0..) |*slot, i| {
                if (!slot.active or slot.meta.class != meta.class) continue;
                if (!std.mem.eql(u8, slot.name[0..slot.name_len], canonical)) continue;
                const same = switch (meta.kind) {
                    .positive, .nodata => (slot.meta.kind == .positive or slot.meta.kind == .nodata) and slot.meta.rr_type == meta.rr_type,
                    .nxdomain => slot.meta.kind == .nxdomain,
                    .delegation => slot.meta.kind == .delegation,
                };
                if (same) return i;
            }
            return null;
        }

        fn hit(slot: *Slot, index: usize) Hit {
            return .{
                .index = index,
                .meta = slot.meta,
                .name = slot.name[0..slot.name_len],
                .payload = &slot.payload,
            };
        }
    };
}

test "fixed cache stores positive NODATA and name-wide NXDOMAIN" {
    const Cache = Fixed(u32, 4, 64);
    var cache = Cache.init();
    _ = try cache.putPresentation("WWW.Example", .{
        .kind = .positive,
        .rr_type = .A,
        .security = .secure,
        .expires_at = expiresAt(100, 60),
    }, 11, 100, null);
    _ = try cache.putPresentation("www.example", .{
        .kind = .nodata,
        .rr_type = .AAAA,
        .security = .secure,
        .expires_at = expiresAt(100, 30),
    }, 12, 100, null);

    const a = (try cache.lookupPresentation("www.example.", .A, .IN, 110)).?;
    try std.testing.expectEqual(@as(u32, 11), a.payload.*);
    try std.testing.expectEqual(dnssec.SecurityStatus.secure, a.meta.security);
    const aaaa = (try cache.lookupPresentation("WWW.EXAMPLE", .AAAA, .IN, 110)).?;
    try std.testing.expectEqual(Kind.nodata, aaaa.meta.kind);

    _ = try cache.putPresentation("www.example", .{
        .kind = .nxdomain,
        .security = .bogus,
        .expires_at = expiresAt(110, 10),
    }, 13, 110, null);
    const nx = (try cache.lookupPresentation("www.example", .TXT, .IN, 111)).?;
    try std.testing.expectEqual(Kind.nxdomain, nx.meta.kind);
    try std.testing.expectEqual(@as(u32, 13), nx.payload.*);
    try std.testing.expect((try cache.lookupPresentation("www.example", .TXT, .IN, 120)) == null);
}

test "fixed cache finds deepest live delegation" {
    const Cache = Fixed(u8, 4, 64);
    var cache = Cache.init();
    _ = try cache.putPresentation("example", .{
        .kind = .delegation,
        .expires_at = 1000,
    }, 1, 0, null);
    _ = try cache.putPresentation("child.example", .{
        .kind = .delegation,
        .expires_at = 1000,
    }, 2, 0, null);
    _ = try cache.putPresentation("expired.child.example", .{
        .kind = .delegation,
        .expires_at = 5,
    }, 3, 0, null);

    const hit = (try cache.findDelegationPresentation("host.expired.child.example", .IN, 10)).?;
    try std.testing.expectEqual(@as(u8, 2), hit.payload.*);
    var presentation: [64]u8 = undefined;
    try std.testing.expectEqualStrings("child.example", try (try name_mod.Name.init(hit.name, 0)).writePresentation(&presentation));
}

test "replacement slot stays caller controlled" {
    const Cache = Fixed(u8, 2, 64);
    var cache = Cache.init();
    _ = try cache.putPresentation("a.example", .{ .kind = .positive, .rr_type = .A, .expires_at = 100 }, 1, 0, null);
    _ = try cache.putPresentation("b.example", .{ .kind = .positive, .rr_type = .A, .expires_at = 200 }, 2, 0, null);
    try std.testing.expectError(error.Full, cache.putPresentation("c.example", .{ .kind = .positive, .rr_type = .A, .expires_at = 300 }, 3, 0, null));

    const view = cache.slotView(0, 0).?;
    try std.testing.expect(!view.expired);
    _ = try cache.putPresentation("c.example", .{ .kind = .positive, .rr_type = .A, .expires_at = 300 }, 3, 0, 0);
    try std.testing.expect((try cache.lookupPresentation("a.example", .A, .IN, 1)) == null);
    try std.testing.expectEqual(@as(u8, 3), (try cache.lookupPresentation("c.example", .A, .IN, 1)).?.payload.*);
}

test "expired slots are reused and expiration saturates" {
    try std.testing.expectEqual(std.math.maxInt(u64), expiresAt(std.math.maxInt(u64) - 1, 60));
    const Cache = Fixed(u8, 1, 64);
    var cache = Cache.init();
    _ = try cache.putPresentation("old.example", .{ .kind = .positive, .rr_type = .A, .expires_at = 5 }, 1, 0, null);
    try std.testing.expectEqual(@as(?usize, 0), cache.reusableSlot(5));
    _ = try cache.putPresentation("new.example", .{ .kind = .positive, .rr_type = .A, .expires_at = 50 }, 2, 5, null);
    try std.testing.expectEqual(@as(usize, 1), cache.activeCount(5));
}

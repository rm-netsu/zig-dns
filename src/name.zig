const std = @import("std");

pub const Error = error{ Truncated, InvalidLabel, InvalidPointer, PointerLoop, NameTooLong, LabelTooLong, BufferTooSmall, InvalidPresentation };

pub const Name = struct {
    packet: []const u8,
    offset: u16,

    pub const max_wire_len = 255;
    pub const max_presentation_len = 253;

    pub fn init(packet: []const u8, offset: usize) Error!Name {
        if (offset >= packet.len or offset > std.math.maxInt(u16)) return error.Truncated;
        _ = try consumedLen(packet, offset);
        return .{ .packet = packet, .offset = @intCast(offset) };
    }

    pub fn consumed(self: Name) Error!usize {
        return consumedLen(self.packet, self.offset);
    }

    pub fn writePresentation(self: Name, out: []u8) Error![]const u8 {
        var source: usize = self.offset;
        var dst: usize = 0;
        var expanded: usize = 1;
        var jumps: usize = 0;
        while (true) {
            if (source >= self.packet.len) return error.Truncated;
            const first = self.packet[source];
            if (first == 0) return out[0..dst];
            if ((first & 0xc0) == 0xc0) {
                if (source + 1 >= self.packet.len) return error.Truncated;
                const target = (@as(usize, first & 0x3f) << 8) | self.packet[source + 1];
                if (target >= source) return error.InvalidPointer;
                source = target;
                jumps += 1;
                if (jumps > self.packet.len / 2 + 1) return error.PointerLoop;
                continue;
            }
            if ((first & 0xc0) != 0) return error.InvalidLabel;
            const len: usize = first;
            if (len > 63) return error.LabelTooLong;
            if (source + 1 + len > self.packet.len) return error.Truncated;
            expanded += len + 1;
            if (expanded > max_wire_len) return error.NameTooLong;
            if (dst != 0) {
                if (dst == out.len) return error.BufferTooSmall;
                out[dst] = '.';
                dst += 1;
            }
            if (dst + len > out.len) return error.BufferTooSmall;
            @memcpy(out[dst..][0..len], self.packet[source + 1 ..][0..len]);
            dst += len;
            source += len + 1;
        }
    }

    pub fn writeWire(self: Name, out: []u8) Error![]const u8 {
        return writeWireExpanded(self, out, false);
    }

    pub fn writeCanonicalWire(self: Name, out: []u8) Error![]const u8 {
        return writeWireExpanded(self, out, true);
    }

    pub fn eqlIgnoreCase(self: Name, other: Name) Error!bool {
        var a_buf: [max_wire_len]u8 = undefined;
        var b_buf: [max_wire_len]u8 = undefined;
        const a = try self.writeCanonicalWire(&a_buf);
        const b = try other.writeCanonicalWire(&b_buf);
        return std.mem.eql(u8, a, b);
    }

    pub fn eqlPresentationIgnoreCase(self: Name, presentation: []const u8) Error!bool {
        var actual_buf: [max_wire_len]u8 = undefined;
        var expected_buf: [max_wire_len]u8 = undefined;
        const actual = try self.writeCanonicalWire(&actual_buf);
        const expected = try presentationWire(presentation, &expected_buf, true);
        return std.mem.eql(u8, actual, expected);
    }

    /// RFC 4034 section 6.1 canonical DNS name ordering.
    ///
    /// Labels are compared from the root towards the left-most label, using
    /// unsigned octets with ASCII case folded to lowercase. No allocation is
    /// performed; compressed names are expanded into bounded stack buffers.
    pub fn canonicalCompare(self: Name, other: Name) Error!std.math.Order {
        var a_buf: [max_wire_len]u8 = undefined;
        var b_buf: [max_wire_len]u8 = undefined;
        const a = try self.writeCanonicalWire(&a_buf);
        const b = try other.writeCanonicalWire(&b_buf);
        return canonicalWireOrder(a, b);
    }
};

fn canonicalWireOrder(a: []const u8, b: []const u8) std.math.Order {
    // A 255-octet wire name can contain at most 127 non-root labels.
    var a_offsets: [127]u8 = undefined;
    var b_offsets: [127]u8 = undefined;
    const a_count = labelOffsets(a, &a_offsets);
    const b_count = labelOffsets(b, &b_offsets);

    const common = @min(a_count, b_count);
    for (0..common) |depth| {
        const a_off: usize = a_offsets[a_count - 1 - depth];
        const b_off: usize = b_offsets[b_count - 1 - depth];
        const a_len: usize = a[a_off];
        const b_len: usize = b[b_off];
        const order = std.mem.order(u8, a[a_off + 1 ..][0..a_len], b[b_off + 1 ..][0..b_len]);
        if (order != .eq) return order;
    }
    return std.math.order(a_count, b_count);
}

fn labelOffsets(wire: []const u8, offsets: *[127]u8) usize {
    var pos: usize = 0;
    var count: usize = 0;
    while (wire[pos] != 0) {
        std.debug.assert(count < offsets.len);
        std.debug.assert(pos <= std.math.maxInt(u8));
        offsets[count] = @intCast(pos);
        count += 1;
        pos += 1 + wire[pos];
    }
    return count;
}

pub fn consumedLen(packet: []const u8, start: usize) Error!usize {
    var i = start;
    var expanded: usize = 1;
    var consumed: ?usize = null;
    var jumps: usize = 0;
    while (true) {
        if (i >= packet.len) return error.Truncated;
        const first = packet[i];
        if (first == 0) return consumed orelse (i + 1 - start);
        if ((first & 0xc0) == 0xc0) {
            if (i + 1 >= packet.len) return error.Truncated;
            const target = (@as(usize, first & 0x3f) << 8) | packet[i + 1];
            if (target >= packet.len) return error.Truncated;
            if (target >= i) return error.InvalidPointer;
            if (consumed == null) consumed = i + 2 - start;
            i = target;
            jumps += 1;
            if (jumps > packet.len / 2 + 1) return error.PointerLoop;
            continue;
        }
        if ((first & 0xc0) != 0) return error.InvalidLabel;
        const len: usize = first;
        if (len > 63) return error.LabelTooLong;
        if (i + 1 + len > packet.len) return error.Truncated;
        expanded += len + 1;
        if (expanded > Name.max_wire_len) return error.NameTooLong;
        i += 1 + len;
    }
}

pub fn validatePresentation(name: []const u8) Error!void {
    if (name.len == 0 or std.mem.eql(u8, name, ".")) return;
    var total: usize = 1;
    var it = std.mem.splitScalar(u8, if (name[name.len - 1] == '.') name[0 .. name.len - 1] else name, '.');
    while (it.next()) |label| {
        if (label.len == 0) return error.InvalidPresentation;
        if (label.len > 63) return error.LabelTooLong;
        total += label.len + 1;
        if (total > Name.max_wire_len) return error.NameTooLong;
    }
}

pub fn writePresentationWire(presentation: []const u8, out: []u8) Error![]const u8 {
    return presentationWire(presentation, out, false);
}

fn presentationWire(presentation: []const u8, out: []u8, canonical: bool) Error![]const u8 {
    try validatePresentation(presentation);
    if (out.len == 0) return error.BufferTooSmall;
    if (presentation.len == 0 or std.mem.eql(u8, presentation, ".")) {
        out[0] = 0;
        return out[0..1];
    }
    const clean = if (presentation[presentation.len - 1] == '.') presentation[0 .. presentation.len - 1] else presentation;
    var pos: usize = 0;
    var it = std.mem.splitScalar(u8, clean, '.');
    while (it.next()) |label| {
        if (pos + 1 + label.len >= out.len) return error.BufferTooSmall;
        out[pos] = @intCast(label.len);
        pos += 1;
        if (canonical) {
            for (label) |c| {
                out[pos] = std.ascii.toLower(c);
                pos += 1;
            }
        } else {
            @memcpy(out[pos..][0..label.len], label);
            pos += label.len;
        }
    }
    if (pos >= out.len) return error.BufferTooSmall;
    out[pos] = 0;
    return out[0 .. pos + 1];
}

test "compressed name expansion" {
    const packet = [_]u8{ 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 4, 'm', 'a', 'i', 'l', 0xc0, 4 };
    const n = try Name.init(&packet, 17);
    var out: [64]u8 = undefined;
    try std.testing.expectEqualStrings("mail.example.com", try n.writePresentation(&out));
    try std.testing.expectEqual(@as(usize, 7), try n.consumed());
}

test "compression loop rejected" {
    const packet = [_]u8{ 0xc0, 0x00 };
    try std.testing.expectError(error.InvalidPointer, Name.init(&packet, 0));
}

pub const Uncompressed = struct {
    bytes: []const u8,

    pub fn init(bytes: []const u8) Error!Uncompressed {
        if (bytes.len == 0 or bytes.len > Name.max_wire_len) return error.InvalidPresentation;
        var pos: usize = 0;
        while (true) {
            if (pos >= bytes.len) return error.Truncated;
            const len: usize = bytes[pos];
            if ((bytes[pos] & 0xc0) != 0) return error.InvalidLabel;
            if (len == 0) {
                if (pos + 1 != bytes.len) return error.InvalidLabel;
                return .{ .bytes = bytes };
            }
            if (len > 63) return error.LabelTooLong;
            if (pos + 1 + len > bytes.len) return error.Truncated;
            pos += 1 + len;
        }
    }
};

fn writeWireExpanded(self: Name, out: []u8, canonical: bool) Error![]const u8 {
    var source: usize = self.offset;
    var dst: usize = 0;
    var expanded: usize = 1;
    var jumps: usize = 0;
    while (true) {
        if (source >= self.packet.len) return error.Truncated;
        const first = self.packet[source];
        if (first == 0) {
            if (dst == out.len) return error.BufferTooSmall;
            out[dst] = 0;
            return out[0 .. dst + 1];
        }
        if ((first & 0xc0) == 0xc0) {
            if (source + 1 >= self.packet.len) return error.Truncated;
            const target = (@as(usize, first & 0x3f) << 8) | self.packet[source + 1];
            if (target >= source) return error.InvalidPointer;
            source = target;
            jumps += 1;
            if (jumps > self.packet.len / 2 + 1) return error.PointerLoop;
            continue;
        }
        if ((first & 0xc0) != 0) return error.InvalidLabel;
        const len: usize = first;
        if (len > 63) return error.LabelTooLong;
        if (source + 1 + len > self.packet.len) return error.Truncated;
        expanded += len + 1;
        if (expanded > Name.max_wire_len) return error.NameTooLong;
        if (dst + 1 + len > out.len) return error.BufferTooSmall;
        out[dst] = first;
        if (canonical) {
            for (self.packet[source + 1 ..][0..len], 0..) |c, j| out[dst + 1 + j] = std.ascii.toLower(c);
        } else {
            @memcpy(out[dst + 1 ..][0..len], self.packet[source + 1 ..][0..len]);
        }
        dst += 1 + len;
        source += 1 + len;
    }
}

pub fn uncompressedConsumedLen(packet: []const u8, start: usize) Error!usize {
    var pos = start;
    var total: usize = 0;
    while (true) {
        if (pos >= packet.len) return error.Truncated;
        const len: usize = packet[pos];
        if ((packet[pos] & 0xc0) != 0) return error.InvalidLabel;
        total += 1;
        if (total > Name.max_wire_len) return error.NameTooLong;
        if (len == 0) return total;
        if (len > 63 or pos + 1 + len > packet.len) return error.InvalidLabel;
        total += len;
        if (total > Name.max_wire_len) return error.NameTooLong;
        pos += 1 + len;
    }
}

test "arbitrary octet labels round trip to wire" {
    const packet = [_]u8{ 3, 0, '.', 0xff, 0 };
    const n = try Name.init(&packet, 0);
    var out: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &packet, try n.writeWire(&out));
    _ = try Uncompressed.init(&packet);
}

test "name equality preserves label boundaries" {
    const one_label = [_]u8{ 3, 'a', '.', 'b', 0 };
    const two_labels = [_]u8{ 1, 'a', 1, 'b', 0 };
    const a = try Name.init(&one_label, 0);
    const b = try Name.init(&two_labels, 0);
    try std.testing.expect(!(try a.eqlIgnoreCase(b)));
    try std.testing.expect(!(try a.eqlPresentationIgnoreCase("a.b")));
    try std.testing.expect(try b.eqlPresentationIgnoreCase("A.B."));
}

test "canonical DNS name order matches RFC 4034" {
    const names = [_][]const u8{
        &.{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 },
        &.{ 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 },
        &.{ 8, 'y', 'l', 'j', 'k', 'j', 'l', 'j', 'k', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 },
        &.{ 1, 'Z', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 },
        &.{ 4, 'z', 'A', 'B', 'C', 1, 'a', 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0 },
        &.{ 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 },
        &.{ 1, 1, 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 },
        &.{ 1, '*', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 },
        &.{ 1, 0x80, 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 },
    };
    for (names, 0..) |wire_a, i| {
        const a = try Name.init(wire_a, 0);
        for (names, 0..) |wire_b, j| {
            const b = try Name.init(wire_b, 0);
            const expected: std.math.Order = if (i < j) .lt else if (i > j) .gt else .eq;
            try std.testing.expectEqual(expected, try a.canonicalCompare(b));
        }
    }
}

test "canonical DNS name order expands compression and folds ASCII case" {
    const packet = [_]u8{
        7, 'E', 'X',  'A', 'M', 'P', 'L',  'E', 0,
        1, 'b', 0xc0, 0,   1,   'A', 0xc0, 0,
    };
    const b = try Name.init(&packet, 9);
    const a = try Name.init(&packet, 13);
    try std.testing.expectEqual(std.math.Order.lt, try a.canonicalCompare(b));
}

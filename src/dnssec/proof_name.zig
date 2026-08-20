const std = @import("std");
const name_mod = @import("../name.zig");

pub const Error = name_mod.Error || error{NotSubdomain};

pub fn wildcardName(closest_encloser_wire: []const u8, out: []u8) Error!name_mod.Name {
    if (closest_encloser_wire.len + 2 > out.len or closest_encloser_wire.len + 2 > name_mod.Name.max_wire_len) return error.NameTooLong;
    out[0] = 1;
    out[1] = '*';
    @memcpy(out[2..][0..closest_encloser_wire.len], closest_encloser_wire);
    return name_mod.Name.init(out[0 .. closest_encloser_wire.len + 2], 0);
}

pub fn nextCloserName(qname_wire: []const u8, closest_encloser_wire: []const u8, out: []u8) Error!name_mod.Name {
    const suffix_offset = try strictSuffixOffset(qname_wire, closest_encloser_wire);
    var pos: usize = 0;
    var previous: usize = 0;
    while (pos < suffix_offset) {
        previous = pos;
        pos += 1 + qname_wire[pos];
    }
    const wire = qname_wire[previous..];
    if (wire.len > out.len) return error.BufferTooSmall;
    @memcpy(out[0..wire.len], wire);
    return name_mod.Name.init(out[0..wire.len], 0);
}

pub fn strictSuffixOffset(name_wire: []const u8, suffix_wire: []const u8) Error!usize {
    var pos: usize = 0;
    while (true) {
        if (std.mem.eql(u8, name_wire[pos..], suffix_wire)) {
            if (pos == 0) return error.NotSubdomain;
            return pos;
        }
        if (name_wire[pos] == 0) return error.NotSubdomain;
        pos += 1 + name_wire[pos];
    }
}

pub fn isEqualOrSubdomain(name_wire: []const u8, zone_wire: []const u8) bool {
    var pos: usize = 0;
    while (true) {
        if (std.mem.eql(u8, name_wire[pos..], zone_wire)) return true;
        if (name_wire[pos] == 0) return false;
        pos += 1 + name_wire[pos];
    }
}

const std = @import("std");
const name_mod = @import("../name.zig");

pub fn namesEqual(a: name_mod.Uncompressed, b: name_mod.Uncompressed) name_mod.Error!bool {
    return (try name_mod.Name.init(a.bytes, 0)).eqlIgnoreCase(try name_mod.Name.init(b.bytes, 0));
}

pub fn isSubdomain(child: name_mod.Uncompressed, parent: name_mod.Uncompressed) name_mod.Error!bool {
    return (try name_mod.Name.init(child.bytes, 0)).isSubdomainOf(try name_mod.Name.init(parent.bytes, 0));
}

pub fn validWildcardSource(qname: name_mod.Uncompressed, source: name_mod.Uncompressed, apex: name_mod.Uncompressed) name_mod.Error!bool {
    if (source.bytes.len < 3 or source.bytes[0] != 1 or source.bytes[1] != '*') return false;
    const suffix = try name_mod.Uncompressed.init(source.bytes[2..]);
    return try isSubdomain(qname, suffix) and try isSubdomain(suffix, apex);
}

pub fn substituteDname(source: name_mod.Uncompressed, owner: name_mod.Uncompressed, target: name_mod.Uncompressed, out: []u8) name_mod.Error![]const u8 {
    var source_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var owner_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    var target_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const source_wire = try (try name_mod.Name.init(source.bytes, 0)).writeCanonicalWire(&source_buf);
    const owner_wire = try (try name_mod.Name.init(owner.bytes, 0)).writeCanonicalWire(&owner_buf);
    const target_wire = try (try name_mod.Name.init(target.bytes, 0)).writeCanonicalWire(&target_buf);

    var pos: usize = 0;
    var prefix_len: ?usize = null;
    while (pos < source_wire.len) {
        if (pos != 0 and std.mem.eql(u8, source_wire[pos..], owner_wire)) {
            prefix_len = pos;
            break;
        }
        const label_len: usize = source_wire[pos];
        if (label_len == 0) break;
        pos += 1 + label_len;
    }
    const prefix = prefix_len orelse return error.InvalidPresentation;
    const needed = prefix + target_wire.len;
    if (needed > name_mod.Name.max_wire_len) return error.NameTooLong;
    if (needed > out.len) return error.BufferTooSmall;
    @memcpy(out[0..prefix], source_wire[0..prefix]);
    @memcpy(out[prefix..][0..target_wire.len], target_wire);
    return out[0..needed];
}

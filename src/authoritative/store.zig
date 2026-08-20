const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const api = @import("types.zig");
const h = @import("name_helpers.zig");

const ZoneRecord = api.ZoneRecord;

/// Allocation-free reference store over caller-owned zone records.
///
/// This adapter deliberately uses linear scans so it remains tiny and useful
/// for examples, tests, embedded zones, and correctness baselines. Large
/// authoritative deployments should implement the same `Composer` structural
/// contract with their own indexed/database-backed store.
pub const SliceStore = struct {
    pub const Error = error{};

    pub const RecordIterator = struct {
        records: []const ZoneRecord,
        owner: name_mod.Uncompressed,
        rr_type: types.Type,
        pos: usize = 0,

        pub fn next(self: *RecordIterator) Error!?ZoneRecord {
            while (self.pos < self.records.len) {
                const rr = self.records[self.pos];
                self.pos += 1;
                if (rr.rr_type == self.rr_type and (h.namesEqual(rr.owner, self.owner) catch false)) return rr;
            }
            return null;
        }
    };

    records: []const ZoneRecord,
    apex_name: name_mod.Uncompressed,

    pub fn init(apex_name: name_mod.Uncompressed, records: []const ZoneRecord) SliceStore {
        return .{ .records = records, .apex_name = apex_name };
    }

    pub fn apex(self: *SliceStore) name_mod.Uncompressed {
        return self.apex_name;
    }

    pub fn lookup(self: *SliceStore, owner: name_mod.Uncompressed, rr_type: types.Type) Error!?RecordIterator {
        var probe: RecordIterator = .{ .records = self.records, .owner = owner, .rr_type = rr_type };
        if ((try probe.next()) == null) return null;
        return .{ .records = self.records, .owner = owner, .rr_type = rr_type };
    }

    /// DNS name existence includes empty non-terminals: a name exists if it
    /// owns data or is a strict ancestor of any owner in this zone view.
    pub fn nameExists(self: *SliceStore, owner: name_mod.Uncompressed) Error!bool {
        if (!(h.isSubdomain(owner, self.apex_name) catch false)) return false;
        for (self.records) |rr| {
            if (h.namesEqual(rr.owner, owner) catch false) return true;
            if (h.isSubdomain(rr.owner, owner) catch false) return true;
        }
        return false;
    }

    /// Return the closest enclosing non-apex NS owner (zone cut).
    pub fn findDelegation(self: *SliceStore, qname: name_mod.Uncompressed) Error!?name_mod.Uncompressed {
        var best: ?name_mod.Uncompressed = null;
        for (self.records) |rr| {
            if (rr.rr_type != .NS) continue;
            if (h.namesEqual(rr.owner, self.apex_name) catch false) continue;
            if (!(h.isSubdomain(qname, rr.owner) catch false)) continue;
            if (best == null or (h.isSubdomain(rr.owner, best.?) catch false) and !(h.namesEqual(rr.owner, best.?) catch false)) best = rr.owner;
        }
        return best;
    }

    /// Return the closest strict ancestor carrying DNAME.
    pub fn findDname(self: *SliceStore, qname: name_mod.Uncompressed) Error!?name_mod.Uncompressed {
        var best: ?name_mod.Uncompressed = null;
        for (self.records) |rr| {
            if (rr.rr_type != .DNAME) continue;
            if (h.namesEqual(qname, rr.owner) catch false) continue;
            if (!(h.isSubdomain(qname, rr.owner) catch false)) continue;
            if (best == null or (h.isSubdomain(rr.owner, best.?) catch false) and !(h.namesEqual(rr.owner, best.?) catch false)) best = rr.owner;
        }
        return best;
    }

    /// RFC 4592 closest-encloser wildcard selection. The returned source is
    /// always borrowed from an existing record owner, so no mutable scratch or
    /// hidden allocation is required and the store remains thread-safe.
    pub fn findWildcard(self: *SliceStore, qname: name_mod.Uncompressed) Error!?name_mod.Uncompressed {
        var canonical_buf: [name_mod.Name.max_wire_len]u8 = undefined;
        const canonical = (name_mod.Name.init(qname.bytes, 0) catch return null).writeCanonicalWire(&canonical_buf) catch return null;

        var pos: usize = 0;
        while (pos < canonical.len) {
            const label_len: usize = canonical[pos];
            if (label_len == 0) return null;
            pos += 1 + label_len; // parent candidate; qname itself was already absent.
            const parent = name_mod.Uncompressed.init(canonical[pos..]) catch return null;
            if (!(h.isSubdomain(parent, self.apex_name) catch false)) return null;
            if (!(try self.nameExists(parent))) continue;

            for (self.records) |rr| {
                if (rr.owner.bytes.len < 3 or rr.owner.bytes[0] != 1 or rr.owner.bytes[1] != '*') continue;
                const suffix = name_mod.Uncompressed.init(rr.owner.bytes[2..]) catch continue;
                if (h.namesEqual(suffix, parent) catch false) return rr.owner;
            }
            return null;
        }
        return null;
    }
};

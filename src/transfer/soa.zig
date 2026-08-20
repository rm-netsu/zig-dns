const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const rdata = @import("../rdata.zig");
const types = @import("../types.zig");

pub const Error = rdata.Error || name_mod.Error;

/// Caller-owned backing for one semantic SOA snapshot. Domain names are
/// canonicalized so the snapshot does not retain the source DNS message.
pub const Storage = struct {
    mname: [name_mod.Name.max_wire_len]u8 = undefined,
    rname: [name_mod.Name.max_wire_len]u8 = undefined,
};

pub const Snapshot = struct {
    class: types.Class,
    ttl: u32,
    mname_len: u16,
    rname_len: u16,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,

    pub fn capture(rr: message.Record, storage: *Storage) Error!Snapshot {
        const soa = try rdata.soa(rr);
        const mname = try soa.mname.writeCanonicalWire(&storage.mname);
        const rname = try soa.rname.writeCanonicalWire(&storage.rname);
        return .{
            .class = rr.class,
            .ttl = rr.ttl,
            .mname_len = @intCast(mname.len),
            .rname_len = @intCast(rname.len),
            .serial = soa.serial,
            .refresh = soa.refresh,
            .retry = soa.retry,
            .expire = soa.expire,
            .minimum = soa.minimum,
        };
    }

    /// Compare all SOA RR fields except the owner name. Callers that care
    /// about zone identity validate the owner separately.
    pub fn eqlRecord(self: Snapshot, storage: *const Storage, rr: message.Record) Error!bool {
        if (rr.class != self.class or rr.ttl != self.ttl) return false;
        const parsed = try rdata.soa(rr);
        const mname = try name_mod.Name.init(storage.mname[0..self.mname_len], 0);
        const rname = try name_mod.Name.init(storage.rname[0..self.rname_len], 0);
        return try parsed.mname.eqlIgnoreCase(mname) and
            try parsed.rname.eqlIgnoreCase(rname) and
            parsed.serial == self.serial and
            parsed.refresh == self.refresh and
            parsed.retry == self.retry and
            parsed.expire == self.expire and
            parsed.minimum == self.minimum;
    }

    pub fn eqlSnapshot(
        self: Snapshot,
        storage: *const Storage,
        other: Snapshot,
        other_storage: *const Storage,
    ) Error!bool {
        if (self.class != other.class or self.ttl != other.ttl or
            self.serial != other.serial or self.refresh != other.refresh or
            self.retry != other.retry or self.expire != other.expire or
            self.minimum != other.minimum) return false;
        const self_mname = try name_mod.Name.init(storage.mname[0..self.mname_len], 0);
        const self_rname = try name_mod.Name.init(storage.rname[0..self.rname_len], 0);
        const other_mname = try name_mod.Name.init(other_storage.mname[0..other.mname_len], 0);
        const other_rname = try name_mod.Name.init(other_storage.rname[0..other.rname_len], 0);
        return try self_mname.eqlIgnoreCase(other_mname) and try self_rname.eqlIgnoreCase(other_rname);
    }
};

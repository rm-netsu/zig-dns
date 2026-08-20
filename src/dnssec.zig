const message = @import("message.zig");
const name_mod = @import("name.zig");

pub const canonical = @import("dnssec/canonical.zig");
pub const CanonicalWriter = canonical.Writer;
pub const rrset = @import("dnssec/rrset.zig");
pub const Rrset = rrset.Rrset;
pub const policy = @import("dnssec/policy.zig");
pub const crypto_backend = @import("dnssec/crypto_backend.zig");
pub const verify = @import("dnssec/verify.zig");
pub const denial = @import("dnssec/denial.zig");

pub const records = @import("dnssec/records.zig");
pub const Error = records.Error || error{InvalidDnskey};
pub const TypeBitmapIterator = records.TypeBitmapIterator;
pub const Nsec = records.Nsec;
pub const Nsec3 = records.Nsec3;
pub const Nsec3Param = records.Nsec3Param;
pub const nsec = records.nsec;
pub const nsec3 = records.nsec3;
pub const nsec3param = records.nsec3param;

pub const key = @import("dnssec/key.zig");
pub const ds = @import("dnssec/ds.zig");
pub const dnskeyKeyTag = key.keyTag;

pub fn validateUncompressedNameInRdata(rr: message.Record, relative: usize) Error!usize {
    if (relative >= rr.rdata.len) return error.InvalidLength;
    const len = try name_mod.uncompressedConsumedLen(rr.packet, @as(usize, rr.rdata_offset) + relative);
    if (relative + len > rr.rdata.len) return error.InvalidLength;
    return len;
}

const std = @import("std");
const dns = @import("dns");

/// Example caller-owned storage for DNSSEC verification. Applications can
/// choose bounds that match their own packet/RRset limits instead of taking a
/// heap dependency from the protocol library.
const ValidatorStorage = struct {
    signed_data: [4096]u8 = undefined,
    order: [64]u16 = undefined,
    compare: [2048]u8 = undefined,
    digest: [48]u8 = undefined,

    fn verifyRrset(
        self: *ValidatorStorage,
        rrsig: dns.Record,
        dnskey: dns.Record,
        records: []const dns.Record,
        now: u64,
    ) !void {
        if (records.len > self.order.len) return error.RrsetTooLarge;
        const rrset = try dns.dnssec.Rrset.init(records);
        try dns.dnssec.verify.verifyRrset(
            rrsig,
            dnskey,
            rrset,
            now,
            .{
                .signed_data = &self.signed_data,
                .order = self.order[0..records.len],
                .compare = &self.compare,
            },
            .{},
        );
    }

    fn evaluateDelegation(
        self: *ValidatorStorage,
        ds_records: []const dns.Record,
        dnskey_records: []const dns.Record,
    ) !dns.dnssec.trust.LinkResult {
        const delegation = try dns.dnssec.Delegation.authenticatedDs(ds_records);
        const keys = try dns.dnssec.DnskeySet.init(dnskey_records);
        return delegation.evaluate(keys, &self.digest, .{});
    }
};

pub fn main() void {
    // Transport and recursive-walk policy stay outside dns. Once the caller
    // has authenticated RRSIG/DNSKEY/DS records, these helpers compose the
    // protocol and crypto checks using only caller-owned scratch storage.
    _ = ValidatorStorage.verifyRrset;
    _ = ValidatorStorage.evaluateDelegation;
    std.debug.print("DNSSEC validator storage: {d} bytes\n", .{@sizeOf(ValidatorStorage)});
}

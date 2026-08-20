const std = @import("std");
const types = @import("types.zig");
const message = @import("message.zig");
const name_mod = @import("name.zig");
const rdata = @import("rdata.zig");
const edns = @import("edns.zig");
const dnssec = @import("dnssec.zig");
const svcb_mod = @import("svcb.zig");
const tsig_mod = @import("tsig.zig");

pub const Error = message.ParseError || rdata.Error || edns.Error || dnssec.Error || svcb_mod.Error || tsig_mod.Error || error{
    OptOutsideAdditional,
    MultipleOpt,
    InvalidOptOwner,
    UnsupportedEdnsVersion,
    InvalidRdata,
    TsigOutsideAdditional,
    MultipleTsig,
    TsigNotLast,
};

pub const Options = struct {
    validate_known_rdata: bool = true,
    require_edns_version_zero: bool = true,
};

pub const Result = struct {
    opt: ?edns.Opt = null,
    tsig: ?tsig_mod.Record = null,
};

pub fn messageStrict(m: message.Message, options: Options) Error!Result {
    try m.validate();
    var result: Result = .{};

    var answers = try m.records(.answer);
    while (try answers.next()) |rr| {
        if (rr.rr_type == .OPT) return error.OptOutsideAdditional;
        if (rr.rr_type == .TSIG) return error.TsigOutsideAdditional;
        if (options.validate_known_rdata) try knownRdata(rr);
    }
    var authority = try m.records(.authority);
    while (try authority.next()) |rr| {
        if (rr.rr_type == .OPT) return error.OptOutsideAdditional;
        if (rr.rr_type == .TSIG) return error.TsigOutsideAdditional;
        if (options.validate_known_rdata) try knownRdata(rr);
    }
    var additional = try m.records(.additional);
    while (try additional.next()) |rr| {
        if (rr.rr_type == .OPT) {
            if (result.opt != null) return error.MultipleOpt;
            var buf: [1]u8 = undefined;
            const owner = try rr.name.writePresentation(&buf);
            if (owner.len != 0) return error.InvalidOptOwner;
            const opt = try edns.Opt.fromRecord(rr);
            if (options.require_edns_version_zero and opt.version != 0) return error.UnsupportedEdnsVersion;
            var oi = opt.iterator();
            while (try oi.next()) |_| {}
            result.opt = opt;
        } else if (rr.rr_type == .TSIG) {
            if (result.tsig != null) return error.MultipleTsig;
            const parsed = try tsig_mod.parse(rr);
            try tsig_mod.validateSemantics(parsed, m.header.flags.response);
            result.tsig = parsed;
            if (additional.remaining != 0) return error.TsigNotLast;
        } else if (options.validate_known_rdata) try knownRdata(rr);
    }
    return result;
}

pub fn knownRdata(rr: message.Record) Error!void {
    switch (rr.rr_type) {
        .A => _ = try rdata.a(rr),
        .AAAA => _ = try rdata.aaaa(rr),
        .NS, .CNAME, .PTR, .DNAME => {
            const n = try rdata.targetName(rr);
            if (try n.consumed() != rr.rdata.len) return error.InvalidRdata;
        },
        .MX => {
            const v = try rdata.mx(rr);
            if (2 + try v.exchange.consumed() != rr.rdata.len) return error.InvalidRdata;
        },
        .SOA => _ = try rdata.soa(rr),
        .TXT => {
            var it = rdata.txt(rr);
            while (try it.next()) |_| {}
        },
        .SRV => {
            const v = try rdata.srv(rr);
            if (6 + try v.target.consumed() != rr.rdata.len) return error.InvalidRdata;
        },
        .CAA => _ = try rdata.caa(rr),
        .SSHFP => _ = try rdata.sshfp(rr),
        .URI => _ = try rdata.uri(rr),
        .ZONEMD => _ = try rdata.zonemd(rr),
        .DS, .CDS => {
            const v = try rdata.ds(rr);
            if (v.digest.len == 0) return error.InvalidRdata;
        },
        .DNSKEY, .CDNSKEY => {
            const v = try rdata.dnskey(rr);
            if (v.protocol != 3 or v.public_key.len == 0) return error.InvalidRdata;
        },
        .RRSIG => {
            _ = try dnssec.validateUncompressedNameInRdata(rr, 18);
            _ = try rdata.rrsig(rr);
        },
        .NSEC => {
            const name_len = try dnssec.validateUncompressedNameInRdata(rr, 0);
            var v = try dnssec.nsec(rr);
            if (name_len >= rr.rdata.len) return error.InvalidRdata;
            while (try v.types.next()) |_| {}
        },
        .NSEC3 => {
            var v = try dnssec.nsec3(rr);
            while (try v.types.next()) |_| {}
        },
        .NSEC3PARAM => _ = try dnssec.nsec3param(rr),
        .TLSA, .SMIMEA => _ = try rdata.tlsa(rr),
        .SVCB, .HTTPS => _ = try svcb_mod.validateRecord(rr),
        .TSIG => _ = try tsig_mod.parse(rr),
        else => {},
    }
}

test "strict validator accepts EDNS and rejects duplicate OPT" {
    const Builder = @import("builder.zig").Builder;
    const CompressionEntry = @import("builder.zig").CompressionEntry;
    var buf: [512]u8 = undefined;
    var entries: [16]CompressionEntry = undefined;
    var b = try Builder.init(&buf, &entries, 1, .{ .response = true });
    try b.addQuestion("example.com", .A, .IN);
    try b.addOpt(1232, 0, 0, .{ .dnssec_ok = true, .compact_answers_ok = true }, &.{});
    const bytes = try b.finish();
    const m = try message.Message.init(bytes);
    const v = try messageStrict(m, .{});
    try std.testing.expect(v.opt.?.dnssecOk());
    try std.testing.expect(v.opt.?.compactAnswersOk());
}

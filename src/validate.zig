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
        if (options.validate_known_rdata and shouldValidateKnownRdata(m.header.flags.opcode, .answer, rr)) try knownRdata(rr);
    }
    var authority = try m.records(.authority);
    while (try authority.next()) |rr| {
        if (rr.rr_type == .OPT) return error.OptOutsideAdditional;
        if (rr.rr_type == .TSIG) return error.TsigOutsideAdditional;
        if (options.validate_known_rdata and shouldValidateKnownRdata(m.header.flags.opcode, .authority, rr)) try knownRdata(rr);
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
            const option_summary = try edns.validateMessageOptions(opt, m.header.flags.response, m.header.flags.opcode);
            if (option_summary.has_zoneversion) try validateZoneVersionQuestion(m, opt);
            try validateMultipleQtypeQuestion(m, option_summary);
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

fn validateZoneVersionQuestion(m: message.Message, opt: edns.Opt) Error!void {
    if (m.header.question_count != 1) return error.InvalidZoneVersion;

    var questions = m.questions();
    const question = (try questions.next()) orelse return error.InvalidZoneVersion;
    if (!m.header.flags.response) return;

    // RFC 9660 forbids duplicate response tuples with the same
    // (LABELCOUNT, TYPE). Track all 256 extensible TYPE values with a fixed
    // 4 KiB bitmap so attacker-controlled option counts cannot turn strict
    // validation into an O(n^2) scan. A valid DNS QNAME cannot have more
    // than 127 non-root labels, so one u128 covers LABELCOUNT after the
    // QNAME-bound check below.
    var seen: [256]u128 = [_]u128{0} ** 256;
    var response_options = opt.iterator();
    while (try response_options.next()) |option| {
        if (option.code != .ZONEVERSION) continue;
        const version = try edns.parseZoneVersion(option, true);
        switch (version) {
            .request => return error.InvalidZoneVersion,
            .response => |value| {
                value.validateQname(question.name) catch return error.InvalidZoneVersion;
                const type_index: usize = @intFromEnum(value.version_type);
                const bit = @as(u128, 1) << @intCast(value.label_count);
                if (seen[type_index] & bit != 0) return error.InvalidZoneVersion;
                seen[type_index] |= bit;
            },
        }
    }
}

fn validateMultipleQtypeQuestion(m: message.Message, summary: edns.MessageOptionSummary) Error!void {
    const relevant = if (m.header.flags.response) summary.mqtype_response else summary.mqtype_query;
    const option = relevant orelse return;
    if (m.header.question_count != 1) return error.InvalidMultipleQtype;

    var questions = m.questions();
    const question = (try questions.next()) orelse return error.InvalidMultipleQtype;
    var scratch: edns.MultipleQtypeScratch = .{};
    const list = if (m.header.flags.response)
        try edns.parseMultipleQtypeResponse(option)
    else
        try edns.parseMultipleQtypeQuery(option);
    list.validate(question.qtype, &scratch) catch return error.InvalidMultipleQtype;
}

fn shouldValidateKnownRdata(opcode: types.Opcode, section: types.Section, rr: message.Record) bool {
    if (opcode != .update) return true;

    // RFC 2136 overloads CLASS and RDLENGTH in the Prerequisite and Update
    // sections. ANY records there intentionally carry empty RDATA, and NONE
    // prerequisites do too; parsing those bytes as the ordinary RR type
    // would reject valid UPDATE messages. NONE records in the Update section
    // are value-dependent deletions and still contain normal RDATA.
    if (rr.class == .ANY) return false;
    if (section == .answer and rr.class == .NONE) return false;
    return true;
}

pub fn knownRdata(rr: message.Record) Error!void {
    switch (rr.rr_type) {
        .A => _ = try rdata.a(rr),
        .AAAA => _ = try rdata.aaaa(rr),
        .NS, .CNAME, .PTR => {
            const n = try rdata.targetName(rr);
            if (try n.consumed() != rr.rdata.len) return error.InvalidRdata;
        },
        .DNAME => {
            const name_len = try dnssec.validateUncompressedNameInRdata(rr, 0);
            if (name_len != rr.rdata.len) return error.InvalidRdata;
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

test "strict validator accepts RFC 2136 meta-record RDATA semantics" {
    const update_mod = @import("update.zig");
    const builder_mod = @import("builder.zig");
    var packet: [512]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var update = try update_mod.Composer.init(&packet, &compression, 0x99, "example.com", .IN);
    try update.requireRrsetNotExists("host.example.com", .AAAA);
    try update.deleteRrset("host.example.com", .TXT);
    try update.deleteA("stale.example.com", .{ 192, 0, 2, 9 });

    const m = try message.Message.init(try update.finish());
    _ = try messageStrict(m, .{});
    _ = try update_mod.validateRequest(m);
}

test "strict validator requires uncompressed DNAME target" {
    const builder_mod = @import("builder.zig");
    var buf: [256]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;

    var good = try builder_mod.Builder.init(&buf, &compression, 0x44, .{ .response = true });
    try good.addQuestion("host.old.example", .A, .IN);
    try good.addNameRecord(.answer, "old.example", .DNAME, 60, "new.example");
    const good_message = try message.Message.init(try good.finish());
    _ = try messageStrict(good_message, .{});

    var answers = try good_message.records(.answer);
    const dname = (try answers.next()).?;
    try std.testing.expectEqual(dname.rdata.len, try name_mod.uncompressedConsumedLen(dname.packet, dname.rdata_offset));

    var bad = try builder_mod.Builder.init(&buf, &compression, 0x45, .{ .response = true });
    try bad.addQuestion("host.old.example", .A, .IN);
    var rr = try bad.beginRecord(.answer, "old.example", .DNAME, .IN, 60);
    try rr.writeBytes(&.{ 0xc0, 0x0c });
    try rr.finish();
    const bad_message = try message.Message.init(try bad.finish());
    try std.testing.expectError(error.InvalidLabel, messageStrict(bad_message, .{}));
}

test "strict validator enforces first COOKIE semantics" {
    const builder_mod = @import("builder.zig");

    const client: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var option_buf: [64]u8 = undefined;
    var options = edns.OptionBuilder.init(&option_buf);
    try options.addCookie(client, null);
    // RFC 7873 says later COOKIE options are ignored. Their option framing
    // still has to be valid, but their COOKIE payload is not interpreted.
    try options.add(.COOKIE, &.{0});

    var packet: [256]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var b = try builder_mod.Builder.init(&packet, &compression, 0x8001, .{});
    try b.addQuestion("example.com", .A, .IN);
    try b.addOpt(1232, 0, 0, .{}, options.bytes());
    _ = try messageStrict(try message.Message.init(try b.finish()), .{});

    var malformed_options = edns.OptionBuilder.init(&option_buf);
    try malformed_options.add(.COOKIE, &.{0});
    var bad = try builder_mod.Builder.init(&packet, &compression, 0x8002, .{});
    try bad.addQuestion("example.com", .A, .IN);
    try bad.addOpt(1232, 0, 0, .{}, malformed_options.bytes());
    try std.testing.expectError(error.InvalidCookie, messageStrict(try message.Message.init(try bad.finish()), .{}));
}

test "strict validator checks TCP keepalive direction" {
    const builder_mod = @import("builder.zig");

    var option_buf: [16]u8 = undefined;
    var packet: [256]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;

    var query_options = edns.OptionBuilder.init(&option_buf);
    try query_options.addKeepaliveRequest();
    var query = try builder_mod.Builder.init(&packet, &compression, 0x8101, .{});
    try query.addQuestion("example.com", .A, .IN);
    try query.addOpt(1232, 0, 0, .{}, query_options.bytes());
    _ = try messageStrict(try message.Message.init(try query.finish()), .{});

    var wrong_query_options = edns.OptionBuilder.init(&option_buf);
    try wrong_query_options.addKeepaliveResponse(100);
    var wrong_query = try builder_mod.Builder.init(&packet, &compression, 0x8102, .{});
    try wrong_query.addQuestion("example.com", .A, .IN);
    try wrong_query.addOpt(1232, 0, 0, .{}, wrong_query_options.bytes());
    try std.testing.expectError(error.InvalidKeepalive, messageStrict(try message.Message.init(try wrong_query.finish()), .{}));

    var response_options = edns.OptionBuilder.init(&option_buf);
    try response_options.addKeepaliveResponse(100);
    var response = try builder_mod.Builder.init(&packet, &compression, 0x8103, .{ .response = true });
    try response.addQuestion("example.com", .A, .IN);
    try response.addOpt(1232, 0, 0, .{}, response_options.bytes());
    _ = try messageStrict(try message.Message.init(try response.finish()), .{});
}

test "strict validator enforces Update Lease opcode" {
    const builder_mod = @import("builder.zig");
    var option_buf: [16]u8 = undefined;
    var opts = edns.OptionBuilder.init(&option_buf);
    try opts.addUpdateLease(.{ .lease = 3600 });

    var packet: [256]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;
    var query = try builder_mod.Builder.init(&packet, &compression, 0x8201, .{});
    try query.addQuestion("example.com", .A, .IN);
    try query.addOpt(1232, 0, 0, .{}, opts.bytes());
    try std.testing.expectError(error.InvalidUpdateLease, messageStrict(try message.Message.init(try query.finish()), .{}));

    var update = try builder_mod.Builder.init(&packet, &compression, 0x8202, .{ .opcode = .update });
    try update.addQuestion("example.com", .SOA, .IN);
    try update.addOpt(1232, 0, 0, .{}, opts.bytes());
    _ = try messageStrict(try message.Message.init(try update.finish()), .{});
}

test "strict validator checks ZONEVERSION query multiplicity and response label count" {
    const builder_mod = @import("builder.zig");
    var option_buf: [32]u8 = undefined;
    var packet: [256]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;

    var duplicate = edns.OptionBuilder.init(&option_buf);
    try duplicate.addZoneVersionRequest();
    try duplicate.addZoneVersionRequest();
    var query = try builder_mod.Builder.init(&packet, &compression, 0x8301, .{});
    try query.addQuestion("www.example.com", .A, .IN);
    try query.addOpt(1232, 0, 0, .{}, duplicate.bytes());
    try std.testing.expectError(error.InvalidZoneVersion, messageStrict(try message.Message.init(try query.finish()), .{}));

    var response_opts = edns.OptionBuilder.init(&option_buf);
    try response_opts.addZoneVersionSoaSerial(4, 1234);
    var response = try builder_mod.Builder.init(&packet, &compression, 0x8302, .{ .response = true, .authoritative = true });
    try response.addQuestion("www.example.com", .A, .IN);
    try response.addOpt(1232, 0, 0, .{}, response_opts.bytes());
    try std.testing.expectError(error.InvalidZoneVersion, messageStrict(try message.Message.init(try response.finish()), .{}));

    var duplicate_response_opts = edns.OptionBuilder.init(&option_buf);
    try duplicate_response_opts.addZoneVersionSoaSerial(2, 1234);
    try duplicate_response_opts.addZoneVersionSoaSerial(2, 5678);
    var duplicate_response = try builder_mod.Builder.init(&packet, &compression, 0x8303, .{ .response = true, .authoritative = true });
    try duplicate_response.addQuestion("www.example.com", .A, .IN);
    try duplicate_response.addOpt(1232, 0, 0, .{}, duplicate_response_opts.bytes());
    try std.testing.expectError(error.InvalidZoneVersion, messageStrict(try message.Message.init(try duplicate_response.finish()), .{}));

    var valid_opts = edns.OptionBuilder.init(&option_buf);
    try valid_opts.addZoneVersionSoaSerial(2, 1234);
    var valid = try builder_mod.Builder.init(&packet, &compression, 0x8304, .{ .response = true, .authoritative = true });
    try valid.addQuestion("www.example.com", .A, .IN);
    try valid.addOpt(1232, 0, 0, .{}, valid_opts.bytes());
    _ = try messageStrict(try message.Message.init(try valid.finish()), .{});
}

test "strict validator enforces RFC 10029 MQTYPE request semantics" {
    const builder_mod = @import("builder.zig");
    var option_buf: [64]u8 = undefined;
    var packet: [256]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;

    var valid_options = edns.OptionBuilder.init(&option_buf);
    try valid_options.addMultipleQtypeQuery(.A, &.{ .AAAA, .HTTPS });
    var valid = try builder_mod.Builder.init(&packet, &compression, 0x8401, .{});
    try valid.addQuestion("www.example.com", .A, .IN);
    try valid.addOpt(1232, 0, 0, .{}, valid_options.bytes());
    _ = try messageStrict(try message.Message.init(try valid.finish()), .{});

    var duplicate_options = edns.OptionBuilder.init(&option_buf);
    // Use the raw option writer because the typed builder correctly rejects
    // duplicate lists before wire mutation.
    try duplicate_options.add(.MQTYPE_QUERY, &.{ 0x00, 0x1c, 0x00, 0x1c });
    var duplicate = try builder_mod.Builder.init(&packet, &compression, 0x8402, .{});
    try duplicate.addQuestion("www.example.com", .A, .IN);
    try duplicate.addOpt(1232, 0, 0, .{}, duplicate_options.bytes());
    try std.testing.expectError(error.InvalidMultipleQtype, messageStrict(try message.Message.init(try duplicate.finish()), .{}));

    var primary_duplicate_options = edns.OptionBuilder.init(&option_buf);
    try primary_duplicate_options.add(.MQTYPE_QUERY, &.{ 0x00, 0x01 });
    var primary_duplicate = try builder_mod.Builder.init(&packet, &compression, 0x8403, .{});
    try primary_duplicate.addQuestion("www.example.com", .A, .IN);
    try primary_duplicate.addOpt(1232, 0, 0, .{}, primary_duplicate_options.bytes());
    try std.testing.expectError(error.InvalidMultipleQtype, messageStrict(try message.Message.init(try primary_duplicate.finish()), .{}));

    var meta_primary_options = edns.OptionBuilder.init(&option_buf);
    try meta_primary_options.add(.MQTYPE_QUERY, &.{ 0x00, 0x01 });
    var meta_primary = try builder_mod.Builder.init(&packet, &compression, 0x8404, .{});
    try meta_primary.addQuestion("www.example.com", .ANY, .IN);
    try meta_primary.addOpt(1232, 0, 0, .{}, meta_primary_options.bytes());
    try std.testing.expectError(error.InvalidMultipleQtype, messageStrict(try message.Message.init(try meta_primary.finish()), .{}));
}

test "strict validator enforces RFC 10029 response semantics without rejecting echoed query" {
    const builder_mod = @import("builder.zig");
    var option_buf: [64]u8 = undefined;
    var packet: [256]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;

    var response_options = edns.OptionBuilder.init(&option_buf);
    try response_options.addMultipleQtypeResponse(.A, &.{ .AAAA, .HTTPS });
    var response = try builder_mod.Builder.init(&packet, &compression, 0x8501, .{ .response = true });
    try response.addQuestion("www.example.com", .A, .IN);
    try response.addOpt(1232, 0, 0, .{}, response_options.bytes());
    _ = try messageStrict(try message.Message.init(try response.finish()), .{});

    var echoed_options = edns.OptionBuilder.init(&option_buf);
    try echoed_options.addMultipleQtypeQuery(.A, &.{.AAAA});
    var echoed = try builder_mod.Builder.init(&packet, &compression, 0x8502, .{ .response = true });
    try echoed.addQuestion("www.example.com", .A, .IN);
    try echoed.addOpt(1232, 0, 0, .{}, echoed_options.bytes());
    _ = try messageStrict(try message.Message.init(try echoed.finish()), .{});

    var duplicate_response_options = edns.OptionBuilder.init(&option_buf);
    try duplicate_response_options.add(.MQTYPE_RESPONSE, &.{ 0x00, 0x1c, 0x00, 0x1c });
    var duplicate_response = try builder_mod.Builder.init(&packet, &compression, 0x8503, .{ .response = true });
    try duplicate_response.addQuestion("www.example.com", .A, .IN);
    try duplicate_response.addOpt(1232, 0, 0, .{}, duplicate_response_options.bytes());
    try std.testing.expectError(error.InvalidMultipleQtype, messageStrict(try message.Message.init(try duplicate_response.finish()), .{}));
}

test "strict validator enforces EDNS EXPIRE direction and QUERY opcode" {
    const builder_mod = @import("builder.zig");
    var option_buf: [16]u8 = undefined;
    var packet: [256]u8 = undefined;
    var compression: [16]builder_mod.CompressionEntry = undefined;

    var request_options = edns.OptionBuilder.init(&option_buf);
    try request_options.addExpireRequest();
    var query = try builder_mod.Builder.init(&packet, &compression, 0x8601, .{});
    try query.addQuestion("example.com", .SOA, .IN);
    try query.addOpt(1232, 0, 0, .{}, request_options.bytes());
    _ = try messageStrict(try message.Message.init(try query.finish()), .{});

    var update = try builder_mod.Builder.init(&packet, &compression, 0x8602, .{ .opcode = .update });
    try update.addQuestion("example.com", .SOA, .IN);
    try update.addOpt(1232, 0, 0, .{}, request_options.bytes());
    try std.testing.expectError(error.InvalidExpire, messageStrict(try message.Message.init(try update.finish()), .{}));

    var response_options = edns.OptionBuilder.init(&option_buf);
    try response_options.addExpireResponse(3600);
    var response = try builder_mod.Builder.init(&packet, &compression, 0x8603, .{ .response = true, .authoritative = true });
    try response.addQuestion("example.com", .SOA, .IN);
    try response.addOpt(1232, 0, 0, .{}, response_options.bytes());
    _ = try messageStrict(try message.Message.init(try response.finish()), .{});

    var wrong_direction = try builder_mod.Builder.init(&packet, &compression, 0x8604, .{});
    try wrong_direction.addQuestion("example.com", .SOA, .IN);
    try wrong_direction.addOpt(1232, 0, 0, .{}, response_options.bytes());
    try std.testing.expectError(error.InvalidExpire, messageStrict(try message.Message.init(try wrong_direction.finish()), .{}));
}

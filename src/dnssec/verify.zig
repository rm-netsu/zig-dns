const std = @import("std");
const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const rdata = @import("../rdata.zig");
const key = @import("key.zig");
const rrset_mod = @import("rrset.zig");
const canonical = @import("canonical.zig");
const policy_mod = @import("policy.zig");
const crypto_backend = @import("crypto_backend.zig");

pub const Error = rdata.Error || key.Error || rrset_mod.Error || canonical.Error || crypto_backend.Error || error{
    NotRrsig,
    NotDnskey,
    OwnerMismatch,
    ClassMismatch,
    TypeCoveredMismatch,
    TooFewOwnerLabels,
    SignerMismatch,
    DnskeyProtocolMismatch,
    DnskeyAlgorithmMismatch,
    DnskeyKeyTagMismatch,
    DnskeyNotZoneKey,
    AlgorithmRejected,
    SignatureNotYetValid,
    SignatureExpired,
    AmbiguousSignatureTime,
    InvalidSignaturePeriod,
};

pub const Workspace = struct {
    signed_data: []u8,
    order: []u16,
    compare: []u8,
};

pub const Options = struct {
    policy: policy_mod.AlgorithmPolicy = policy_mod.AlgorithmPolicy.registry_2026_01_13,
    backend: crypto_backend.Backend = crypto_backend.Backend.builtin,
};

/// Verify one RRSIG over an RRset using one candidate DNSKEY.
///
/// `now` is injected Unix time in seconds. Only its low 32 bits participate in
/// RFC 1982 serial-number comparisons, matching RRSIG's 32-bit time fields.
pub fn verifyRrset(
    rrsig_rr: message.Record,
    dnskey_rr: message.Record,
    rrset: rrset_mod.Rrset,
    now: u64,
    workspace: Workspace,
    options: Options,
) Error!void {
    if (rrsig_rr.rr_type != .RRSIG) return error.NotRrsig;
    if (dnskey_rr.rr_type != .DNSKEY and dnskey_rr.rr_type != .CDNSKEY) return error.NotDnskey;

    const sig = try rdata.rrsig(rrsig_rr);
    const dnskey = try rdata.dnskey(dnskey_rr);
    const first = rrset.records[0];

    if (!(try rrsig_rr.name.eqlIgnoreCase(first.name))) return error.OwnerMismatch;
    if (rrsig_rr.class != first.class) return error.ClassMismatch;
    if (sig.type_covered != @intFromEnum(first.rr_type)) return error.TypeCoveredMismatch;
    if (try labelCount(first.name) < sig.labels) return error.TooFewOwnerLabels;
    try validateSignatureTime(sig.inception, sig.expiration, now);

    if (!(try dnskey_rr.name.eqlIgnoreCase(sig.signer_name))) return error.SignerMismatch;
    if (dnskey.protocol != 3) return error.DnskeyProtocolMismatch;
    if (dnskey.algorithm != sig.algorithm) return error.DnskeyAlgorithmMismatch;
    if ((dnskey.flags & 0x0100) == 0) return error.DnskeyNotZoneKey;
    if (try key.keyTag(dnskey_rr.rdata) != sig.key_tag) return error.DnskeyKeyTagMismatch;
    if (!options.policy.accepts(sig.algorithm)) return error.AlgorithmRejected;

    var writer = canonical.Writer.init(workspace.signed_data);
    try rrset_mod.writeSignedData(&writer, sig, rrset, workspace.order, workspace.compare);
    try options.backend.verify(sig.algorithm, dnskey.public_key, writer.written(), sig.signature);
}

pub fn validateSignatureTime(inception: u32, expiration: u32, now: u64) Error!void {
    const interval = try serialOrder(inception, expiration);
    if (interval == .gt) return error.InvalidSignaturePeriod;

    const now32: u32 = @truncate(now);
    if ((try serialOrder(now32, inception)) == .lt) return error.SignatureNotYetValid;
    if ((try serialOrder(expiration, now32)) == .lt) return error.SignatureExpired;
}

fn serialOrder(a: u32, b: u32) Error!std.math.Order {
    if (a == b) return .eq;
    const forward = b -% a;
    if (forward == 0x8000_0000) return error.AmbiguousSignatureTime;
    return if (forward < 0x8000_0000) .lt else .gt;
}

fn labelCount(n: name_mod.Name) name_mod.Error!u8 {
    var wire_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const wire = try n.writeWire(&wire_buf);
    var pos: usize = 0;
    var count: u8 = 0;
    while (wire[pos] != 0) {
        count += 1;
        pos += 1 + wire[pos];
    }
    return count;
}

test "signature time uses RFC 1982 arithmetic across wrap" {
    try validateSignatureTime(0xffff_fff0, 0x0000_0010, 0);
    try std.testing.expectError(error.SignatureNotYetValid, validateSignatureTime(100, 200, 99));
    try validateSignatureTime(100, 200, 100);
    try validateSignatureTime(100, 200, 200);
    try std.testing.expectError(error.SignatureExpired, validateSignatureTime(100, 200, 201));
    try std.testing.expectError(error.AmbiguousSignatureTime, validateSignatureTime(0, 0x8000_0000, 0));
}

test "verify Ed25519 RRSIG with caller-owned workspace" {
    const builder = @import("../builder.zig");
    const Ed25519 = std.crypto.sign.Ed25519;
    const key_pair = try Ed25519.KeyPair.generateDeterministic([_]u8{0x31} ** Ed25519.KeyPair.seed_length);
    const public_key = key_pair.public_key.toBytes();

    var dnskey_rdata: [4 + public_key.len]u8 = undefined;
    dnskey_rdata[0..4].* = .{ 0x01, 0x00, 0x03, 15 };
    dnskey_rdata[4..].* = public_key;
    const key_tag = try key.keyTag(&dnskey_rdata);

    // Build an unsigned instance first to obtain the exact borrowed RRset.
    var unsigned_packet: [512]u8 = undefined;
    var unsigned_compression: [16]builder.CompressionEntry = undefined;
    var ub = try builder.Builder.init(&unsigned_packet, &unsigned_compression, 1, .{ .response = true });
    try ub.addA(.answer, "www.example.com", 300, .{ 192, 0, 2, 1 });
    const unsigned_bytes = try ub.finish();
    const unsigned_message = try message.Message.init(unsigned_bytes);
    var uit = try unsigned_message.records(.answer);
    var unsigned_records = [_]message.Record{(try uit.next()).?};
    const unsigned_set = try rrset_mod.Rrset.init(&unsigned_records);

    const signer_wire = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const signer_name = try name_mod.Name.init(&signer_wire, 0);
    var sig_meta: rdata.Rrsig = .{
        .type_covered = @intFromEnum(types.Type.A),
        .algorithm = 15,
        .labels = 3,
        .original_ttl = 300,
        .expiration = 110,
        .inception = 90,
        .key_tag = key_tag,
        .signer_name = signer_name,
        .signature = &.{},
    };
    var signing_data: [512]u8 = undefined;
    var signing_writer = canonical.Writer.init(&signing_data);
    var signing_order: [1]u16 = undefined;
    var signing_compare: [64]u8 = undefined;
    try rrset_mod.writeSignedData(&signing_writer, sig_meta, unsigned_set, &signing_order, &signing_compare);
    const signature = try key_pair.sign(signing_writer.written(), null);
    const signature_bytes = signature.toBytes();
    sig_meta.signature = &signature_bytes;

    // Build the actual response carrying the RRSIG and DNSKEY.
    var packet: [1024]u8 = undefined;
    var compression: [32]builder.CompressionEntry = undefined;
    var b = try builder.Builder.init(&packet, &compression, 1, .{ .response = true });
    try b.addA(.answer, "www.example.com", 300, .{ 192, 0, 2, 1 });
    var signer_buf: [name_mod.Name.max_wire_len]u8 = undefined;
    const signer_uncompressed = try name_mod.Uncompressed.init(try signer_name.writeWire(&signer_buf));
    var rw = try b.beginRecord(.answer, "www.example.com", .RRSIG, .IN, 300);
    try rw.writeU16(sig_meta.type_covered);
    try rw.writeByte(sig_meta.algorithm);
    try rw.writeByte(sig_meta.labels);
    try rw.writeU32(sig_meta.original_ttl);
    try rw.writeU32(sig_meta.expiration);
    try rw.writeU32(sig_meta.inception);
    try rw.writeU16(sig_meta.key_tag);
    try rw.writeWireName(signer_uncompressed);
    try rw.writeBytes(&signature_bytes);
    try rw.finish();
    try b.addDnskey(.additional, "example.com", 300, 0x0100, 15, &public_key);
    const bytes = try b.finish();

    const m = try message.Message.init(bytes);
    var answers = try m.records(.answer);
    var records: [1]message.Record = undefined;
    records[0] = (try answers.next()).?;
    const rrsig_rr = (try answers.next()).?;
    var additional = try m.records(.additional);
    const dnskey_rr = (try additional.next()).?;
    const set = try rrset_mod.Rrset.init(&records);

    var signed_data: [512]u8 = undefined;
    var order: [1]u16 = undefined;
    var compare: [64]u8 = undefined;
    try verifyRrset(rrsig_rr, dnskey_rr, set, 100, .{
        .signed_data = &signed_data,
        .order = &order,
        .compare = &compare,
    }, .{});
}

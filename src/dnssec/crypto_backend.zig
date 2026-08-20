const std = @import("std");

pub const Error = error{
    UnsupportedAlgorithm,
    InvalidPublicKey,
    UnsupportedKeySize,
    InvalidSignature,
};

/// Small runtime-dispatch contract for cryptographic verification. Protocol
/// validation and algorithm policy live outside this backend.
pub const Backend = struct {
    context: ?*const anyopaque = null,
    verify_fn: *const fn (?*const anyopaque, u8, []const u8, []const u8, []const u8) Error!void = builtinVerify,

    pub fn verify(self: Backend, algorithm: u8, public_key: []const u8, message: []const u8, signature: []const u8) Error!void {
        return self.verify_fn(self.context, algorithm, public_key, message, signature);
    }

    pub const builtin: Backend = .{};
};

fn builtinVerify(_: ?*const anyopaque, algorithm: u8, public_key: []const u8, message: []const u8, signature: []const u8) Error!void {
    switch (algorithm) {
        5, 7 => try verifyRsa(std.crypto.hash.Sha1, public_key, message, signature),
        8 => try verifyRsa(std.crypto.hash.sha2.Sha256, public_key, message, signature),
        10 => try verifyRsa(std.crypto.hash.sha2.Sha512, public_key, message, signature),
        13 => try verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP256Sha256, 64, public_key, message, signature),
        14 => try verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP384Sha384, 96, public_key, message, signature),
        15 => try verifyEd25519(public_key, message, signature),
        else => return error.UnsupportedAlgorithm,
    }
}

fn verifyRsa(comptime Hash: type, encoded_key: []const u8, message: []const u8, signature: []const u8) Error!void {
    const parts = try parseRsaKey(encoded_key);
    if (signature.len != parts.modulus.len) return error.InvalidSignature;
    const rsa = std.crypto.Certificate.rsa;
    const public_key = rsa.PublicKey.fromBytes(parts.exponent, parts.modulus) catch return error.InvalidPublicKey;

    switch (parts.modulus.len) {
        inline 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 480, 512 => |modulus_len| {
            rsa.PKCS1v1_5Signature.verify(
                modulus_len,
                signature[0..modulus_len].*,
                message,
                public_key,
                Hash,
            ) catch return error.InvalidSignature;
        },
        else => return error.UnsupportedKeySize,
    }
}

const RsaParts = struct { exponent: []const u8, modulus: []const u8 };

fn parseRsaKey(encoded: []const u8) Error!RsaParts {
    if (encoded.len < 3) return error.InvalidPublicKey;
    var exponent_len: usize = encoded[0];
    var exponent_off: usize = 1;
    if (exponent_len == 0) {
        if (encoded.len < 4) return error.InvalidPublicKey;
        exponent_len = std.mem.readInt(u16, encoded[1..3], .big);
        exponent_off = 3;
    }
    if (exponent_len == 0 or exponent_len > encoded.len - exponent_off) return error.InvalidPublicKey;
    const modulus_off = exponent_off + exponent_len;
    if (modulus_off >= encoded.len) return error.InvalidPublicKey;
    return .{
        .exponent = encoded[exponent_off..modulus_off],
        .modulus = encoded[modulus_off..],
    };
}

fn verifyEcdsa(comptime Scheme: type, comptime key_len: usize, encoded_key: []const u8, message: []const u8, signature: []const u8) Error!void {
    if (encoded_key.len != key_len) return error.InvalidPublicKey;
    if (signature.len != Scheme.Signature.encoded_length) return error.InvalidSignature;

    var sec1: [key_len + 1]u8 = undefined;
    sec1[0] = 0x04;
    @memcpy(sec1[1..], encoded_key);
    const public_key = Scheme.PublicKey.fromSec1(&sec1) catch return error.InvalidPublicKey;
    const sig = Scheme.Signature.fromBytes(signature[0..Scheme.Signature.encoded_length].*);
    sig.verify(message, public_key) catch return error.InvalidSignature;
}

fn verifyEd25519(encoded_key: []const u8, message: []const u8, signature: []const u8) Error!void {
    const Ed25519 = std.crypto.sign.Ed25519;
    if (encoded_key.len != Ed25519.PublicKey.encoded_length) return error.InvalidPublicKey;
    if (signature.len != Ed25519.Signature.encoded_length) return error.InvalidSignature;
    const public_key = Ed25519.PublicKey.fromBytes(encoded_key[0..Ed25519.PublicKey.encoded_length].*) catch return error.InvalidPublicKey;
    const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
    sig.verify(message, public_key) catch return error.InvalidSignature;
}

test "builtin Ed25519 verification" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const key_pair = try Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** Ed25519.KeyPair.seed_length);
    const msg = "dnssec signed data";
    const sig = try key_pair.sign(msg, null);
    const pk = key_pair.public_key.toBytes();
    const sig_bytes = sig.toBytes();
    try Backend.builtin.verify(15, &pk, msg, &sig_bytes);

    var corrupted = sig_bytes;
    corrupted[0] ^= 1;
    try std.testing.expectError(error.InvalidSignature, Backend.builtin.verify(15, &pk, msg, &corrupted));
}

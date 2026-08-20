const types = @import("../types.zig");
const name_mod = @import("../name.zig");
const message = @import("../message.zig");
const builder = @import("../builder.zig");
const server = @import("../server.zig");
const edns = @import("../edns.zig");

/// Uncompressed, store-owned zone record view.
///
/// `rdata` must be wire-format RDATA that is independent of any DNS message.
/// In particular, embedded domain names must not contain compression pointers.
/// The authoritative composer borrows all fields only for the duration of the
/// current call and never owns zone storage.
pub const ZoneRecord = struct {
    owner: name_mod.Uncompressed,
    rr_type: types.Type,
    class: types.Class,
    ttl: u32,
    rdata: []const u8,
};

pub const Transport = enum { datagram, stream };
pub const AnyPolicy = union(enum) { refuse, rr_type: types.Type };

pub const Options = struct {
    zone_class: types.Class = .IN,
    transport: Transport = .datagram,
    max_udp_payload: u16 = 1232,
    recursion_available: bool = false,
    include_glue: bool = true,
    any_policy: AnyPolicy = .refuse,
    /// The caller owns signing policy. When true, DO=1 responses require the
    /// store to provide matching RRSIGs and authenticated denial proofs.
    signed_zone: bool = false,
};

pub const ProofKind = enum { nodata, nxdomain, wildcard, insecure_delegation };

pub const Kind = enum {
    answer,
    cname,
    dname,
    wildcard,
    referral,
    nodata,
    nxdomain,
    refused,
    not_implemented,
    bad_edns_version,
};

pub const Result = struct {
    bytes: []const u8,
    kind: Kind,
    truncated: bool,
    used_edns: bool,
};

pub const CoreError = message.ParseError || name_mod.Error || builder.Error || edns.Error || server.Error || error{
    ExpectedQuery,
    ExpectedOneQuestion,
    UnexpectedQuerySections,
    DuplicateOpt,
    InvalidOptOwner,
    StoreContract,
    MissingSoa,
    MissingDelegationNs,
    InvalidDname,
    MissingRrsig,
    MissingDnssecProof,
};

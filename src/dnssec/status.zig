/// DNSSEC validation result carried by higher-level resolver/cache state.
/// Kept in a dependency-light module so non-cryptographic layers do not need
/// to instantiate the DNSSEC algorithm/backend graph merely to store status.
pub const SecurityStatus = enum {
    secure,
    insecure,
    bogus,
    indeterminate,
};

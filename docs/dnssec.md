# DNSSEC validation

The development branch for 0.2.0 adds a transport-neutral DNSSEC validation engine on top of the 0.1.0 wire primitives. It still does not own sockets, a recursive resolver, a wall clock, or trust-anchor persistence.

## Validation model

The public layers are intentionally separable:

```text
borrowed DNS Records
    ↓
dns.dnssec.Rrset / canonical writer
    ↓
protocol checks + signed-data generation
    ↓
algorithm policy
    ↓
crypto backend
    ↓
trust / denial primitives
    ↓
caller-owned recursive or stub-resolver policy
```

All hot-path scratch storage is caller-owned. The built-in path does not allocate while canonicalizing an RRset, generating signed data, verifying a signature, matching DS/DNSKEY, or evaluating NSEC/NSEC3 proofs.

## Canonical RRsets

`dns.dnssec.CanonicalWriter` implements canonical DNSSEC record serialization, including:

- canonical owner-name ordering and ASCII case folding;
- fully expanded owner names with no compression;
- RFC 3597 canonical-RDATA rules for legacy name-bearing RRs;
- the RFC 6840 RRSIG/NSEC case-handling clarifications;
- Original TTL substitution;
- wildcard owner reconstruction from `RRSIG Labels`.

`dns.dnssec.Rrset` validates owner/type/class grouping. `canonicalOrder` sorts by canonical RDATA using caller-provided order and comparison buffers. Duplicate canonical records are rejected rather than silently changing the signed input.

```zig
const set = try dns.dnssec.Rrset.init(records);

var signed_data: [4096]u8 = undefined;
var order: [64]u16 = undefined;
var compare: [2048]u8 = undefined;
var writer = dns.dnssec.CanonicalWriter.init(&signed_data);

try dns.dnssec.rrset.writeSignedData(
    &writer,
    parsed_rrsig,
    set,
    order[0..records.len],
    &compare,
);
```

The signed-data writer emits directly to the destination. Sorting materializes only two canonical RDATA values at a time.

## RRSIG verification

`dns.dnssec.verify.verifyRrset` combines protocol validation, canonical signed-data generation, time validation, algorithm policy, and a crypto backend. Time is injected by the caller:

```zig
try dns.dnssec.verify.verifyRrset(
    rrsig_rr,
    dnskey_rr,
    set,
    now_unix_seconds,
    .{
        .signed_data = &signed_data,
        .order = order[0..records.len],
        .compare = &compare,
    },
    .{},
);
```

The verifier checks type covered, owner/class, signer, DNSKEY protocol, Zone Key flag, algorithm, key tag, wildcard label constraints, and the RFC 1982 interpretation of the 32-bit inception/expiration fields before invoking cryptography.

The built-in backend currently supports DNSSEC algorithms 5, 7, 8, 10, 13, 14, and 15. Algorithm 16 (Ed448) is accepted by the current default registry policy but is not implemented by Zig 0.16.0's standard crypto library; applications may inject a backend that supports it. This is intentionally distinct from policy acceptance.

`dns.dnssec.policy.AlgorithmPolicy` is a runtime-injectable recommendation policy. The bundled `registry_2026_01_13` value is date-stamped so a future IANA policy change cannot silently masquerade as timeless protocol semantics.

## DS and DNSKEY

`dns.dnssec.key.keyTag` implements DNSKEY key tags, including the historical algorithm-1 rule.

`dns.dnssec.ds` provides:

- SHA-1, SHA-256, and SHA-384 DS digest generation;
- digest-length/support queries;
- DNSKEY-to-DS matching over the canonical owner name plus DNSKEY RDATA.

The digest output buffer is caller-owned.

## Chain-of-trust primitives

`dns.dnssec.TrustAnchor`, `DnskeySet`, and `Delegation` represent authenticated inputs without embedding recursive network traversal into the library.

`Delegation.evaluate` returns a `ValidationState` with one of:

- `secure`;
- `insecure`;
- `bogus`;
- `indeterminate`.

Authenticated DS absence and NSEC3 Opt-Out remain distinguishable from an unproven delegation. A supported DS path with no matching DNSKEY is `bogus`; a DS set for which the selected policy/backend has no usable algorithm path is not accidentally promoted to `secure`.

## NSEC proofs

`dns.dnssec.denial` provides NSEC primitives for:

- canonical cyclic interval coverage;
- exact-owner NODATA;
- NXDOMAIN proof pieces;
- wildcard denial and wildcard NODATA.

NODATA rejects an NSEC bitmap containing CNAME, following the RFC 6840 clarification. These functions consume already-authenticated NSEC records; RRSIG authentication remains an explicit preceding step.

## NSEC3 proofs

`dns.dnssec.denial.nsec3` provides:

- SHA-1 NSEC3 hashing;
- Base32hex hash encoding/decoding;
- selected-chain validation;
- exact and covering-record lookup;
- closest-encloser proofs;
- NXDOMAIN, NODATA, wildcard, and Opt-Out proof composition.

The caller supplies `max_iterations` to `ProofSet.init`/hashing. There is no hidden global CPU policy. Exact NODATA and Opt-Out results are distinct values so the caller cannot accidentally treat an Opt-Out delegation proof as equivalent to ordinary authenticated existence.

## Wire helpers retained from 0.1.0

The DNSSEC facade still exposes parsers/builders for:

- DS / CDS;
- DNSKEY / CDNSKEY;
- RRSIG;
- NSEC type bitmaps;
- NSEC3 / NSEC3PARAM;
- TLSA / SMIMEA;
- SSHFP;
- ZONEMD parsing.

`validate.messageStrict` continues to enforce local wire invariants such as RDATA bounds and DNSSEC uncompressed-name requirements.

## What remains outside this layer

The current DNSSEC engine deliberately does not own:

- recursive delegation walking or network retries;
- root-anchor download/update/persistence;
- wall-clock acquisition;
- cache lifetime/prefetch policy;
- socket, TLS, QUIC, or HTTP transports;
- application policy for unsupported algorithms or NSEC3 iteration limits.

See [`../examples/dnssec.zig`](../examples/dnssec.zig) for a compact caller-owned workspace composition.

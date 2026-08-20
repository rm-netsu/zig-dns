# Changelog

## Unreleased

- Add allocation-free DNSSEC canonical name ordering, canonical RR/RDATA serialization, RRset validation and canonical sorting.
- Add streaming RRSIG signed-data generation with Original TTL and wildcard-owner reconstruction.
- Add DS digest generation, DNSKEY key tags/matching, injectable algorithm policy, and an injectable crypto backend.
- Add built-in RRSIG verification for RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256/P-384, and Ed25519 with caller-injected time.
- Add NSEC and NSEC3 authenticated-denial primitives, including closest-encloser, wildcard, NODATA, NXDOMAIN, Opt-Out, and explicit NSEC3 iteration limits.
- Add trust-anchor, DNSKEY-set, delegation, and security-status primitives for composing a chain of trust without transport ownership.
- Add deterministic canonicalization/RRset-order properties and a caller-owned DNSSEC composition example.
- Add independent RFC RRSIG vectors for RSA/SHA-256, RSA/SHA-512, ECDSA P-256/P-384, and Ed25519, including wildcard and corrupted-signature coverage.
- Add an optional dnspython interoperability gate and ReleaseFast core/DNSSEC benchmark harnesses.
- Synchronize the default validation policy with the IANA 2026-01-13 registry snapshot and make runtime RSA key-size dispatch safe.

## 0.1.0

- Add allocation-free DNS header/message/question/RR parsing with safe RFC 1035 name decompression.
- Add caller-buffer message construction with transactional writes and name compression.
- Support full uncompressed wire names for arbitrary DNS label octets alongside simple dotted helpers.
- Add typed common RDATA decoders and strict structural validation while preserving unknown RR types as opaque data.
- Add EDNS(0), ECS, Extended DNS Errors, padding, extended RCODEs, DNSSEC OK, and Compact Answers OK support.
- Add DNSSEC parsing/canonical-name helpers, NSEC/NSEC3 type bitmaps, DNSKEY key-tag calculation, and SVCB/HTTPS validation.
- Add UDP truncation, incremental DNS-over-TCP, DoT, DoQ, and DoH message-framing helpers.
- Add fixed-capacity resolver transaction matching and transport-neutral server response construction.
- Add deterministic parser, builder, compression, and stream-fragmentation property tests.

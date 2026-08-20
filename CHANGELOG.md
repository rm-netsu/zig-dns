# Changelog

## Unreleased

- Replace synthetic core microbenchmarks with a deterministic real-RRset wire corpus and an interleaved cross-tag A/B runner that reports MAD and paired regression deltas.

## 0.4.0 - 2026-08-20

- Add allocation-free RFC 5936 AXFR streaming with first/closing SOA validation, borrowed record events, query builders, premature-EOF detection, and fixed caller-owned state.
- Add RFC 1995 IXFR semantic events for delete/add deltas, RFC 1982 serial arithmetic, up-to-date responses, multi-delta streams, and AXFR fallback detection.
- Share canonical SOA snapshots between AXFR/IXFR so transfer state never retains prior DNS message buffers.
- Add TCP fragmentation coverage at every stream split, 256-message AXFR stress coverage, IXFR mutation replay, premature-EOF tests, and explicit persistent-state budgets.
- Compose AXFR with RFC 8945 request/continuation TSIG MAC chaining without moving authentication ownership into the transfer core.
- Extend DoQ stream decoding with explicit query, single-response, and multi-response cardinality so RFC 9250 zone transfers can carry multiple DNS messages before STREAM FIN.
- Accept omitted Question sections for native incremental IXFR responses while retaining the RFC 5936 first-Question requirement when IXFR falls back to AXFR semantics.
- Add a compile-checked streaming transfer example, integration documentation, and a ReleaseFast AXFR/IXFR benchmark baseline.

## 0.3.0 - 2026-08-20

- Add RFC 8945 TSIG parsing, transactional composition, HMAC-SHA1/HMAC-SHA256 authentication, truncation policy, BADTIME helpers, forwarding Original ID handling, and bounded multi-message MAC chaining.
- Add RFC 2136 DNS UPDATE composition with semantic prerequisite/add/delete helpers, strict prescan, zone-containment enforcement, RFC 3597 unknown-type passthrough, and TSIG composition.
- Add RFC 1996 NOTIFY request/response composition and transport-neutral response matching.
- Add signed UPDATE and TSIG dnspython interoperability gates plus deterministic TSIG/UPDATE property replay.
- Add bounded `tsig.auth.Key.init` helpers so examples and integrations do not need private wire-name conversion glue.
- Reject signed BADKEY/BADSIG responses and invalid TSIG request/error combinations before wire mutation.
- Reject UPDATE QTYPE/meta and reserved RR TYPE allocation ranges while preserving unknown ordinary and Private Use data RRTYPEs.
- Tighten NOTIFY request/success-response envelopes and distinguish canonical successful acknowledgement validation from ordinary error RCODE handling.

## 0.2.0 - 2026-08-20

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

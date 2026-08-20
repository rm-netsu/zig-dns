# Changelog

## Unreleased

## 0.7.0 - 2026-08-20

- Add caller-defined authoritative QUERY response composition for exact answers, CNAME/DNAME, RFC 4592 wildcards, delegations/referrals, glue, DS-at-cut, NODATA/NXDOMAIN, EDNS/BADVERS, explicit ANY policy, and whole-RRset truncation.
- Add DNSSEC-aware authoritative output with store-provided RRSIG and NSEC/NSEC3 proof hooks that fail closed when a zone declared signed cannot supply required material.
- Add an allocation-free `SliceStore` reference adapter while keeping production indexing/database ownership outside the protocol core.
- Add exact caller-owned tail reservation and TSIG in-place signing for already-finished responses, including end-to-end signed authoritative QUERY coverage.
- Clamp negative-response SOA and covering RRSIG TTLs to `min(SOA TTL, SOA.MINIMUM)` for RFC 2308-compliant negative caching.
- Add deterministic authoritative response replay, a compile-checked example, and a real-RRset ReleaseFast benchmark baseline.

## 0.6.0 - 2026-08-20

- Add a bounded caller-owned high-level resolver state machine with generation-safe handles and fixed compile-time query/alias limits.
- Return transport-neutral UDP/TCP/DoT/DoQ/DoH actions without owning sockets, timers, TLS, QUIC, HTTP, threads, or an allocator.
- Compose ID allocation/matching, EDNS downgrade, retry budgets, UDP truncation fallback, CNAME/DNAME continuation, and caller-driven referral descent.
- Add cache lookup/store hooks with injected time and conservative DNSSEC security-status composition; bogus validation results are terminal and never enter cache hooks.
- Complete recursive responses containing CNAME/DNAME plus the terminal target answer in the same packet without an unnecessary follow-up query.
- Add arbitrary-octet wire-name query/response helpers used by the high-level lifecycle.
- Add deterministic high-level lifecycle replay with stale-handle, capacity, malformed-response, retry, and mixed-transport coverage.
- Add a compile-checked high-level resolver example, explicit persistent-state budgets, and ReleaseFast lifecycle benchmarks.
- Re-run the real-RRset core A/B benchmark against v0.5.0; no core parser/validator/name/builder regression was confirmed within the observed paired-run spread.

## 0.5.0 - 2026-08-20

- Replace synthetic core microbenchmarks with a deterministic real-RRset wire corpus and an interleaved cross-tag A/B runner that reports MAD and paired regression deltas.
- Add zero-copy resolver response classification for answers, CNAME/DNAME, referrals, NODATA/NXDOMAIN, truncation, and terminal RCODEs.
- Add bounded caller-owned CNAME/DNAME chains with loop/depth/storage limits, DNAME substitution, and synthesized-CNAME validation.
- Enforce RFC 6672 uncompressed DNAME targets in both builders and strict validation.
- Add structured referral extraction with NS/DS iterators and bailiwick-aware in-domain/sibling/out-of-bailiwick glue filtering.
- Add generic bounded cache primitives for positive, NXDOMAIN, NODATA, and delegation entries with DNSSEC status, injected time, explicit replacement, and RFC 2308 negative TTL helpers.
- Add transport-neutral retry planning with TCP fallback, EDNS fallback constraints, alternate-server decisions, and RFC 9520 retry caps.
- Add deterministic resolver-classification replay, a compile-checked resolver composition example, and a ReleaseFast resolver-semantics benchmark baseline.

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

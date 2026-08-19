# Changelog

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

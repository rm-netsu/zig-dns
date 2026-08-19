# DNSSEC and modern RRs

The 0.1.0 package provides DNSSEC **wire and validation primitives**, not a cryptographic validating resolver.

## Implemented wire helpers

- DS / CDS
- DNSKEY / CDNSKEY
- RRSIG
- NSEC type bitmaps
- NSEC3 / NSEC3PARAM
- canonical uncompressed domain names
- DNSKEY key-tag calculation, including the historical algorithm-1 rule
- TLSA / SMIMEA
- SSHFP
- ZONEMD parsing

`validate.messageStrict` also enforces the DNSSEC rule that RRSIG signer names and NSEC next-domain names are not compressed.

## Key tags

`dnssec.dnskeyKeyTag` implements the RFC 4034 checksum for normal DNSKEY algorithms. Algorithm 1 (RSA/MD5) is handled separately from its RSA public-key encoding; the implementation follows the verified RFC 4034 erratum for which two modulus octets form the historical tag.

## Canonical names

`Name.writeCanonicalWire` expands compression and lowercases ASCII letters while retaining exact label boundaries. This is the primitive needed by DNSSEC canonical RR processing.

The package does not yet implement full canonical RRset serialization, signature verification, trust-anchor management, negative-answer proof validation, or chain building. A validating resolver can build those policies and cryptographic operations above the exposed records without changing the packet parser.

## SVCB / HTTPS

`svcb.validateRecord` verifies the main wire invariants used by consumers:

- IN class;
- uncompressed TargetName;
- strictly increasing SvcParamKey order;
- mandatory-key references;
- ALPN list framing;
- no-default-alpn relationship;
- port and IP-hint lengths.

Alias-mode parameters are intentionally ignored by the semantic validator, matching recipient behavior defined by SVCB/HTTPS.

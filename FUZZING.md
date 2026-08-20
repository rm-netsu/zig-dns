# Fuzzing

The normal unit suite includes deterministic property-style coverage for the protocol boundaries most likely to receive hostile input.

Current replay coverage includes:

1. arbitrary byte strings through `Message.init` and `validate.messageStrict`;
2. builder → parser round trips over generated multi-label names;
3. DNS-over-TCP framing under randomized stream fragmentation;
4. compression pointer loop/forward-pointer rejection;
5. DNSSEC canonical RR output under randomized presentation-name case;
6. DNSSEC signed RRset output under randomized record permutations;
7. arbitrary TSIG RDATA through the RFC 8945 structural parser;
8. UPDATE prescan over arbitrary UPDATE-shaped packets plus generated semantic operations;
9. generated IXFR delta streams plus deterministic wire mutation replay through the state machine;
10. resolver response classification over arbitrary QUERY-shaped packets;
11. bounded high-level resolver lifecycle replay across slot reuse, retries, mixed transports, valid/malformed responses, and stale handles;
12. authoritative query/EDNS/output-cap replay with response strict-validation and deterministic wire mutation;
13. operational EDNS replay over arbitrary COOKIE/KEEPALIVE/NSID/PADDING/EDE/EXPIRE/REPORT-CHANNEL/UPDATE-LEASE/ZONEVERSION/MQTYPE/DAU/DHU/N3U/KEY-TAG/CHAIN payloads plus generated typed round trips and block-padding boundary properties;
14. bounded EDNS and RDATA parsing tests in their owning modules.

Run it with:

```bash
zig build test
```

For an external fuzzing harness, the best stateless entry points are:

- `Message.init(bytes)` followed by `validate.messageStrict`;
- `Name.init(packet, offset)` followed by `writeWire` into a 255-byte buffer;
- `edns.Opt.fromRecord` + option iteration, including typed COOKIE/KEEPALIVE/NSID/PADDING/EDE/EXPIRE/REPORT-CHANNEL/UPDATE-LEASE/ZONEVERSION/MQTYPE/DAU/DHU/N3U/KEY-TAG/CHAIN parsers;
- `svcb.validateRecord`;
- `dnssec.TypeBitmapIterator.next`;
- `dnssec.CanonicalWriter.writeRecord`;
- `dnssec.Rrset.canonicalOrder` and `dnssec.rrset.writeSignedData`;
- `dnssec.denial.nsec3.hashName` with an explicit iteration cap;
- `tsig.parse` followed by `tsig.validateSemantics`;
- `update.validateRequest` over packets with OPCODE=UPDATE.
- `transfer.axfr.Transfer` / `transfer.ixfr.Transfer` with arbitrary valid-message boundaries and explicit EOF;
- `resolver.response.classify` followed by alias/referral processing on structurally valid responses;
- `high_level.Resolver` with deterministic action/event sequences and bounded caller-owned storage;
- `authoritative.Composer` with arbitrary structurally valid QUERY envelopes, output caps, EDNS sizing, and caller-defined store adapters.

The parser APIs do not allocate, so fuzz harnesses can run them with fixed stack/caller buffers and no allocator noise.

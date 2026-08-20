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
10. bounded EDNS and RDATA parsing tests in their owning modules.

Run it with:

```bash
zig build test
```

For an external fuzzing harness, the best stateless entry points are:

- `Message.init(bytes)` followed by `validate.messageStrict`;
- `Name.init(packet, offset)` followed by `writeWire` into a 255-byte buffer;
- `edns.Opt.fromRecord` + option iteration;
- `svcb.validateRecord`;
- `dnssec.TypeBitmapIterator.next`;
- `dnssec.CanonicalWriter.writeRecord`;
- `dnssec.Rrset.canonicalOrder` and `dnssec.rrset.writeSignedData`;
- `dnssec.denial.nsec3.hashName` with an explicit iteration cap;
- `tsig.parse` followed by `tsig.validateSemantics`;
- `update.validateRequest` over packets with OPCODE=UPDATE.
- `transfer.axfr.Transfer` / `transfer.ixfr.Transfer` with arbitrary valid-message boundaries and explicit EOF.

The parser APIs do not allocate, so fuzz harnesses can run them with fixed stack/caller buffers and no allocator noise.

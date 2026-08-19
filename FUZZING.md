# Fuzzing

The normal unit suite includes deterministic property-style coverage for the protocol boundaries most likely to receive hostile input.

Current replay coverage includes:

1. arbitrary byte strings through `Message.init` and `validate.messageStrict`;
2. builder → parser round trips over generated multi-label names;
3. DNS-over-TCP framing under randomized stream fragmentation;
4. compression pointer loop/forward-pointer rejection;
5. bounded EDNS and RDATA parsing tests in their owning modules.

Run it with:

```bash
zig build test
```

For an external fuzzing harness, the best stateless entry points are:

- `Message.init(bytes)` followed by `validate.messageStrict`;
- `Name.init(packet, offset)` followed by `writeWire` into a 255-byte buffer;
- `edns.Opt.fromRecord` + option iteration;
- `svcb.validateRecord`;
- `dnssec.TypeBitmapIterator.next`.

The parser APIs do not allocate, so fuzz harnesses can run them with fixed stack/caller buffers and no allocator noise.

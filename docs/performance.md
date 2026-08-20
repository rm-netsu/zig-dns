# Performance

`dns` keeps benchmarks separate from correctness tests so release builds can
measure hot paths without making normal CI timing-sensitive.

Run the benchmarks with Zig 0.16.0:

```bash
zig build bench-core -Doptimize=ReleaseFast
zig build bench-dnssec -Doptimize=ReleaseFast
```

The benchmark roots are also compiled by `zig build check` so API changes
cannot silently break them.

## 0.2.0 review

The figures below are release-review measurements from the x86_64 Linux
project environment. They are not portable performance promises. Compare
changes on the same machine and toolchain.

### Core A/B against v0.1.0

The same `bench/core.zig` source was compiled against `v0.1.0` and the current
0.2.0 development tree with `-OReleaseFast`. Nine runs were interleaved and
the median throughput was used:

| Operation | v0.1.0 | 0.2.0 tree | Delta |
| --- | ---: | ---: | ---: |
| parse message + iterate sections | 5,742,955 ops/s | 5,724,278 ops/s | -0.33% |
| decompress compressed owner name | 66,337,055 ops/s | 69,870,201 ops/s | +5.33% |
| build representative response | 2,548,040 ops/s | 2,602,656 ops/s | +2.14% |

The existing parser, `Name.writeWire`, and builder hot paths were not changed
by the DNSSEC work. These small differences are treated as environment/code
layout noise rather than claimed speedups. The review found no material core
throughput regression.

### DNSSEC baseline

Five ReleaseFast runs were sampled; the table reports medians:

| Operation | Median |
| --- | ---: |
| canonical RRSIG signed-data generation, one-record MX RRset | 103 ns/op |
| Ed25519 RRSIG verification | 70,248 ns/op |
| DS SHA-256 digest | 64 ns/op |
| NSEC3 SHA-1 hash, zero extra iterations | 110 ns/op |

The benchmarked RRSIG path uses 770 bytes of caller-owned scratch storage and
a 48-byte `dns.dnssec.verify.Workspace` descriptor. The low-level benchmark
paths do not request an allocator.

NSEC3 cost scales with the record's iteration count. The API therefore keeps
the validation limit caller-owned instead of hiding an unbounded CPU policy.

## Benchmark policy

Before accepting a hot-path optimization:

1. run the representative benchmark in ReleaseFast;
2. compare against the previous tag using the same benchmark source;
3. check caller-owned/persistent state size as well as throughput;
4. keep correctness/property/interoperability tests independent from timing;
5. do not keep an optimization whose benefit disappears on realistic data.

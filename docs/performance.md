# Performance

`dns` keeps timing-sensitive benchmarks separate from correctness tests. The
benchmark roots are still compiled by `zig build check`, so API changes cannot
silently leave them stale.

Run the ReleaseFast benchmarks with Zig 0.16.0:

```bash
zig build bench-core -Doptimize=ReleaseFast
zig build bench-dnssec -Doptimize=ReleaseFast
zig build bench-transfer -Doptimize=ReleaseFast
zig build bench-resolver -Doptimize=ReleaseFast
zig build bench-high-level -Doptimize=ReleaseFast
zig build bench-authoritative -Doptimize=ReleaseFast
```

For cross-release core A/B measurements, compile the **same current benchmark
source** against each tag:

```bash
python3 bench/compare_releases.py \
  v0.1.0 v0.2.0 v0.3.0 v0.4.0 \
  --runs 13 \
  --zig /path/to/zig
```

The runner pins benchmark processes to one CPU when `taskset` is available,
warms every binary before sampling, rotates/reverses release order between
rounds, reports median absolute deviation (MAD), and records raw samples as
JSON when `--json` is supplied. `--round-offset` plus `--merge-json` allows the
same interleaved run sequence to be split across environments with per-process
time limits.

## Real-data core corpus

`bench/core.zig` no longer benchmarks one synthetic `www.example.com` packet or
an isolated ~10 ns `Name.writeWire` call. It uses the deterministic fixtures in
`bench/corpus/`.

The 2026-08-20 snapshot contains **13 messages / 3278 bytes of DNS wire data per
corpus pass** and covers:

- short A and AAAA responses;
- multi-record NS, CAA, MX, and TXT responses;
- CNAME indirection;
- NODATA and NXDOMAIN with SOA authority data;
- DS and an 853-byte root DNSKEY response;
- an 884-byte `.com` referral with 13 NS records, DS, and IPv4/IPv6 glue;
- EDNS on every message.

These are normalized snapshots built from real RRsets, not live network calls
or literal packet captures. IDs, TTLs, ordering, flags, and EDNS details may be
normalized so a DNS change tomorrow cannot change an A/B result. Provenance and
normalization notes live in `bench/corpus/README.md`.

The timed workloads are:

1. parse the message and iterate every question/RR;
2. strict structural validation;
3. parse and materialize every question/owner name;
4. build equivalent representative responses with caller-owned buffers and
   compression storage.

This deliberately removes the old isolated name microbenchmark. Across earlier
runs it reported changes of roughly -7% and +8% between releases even when the
underlying name-writing algorithm had not materially changed, making it a poor
regression signal.

## Core release A/B review

The following ReleaseFast review used Zig 0.16.0, benchmark hash
`23c4a01c33`, one pinned CPU, and 13 interleaved rounds. The throughput columns
are independent medians. The final two columns use **paired samples from the
same rounds**, which are the primary regression signal because they are less
sensitive to host-wide drift during a long run.

| Workload | v0.1.0 | v0.2.0 | v0.3.0 | v0.4.0 | v0.4 vs v0.1 paired | paired MAD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| parse real corpus | 2.551 M msg/s | 2.639 M | 2.643 M | 2.635 M | +0.44% | 5.42 pp |
| strict validate | 0.960 M msg/s | 0.972 M | 0.960 M | 0.946 M | +0.51% | 4.98 pp |
| parse + materialize names | 2.304 M msg/s | 2.248 M | 2.231 M | 2.252 M | -0.04% | 2.69 pp |
| build real corpus | 1.292 M msg/s | 1.319 M | 1.308 M | 1.344 M | +4.05% | 2.68 pp |

Adjacent-release paired medians were:

| Workload | v0.1→v0.2 | v0.2→v0.3 | v0.3→v0.4 |
| --- | ---: | ---: | ---: |
| parse real corpus | +2.47% | +0.14% | -1.04% |
| strict validate | +0.12% | -1.99% | +1.37% |
| parse + materialize names | +1.44% | -3.64% | +3.20% |
| build real corpus | +2.62% | -1.89% | +3.05% |

The raw 13-round samples and derived statistics are retained in
`bench/results/core-real-corpus-v0.1.0-v0.4.0-2026-08-20.json`.

### Regression verdict

No material core regression is confirmed between `v0.1.0` and `v0.4.0` on the
real-data corpus. The apparent strict-validation regression seen in shorter
runs did not survive the longer paired A/B review. Parse, validation, and name
materialization are effectively flat relative to their observed run-to-run
spread. Builder throughput is higher in this sample, but it is not claimed as
an optimization because builder logic was not intentionally optimized across
these releases and code-layout effects are measurable at this scale.

## DNSSEC baseline

DNSSEC was new in 0.2.0, so these are baselines rather than cross-tag speedup
claims. Five ReleaseFast runs were sampled on the same x86_64 Linux project
environment; the table reports medians:

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

## 0.4.0 transfer baseline

AXFR/IXFR state machines were new in 0.4.0, so there is no meaningful A/B
comparison with v0.3.0. Five ReleaseFast runs were sampled; the table reports
median latency:

| Operation | Median | Persistent storage |
| --- | ---: | ---: |
| single-message AXFR, 4 ordinary RRs | 1,470 ns/op | 765 B |
| one-delta IXFR, 1 delete + 1 add | 1,973 ns/op | 1,275 B |

The corresponding `Transfer` descriptors are 56 B for AXFR and 104 B for IXFR.
The benchmark performs parsing/state transitions but no socket I/O, heap
allocation, zone-store writes, or TSIG cryptography.

Separate stress tests feed 256 AXFR DNS messages through the same fixed storage
and replay generated IXFR delta streams. Protocol state is therefore independent
of transfer message count and zone size; only the caller's current DNS message
buffer and destination zone store scale with transferred data.

## 0.5.0 resolver-semantics baseline

Resolver classification, alias/referral processing, and bounded cache lookup
are new in 0.5.0, so these are baselines rather than cross-tag speedup claims.
Five ReleaseFast runs were sampled on the same x86_64 Linux project
environment; the table reports medians (MAD in parentheses):

| Operation | Median |
| --- | ---: |
| classify one response from the 13-message real corpus | 486 ns/op (14.6 ns) |
| extract the real `.com` referral (13 NS + DS + A/AAAA glue) | 43.3 us/op (5.86 us) |
| bounded cache lookup using real corpus query names | 79.3 ns/op (4.53 ns) |
| follow the real `status.openai.com` CNAME | 131 ns/op (9.32 ns) |

The referral workload intentionally uses the zero-allocation iterator path and
performs no pre-indexing. Its cost is therefore a useful baseline for a future
optional caller-scratch index if iterative-resolver profiling shows referral
processing to be material. No heap allocation or network I/O is included in
any resolver benchmark.

## 0.6.0 high-level resolver baseline

The bounded high-level lifecycle is new in 0.6.0. The benchmark uses the same
real-data corpus where a received response is needed and does not perform
socket, TLS, QUIC, HTTP, timer, or allocator work. Five ReleaseFast runs were
sampled; the table reports median latency and median absolute deviation (MAD):

| Lifecycle | Median | MAD |
| --- | ---: | ---: |
| begin -> real `cloudflare.com A` response -> complete -> release | 532 ns/op | 16 ns |
| begin -> real `status.openai.com` CNAME + terminal A records in one response -> complete -> release | 1,399 ns/op | 18 ns |
| begin UDP -> TC response -> TCP action -> real A response -> complete -> release | 655 ns/op | 7 ns |
| begin -> caller cache-hook hit -> complete -> release | 82 ns/op | 3 ns |

With the default compile-time configuration (`max_queries=64`,
`max_alias_depth=16`, `alias_storage_bytes=1024`) the caller-owned
`Resolver.Storage` is **87,552 bytes** on the benchmark x86_64 target, or 1,368
bytes per maximum concurrent query. The resolver descriptor itself is 48 bytes.
No persistent state grows with response size or number of retries.

A 28-round interleaved ReleaseFast regression review compiled the same real
core benchmark source (hash `23c4a01c33`) against `v0.5.0` and the 0.6 high-level
release candidate. Paired median throughput deltas were:

| Existing core workload | 0.6 candidate vs v0.5.0 paired median | paired MAD |
| --- | ---: | ---: |
| parse real corpus | -0.00% | 2.87 pp |
| strict validate | -1.03% | 3.38 pp |
| parse + materialize names | -0.93% | 5.70 pp |
| build real corpus | +0.18% | 2.49 pp |

No existing parser/validator/name/builder hot-path source changed in this
release candidate, and none of these deltas exceeds the observed paired spread.
The result is therefore classified as **no confirmed core regression**, not as
an optimization claim. Raw samples are retained in
`bench/results/core-real-corpus-v0.5.0-v0.6.0-rc-2026-08-20.json`.

## 0.7.0 authoritative baseline

Authoritative response composition is new in 0.7.0, so these are baselines rather than cross-release speedup claims. The benchmark reuses fixed real RRsets from the normal core corpus and performs no socket, filesystem, allocator, zone-database, TLS, or QUIC work. Five ReleaseFast runs were sampled; the table reports median latency and median absolute deviation (MAD):

| Workload | Median | MAD |
| --- | ---: | ---: |
| compose real `cloudflare.com` A RRset | 638 ns/op | 25.6 ns |
| compose real `cloudflare.com` CAA RRset | 924 ns/op | 21.2 ns |
| compose real `chatgpt.com` TXT RRset | 796 ns/op | 12.8 ns |
| compose NXDOMAIN + RFC 2308 SOA | 1,890 ns/op | 47.0 ns |
| compose real A response + exact TSIG reserve + HMAC-SHA256 in-place signing | 1,114 ns/op | 33.1 ns |

The reference `SliceStore` descriptor is 32 bytes and `Composer(SliceStore)` is 8 bytes on the benchmark x86_64 target. The store benchmark intentionally uses linear scans; indexed production stores can implement the same structural interface without changing composer ownership.

The TSIG workload includes the response HMAC and secure-zeroing the returned MAC. The signed request MAC is prepared before timing. Exact tail reservation is part of the compose call, so the measured path exercises the production rule that OPT/ordinary RRsets must leave sufficient room for final TSIG without exceeding the negotiated UDP response limit.

Raw samples are retained in `bench/results/authoritative-v0.7.0-2026-08-20.json`.

## 0.8.0 operational regression review

The 0.8 operational work is mostly outside the existing core fast paths, but
strict validation now performs additional typed option/context and modern-RR
checks. A 24-round interleaved ReleaseFast A/B review compiled the same
real-data core benchmark source (hash `23c4a01c33`) with Zig 0.16.0 against
`v0.7.0` (`63000a96d176`) and the complete operational candidate
`dd418ab89a45`. Processes were pinned to CPU 4. Paired throughput deltas were:

| Existing core workload | 0.8 candidate vs v0.7.0 paired median | paired MAD |
| --- | ---: | ---: |
| parse real corpus | -0.61% | 2.26 pp |
| strict validate | -0.39% | 2.41 pp |
| parse + materialize names | -1.10% | 2.21 pp |
| build real corpus | +1.88% | 2.62 pp |

None of the paired deltas exceeds the observed paired spread, so this is
classified as **no confirmed core regression**. After the first 16 pairs,
name materialization briefly sat close to the measured-noise boundary; an
additional independently ordered eight-pair batch reversed that apparent
slowdown and the 24-pair aggregate is therefore retained instead of selecting
a favorable short batch. The benchmark binaries were 4,078,736 bytes for
`v0.7.0` and 4,110,584 bytes for the candidate (+31,848 bytes, +0.78%); the
change includes the newly reachable operational EDNS, RESINFO, DSYNC, and
generalized-NOTIFY APIs. These additions introduce no allocator ownership or
new persistent runtime state in the existing core paths.

Raw samples and exact resolved revisions are retained in
`bench/results/core-real-corpus-v0.7.0-v0.8.0-dev-2026-08-20.json`.

## Benchmark policy

Before accepting a hot-path optimization:

1. benchmark realistic data in ReleaseFast;
2. compare tags with the same benchmark source and fixture hash;
3. prefer interleaved paired deltas over unrelated one-shot medians;
4. report spread (at least MAD), not only the fastest run;
5. measure caller-owned/persistent state and allocations as well as throughput;
6. keep correctness/property/interoperability tests independent from timing;
7. reject optimizations whose benefit disappears on realistic workloads.

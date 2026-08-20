# dns

A transport-neutral DNS protocol library for Zig 0.16.0.

`dns` is designed for the same style of systems code as `zig-http`: protocol state and wire correctness live in the library, while socket ownership, TLS, QUIC, HTTP transports, timers, caches, and event loops remain under the application's control.

## Status

Version 0.7.0 is the current authoritative-composition release. The public API is still pre-1.0 and may be refined as real integrations exercise it.

## Highlights

- zero-copy DNS message parsing with caller-controlled name expansion;
- allocation-free message building into caller-provided buffers;
- RFC 1035 name compression with backward-pointer validation;
- arbitrary-octet domain names through uncompressed wire-name APIs;
- transactional builder operations that roll back after local write failures;
- typed helpers for common RRs and raw passthrough for every unknown RR type;
- EDNS(0), extended RCODEs, ECS, EDE, padding, DNSSEC OK and Compact Answers OK flags;
- DNSSEC canonical RRset serialization, RRSIG verification, DS/DNSKEY matching, NSEC/NSEC3 denial proofs, and chain-of-trust primitives;
- caller-injected DNSSEC algorithm policy, crypto backend, time, and bounded scratch storage;
- RFC 8945 TSIG HMAC authentication with bounded multi-message chaining and explicit truncation policy;
- RFC 2136 Dynamic UPDATE composition/prescan with semantic prerequisite and add/delete APIs;
- RFC 1996 SOA NOTIFY composition, validation, and transport-neutral response matching;
- SVCB/HTTPS validation, including uncompressed targets and ordered SvcParams;
- UDP truncation policy helper and incremental DNS-over-TCP decoder;
- DoT, DoQ, and DoH wire/framing helpers without TLS, QUIC, or HTTP dependencies;
- fixed-capacity resolver transaction table for pipelined/out-of-order responses;
- zero-copy response classification, bounded CNAME/DNAME chains, structured referral/glue extraction, bounded cache primitives, and retry planning;
- bounded high-level resolver state machine with generation-safe handles, UDP/TCP/DoT/DoQ/DoH actions, alias/referral composition, cache hooks, and DNSSEC status propagation;
- deterministic parser/builder/fragmentation/resolver/high-level lifecycle property tests.

## Package integration

After adding the package to `build.zig.zon`, expose the module to your executable:

```zig
const dns_dep = b.dependency("dns", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("dns", dns_dep.module("dns"));
```

The package name and import name are both `dns`; the repository is intended to be named `zig-dns`.

## Parse a response

```zig
const dns = @import("dns");

const msg = try dns.Message.init(packet);
_ = try dns.validate.messageStrict(msg, .{});

var answers = try msg.records(.answer);
while (try answers.next()) |rr| {
    switch (rr.rr_type) {
        .A => {
            const address = try dns.rdata.a(rr);
            _ = address;
        },
        .AAAA => {
            const address = try dns.rdata.aaaa(rr);
            _ = address;
        },
        else => {
            // Unknown and unsupported RR types remain available as raw RDATA.
            _ = rr.rdata;
        },
    }
}
```

`Message`, `Question`, `Record`, and their iterators borrow the original packet. No heap allocation occurs while parsing.

## Build a query

```zig
var packet: [1232]u8 = undefined;
var compression: [32]dns.CompressionEntry = undefined;

const wire = try dns.resolver.buildQuery(
    &packet,
    &compression,
    0x1234,
    .{ .name = "example.com", .qtype = .AAAA },
    .{
        .udp_payload_size = 1232,
        .dnssec_ok = true,
    },
    &.{},
);
```

The builder writes directly to `packet`. Compression state also comes from caller storage, so the hot path has no allocator requirement.

For binary labels or names that cannot be represented by the simple dotted helper, use `dns.name.Uncompressed` with `addQuestionWire`, `beginRecordWire`, or `addRawRecordWire`.

## Resolver transaction matching

DNS-over-TCP permits pipelining and does not require responses to arrive in query order. A bounded transaction table is provided without owning the transport:

```zig
var tx: dns.resolver.FixedTransactions(64) = .{};
const slot = try tx.reserve(id, .{ .name = "example.com", .qtype = .A });
errdefer tx.cancel(slot);

// Send the query by UDP/TCP/DoT/DoH/DoQ using your runtime.

const matched = try tx.match(response_packet);
const response = matched.response;
_ = response;
```

The response matcher checks ID, query opcode, question count, QTYPE/QCLASS, and DNS label boundaries rather than flattening a name to an ambiguous dotted byte string.

## TCP, DoT, DoQ, and DoH

DNS-over-TCP framing is incremental and uses caller-owned message storage:

```zig
var message_storage: [65535]u8 = undefined;
var decoder = dns.tcp.Decoder.init(&message_storage);

const feed = try decoder.feed(received_bytes);
switch (feed.event) {
    .need_more => {},
    .message => |wire| {
        const msg = try dns.Message.init(wire);
        _ = msg;
    },
}
```

Use `feed.consumed` to process coalesced messages. `finish()` detects truncated EOF.

- `dns.dot` reuses DNS-over-TCP framing and publishes DoT transport constants.
- `dns.doq.StreamDecoder` enforces DoQ ID/role/cardinality and supports multi-response AXFR/IXFR streams.
- `dns.doh` provides `application/dns-message` constants and base64url GET encoding/decoding.

The library does **not** own TCP sockets, TLS sessions, QUIC streams, or HTTP requests.

## Strict validation

`dns.validate.messageStrict` performs structural checks beyond safe iteration:

- all counted sections consume the packet exactly;
- OPT appears at most once and only in Additional;
- OPT owner is the root name;
- EDNS version policy;
- known RDATA structures are internally bounded;
- DNSKEY protocol/public-key checks;
- DNSSEC uncompressed-name requirements for RRSIG/NSEC;
- NSEC/NSEC3 type bitmap structure;
- SVCB/HTTPS target and SvcParam rules.

Unknown RR types remain valid and are not rejected merely because the library has no typed decoder for them.

## Name model

`dns.Name` is a view into a packet. Compression pointers are followed only backwards, pointer loops and overlong expanded names are rejected, and expansion happens only when requested.

Two representations are intentionally available:

- simple dotted presentation helpers for conventional DNS names;
- `dns.name.Uncompressed` for the full DNS wire-name space, including arbitrary label octets.

`writeWire` and `writeCanonicalWire` preserve label boundaries; the latter also applies DNS ASCII case-folding required by canonical DNSSEC name processing.

## Scope

Version 0.7.0 includes:

- RFC 1035 message/header/question/RR wire processing;
- EDNS(0) and common EDNS options;
- UDP/TCP transport framing and truncation decisions;
- DNSSEC RR parsing, canonical RRsets, RRSIG verification, DS/DNSKEY matching, denial proofs, and trust-link primitives;
- SVCB/HTTPS wire validation;
- DoT/DoH/DoQ protocol adaptation helpers;
- bounded resolver transaction/response helpers plus response classification, alias processing, referral extraction, cache primitives, and retry planning;
- a bounded high-level resolver state machine that returns transport/cache/referral/completion actions while leaving I/O, clocks, server addresses, and runtime ownership to the caller;
- authoritative QUERY response composition over caller-defined zone stores, including wildcard/delegation/glue/negative/DNSSEC semantics and caller-reserved TSIG tails;
- TSIG request/response authentication and transfer-ready continuation MAC state;
- Dynamic UPDATE composition/validation and SOA NOTIFY protocol primitives.
- allocation-free AXFR/IXFR receivers with semantic events, AXFR fallback, RFC 1982 serial handling, and bounded persistent state;
- TCP/DoT/DoQ zone-transfer composition, including multi-response DoQ stream framing.

Deliberately outside the protocol core:

- socket and event-loop ownership;
- TLS/QUIC/HTTP implementations;
- network ownership, upstream address discovery, and recursive server-selection policy;
- cache eviction/staleness/prefetch/failure-cache policy;
- recursive DNSSEC delegation walking and trust-anchor lifecycle management;
- mDNS/LLMNR policy;
- zone-file text parsing.

These can be layered above the wire/core APIs without forcing their resource model on every user.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — ownership, parsing, encoding, and layering.
- [`docs/transports.md`](docs/transports.md) — UDP, TCP, DoT, DoQ, and DoH integration.
- [`docs/transfer.md`](docs/transfer.md) — allocation-free AXFR/IXFR streaming and TCP/DoQ/TSIG composition.
- [`docs/resolver.md`](docs/resolver.md) — response semantics, aliases, referrals/glue, bounded cache primitives, and retry planning.
- [`docs/high_level_resolver.md`](docs/high_level_resolver.md) — bounded query lifecycle, transport actions, cache/DNSSEC hooks, and referral composition.
- [`docs/authoritative.md`](docs/authoritative.md) — caller-owned authoritative response composition, DNSSEC proof hooks, truncation, and TSIG reservation.
- [`docs/dnssec.md`](docs/dnssec.md) — DNSSEC validation, canonical RRsets, denial proofs, and crypto-policy boundaries.
- [`docs/tsig.md`](docs/tsig.md) — RFC 8945 signing, verification, error semantics, and multi-message chaining.
- [`docs/update.md`](docs/update.md) — Dynamic UPDATE, signed UPDATE, and NOTIFY composition/validation.
- [`docs/performance.md`](docs/performance.md) — release A/B methodology and DNSSEC benchmark baseline.
- [`FUZZING.md`](FUZZING.md) — deterministic property corpus and suggested fuzz entry points.

## Development

```bash
zig build test
zig build check
zig build example-inspect
zig build example-resolver
zig build example-high-level-resolver
zig build example-authoritative
zig build example-dnssec
zig build example-update
zig build interop-dnssec     # optional: requires dnspython + cryptography
zig build interop-tsig       # optional: requires dnspython
zig build interop-update     # optional: requires dnspython
zig build bench-core -Doptimize=ReleaseFast
zig build bench-dnssec -Doptimize=ReleaseFast
zig build bench-transfer -Doptimize=ReleaseFast
zig build bench-resolver -Doptimize=ReleaseFast
zig build bench-high-level -Doptimize=ReleaseFast
zig build bench-authoritative -Doptimize=ReleaseFast
```

The project targets Zig 0.16.0.

## License

MIT.

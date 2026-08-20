# Resolver semantics

`dns` keeps recursive-resolution semantics separate from socket, timer, thread,
and event-loop ownership. The resolver layer consumes already received DNS
messages and returns structured protocol state that an application can compose
with any UDP/TCP/DoT/DoH/DoQ runtime.

## Response classification

After transaction/question validation, classify a QUERY response without
allocation:

```zig
const outcome = try dns.resolver.response.classify(message, question);
switch (outcome) {
    .answer => {},
    .cname => |rr| {},
    .dname => |rr| {},
    .referral => {},
    .nodata => {},
    .nxdomain => {},
    .servfail, .formerr, .truncated, .failure => {},
}
```

NXDOMAIN is determined from RCODE. NOERROR/no-answer responses distinguish
NODATA from referrals using Authority semantics, and a referral is validated
as an actual delegation rather than accepting any unrelated NS record.

## Bounded CNAME/DNAME chains

`dns.resolver.alias.Chain` stores only canonical wire names in caller-provided
entry and byte storage. It does not retain response packets.

```zig
var entries: [16]dns.resolver.alias.Entry = undefined;
var names: [1024]u8 = undefined;
var chain = try dns.resolver.alias.Chain.initPresentation(
    &entries,
    &names,
    question.name,
);

try chain.followCname(cname_record);
// or: try chain.followDname(dname_record);
```

The chain detects loops, enforces the caller's depth/storage limits, and keeps
state transactional on failure. DNAME substitution is label-aware, supports a
root-owner DNAME, rejects results over the 255-octet wire-name limit, and can
validate a server-synthesized CNAME against the DNAME.

## Referral extraction and glue

`dns.resolver.referral.Referral` borrows the DNS message and exposes NS, DS,
and matching Additional A/AAAA iterators.

```zig
const referral = try dns.resolver.referral.Referral.init(message, question);

var ns = try referral.nameServers();
while (try ns.next()) |server| {
    _ = server.target;
}

var glue = try referral.gluePresentation("example"); // current parent zone
while (try glue.next()) |item| {
    if (!item.usable()) continue;
    switch (item.scope) {
        .in_domain, .sibling => {},
        .out_of_bailiwick => unreachable,
    }
}
```

The current parent zone is explicit because a response alone cannot determine
whether an NS target outside the delegated child is a sibling name or truly
out of bailiwick. Additional A/AAAA records are returned only when their owner
matches an NS target. Unrelated Additional address data is ignored.

`GlueScope` has three values:

- `in_domain`: NS target is at/below the delegated child;
- `sibling`: outside the child but still below the current parent zone;
- `out_of_bailiwick`: outside the parent's authority and therefore not usable
  as trusted glue.

## Cache primitives

`dns.cache.Fixed` is a generic bounded metadata/value cache. `Payload` remains
application-defined, so it can be an RRset handle, arena offset, or inline
small value.

```zig
const Cache = dns.cache.Fixed(MyHandle, 256, 128);
var cache = Cache.init();

_ = try cache.putPresentation("www.example", .{
    .kind = .positive,
    .rr_type = .A,
    .security = .secure,
    .expires_at = dns.cache.expiresAt(now, ttl),
}, handle, now, null);
```

Supported entry kinds are positive RRset, NXDOMAIN, NODATA, and delegation.
NXDOMAIN lookup is name/class-wide; NODATA and positive data are type-specific.
`findDelegation*` returns the deepest live cached ancestor. Fresh existence data
(positive, NODATA, or delegation) invalidates an exact-name NXDOMAIN, while a
new NXDOMAIN invalidates contradictory exact-name positive/NODATA/delegation
entries.

The cache owns no clock or eviction policy. `now` is injected.
`remainingTtl(expires_at, now)` derives the TTL to emit or display. When all
slots are live, `put*` returns `Full` unless the caller explicitly supplies a
replacement slot. `slotView`, `reusableSlot`, and exact-name invalidation are
provided to build custom replacement/coherence policies without exposing
internal implementation details.

For authoritative negative responses:

```zig
const ttl = try dns.cache.negativeTtl(soa_record);
const expires = try dns.cache.negativeExpiresAt(now, soa_record);
```

The helper applies the RFC 2308 `min(SOA TTL, SOA.MINIMUM)` rule.

## Retry planning

`dns.resolver.retry` maps the result of one transport attempt to an action but
does not send anything itself:

```zig
const decision = dns.resolver.retry.plan(.{
    .transport = .udp,
    .queries_sent = attempts_to_this_server,
    .other_servers_available = true,
    .edns_used = true,
    .edns_required = dnssec_required,
}, event);
```

Actions are:

```text
retry_udp
fallback_tcp
retry_other_server
retry_without_edns
terminal
```

The UDP retry budget is capped at three total queries to one server address on
one transport. A FORMERR without OPT can trigger EDNS fallback only if EDNS was
used and is not required. A FORMERR carrying OPT is treated as a protocol/EDNS
error rather than proof that the server lacks EDNS support.

## Ownership boundary

These modules deliberately do not own:

- sockets or TLS/QUIC/HTTP clients;
- timers or retry delays;
- server-address selection;
- trust-anchor lifecycle;
- cache payload arenas/databases;
- eviction, prefetch, or stale-serving policy.

They provide the protocol decisions and bounded state needed to implement
those policies above the core library.

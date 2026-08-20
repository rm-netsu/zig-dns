# High-level resolver composition

`dns.high_level.Resolver` is a bounded protocol state machine that composes the
lower-level resolver primitives without owning sockets, timers, TLS sessions,
QUIC streams, HTTP requests, threads, or an allocator.

The caller owns transport endpoints and decides what a `server_index` means.
The resolver only keeps enough protocol state to correlate responses, apply
retry/EDNS policy, follow aliases and referrals, and return the next action.

## Storage and configuration

The resolver is configured at compile time and initialized in caller-owned
storage:

```zig
const Resolver = dns.high_level.Resolver(.{
    .max_queries = 64,
    .max_alias_depth = 16,
    .alias_storage_bytes = 1024,
});

var storage: Resolver.Storage = undefined;
var resolver = Resolver.initInPlace(&storage);
```

With the v0.6 defaults on 64-bit targets, `Resolver.Storage` is 87,552 bytes,
or 1,368 bytes per maximum concurrent query. The resolver value itself is 48
bytes. These sizes are benchmarked and guarded by a persistent-state budget;
applications with tighter limits can reduce any of the compile-time bounds.

Alias storage contains canonical wire names only. No response packet is
retained after `onResponse*` returns, except that a `.referral` action contains
a borrowed `Referral` view and therefore must be consumed before the caller
reuses that response buffer.

## Begin and dispatch

Start with either a presentation name or an arbitrary-octet wire name:

```zig
const action = try resolver.beginPresentation(.{
    .name = "www.example.com",
    .qtype = .A,
}, .{
    .server_count = upstreams.len,
    .transport = .udp,
    .query = .{
        .udp_payload_size = 1232,
        .dnssec_ok = true,
    },
});
```

`Action` is a tagged union. Transport actions are:

```text
send
retry
connect_tcp
connect_dot
open_doq_stream
perform_doh
```

Each carries a `Dispatch` with a generation-checked query handle, DNS message
ID, caller-owned server index, transport, EDNS state, and dispatch reason.
`DoQ` and `DoH` use DNS ID zero and therefore require the caller-provided
handle for response correlation. UDP/TCP/DoT can additionally use
`matchResponse` / `onMatchedResponse` for DNS-ID correlation.

Build the current DNS query into caller buffers:

```zig
var packet: [1232]u8 = undefined;
var compression: [32]dns.CompressionEntry = undefined;
const wire = try resolver.writeQuery(
    dispatch.handle,
    &packet,
    &compression,
    edns_options,
);
```

The resolver does not transmit `wire` or retain either output buffer.

## Feeding responses

For an ordinary non-validating integration:

```zig
const next = try resolver.onResponse(dispatch.handle, response_wire);
```

When DNSSEC validation is performed externally, inject both validation time
and status:

```zig
const next = try resolver.onValidatedResponse(
    dispatch.handle,
    response_wire,
    now,
    security_status,
);
```

A `.bogus` DNSSEC result is terminal and is never completed or passed to a
cache store hook. `secure`, `insecure`, and `indeterminate` statuses are
composed conservatively across accepted CNAME/DNAME/referral hops.

A recursive response can contain a complete alias chain in one packet. The
state machine consumes applicable CNAME/DNAME records in-place and completes
immediately when the same packet also contains the final answer. A CNAME-only
response without negative SOA evidence produces a new alias dispatch rather
than inventing NODATA for the target.

## Retry and fallback

Timeout and transport failures are explicit inputs:

```zig
const next = try resolver.onTimeout(handle);
// or
const next = try resolver.onTransportFailure(handle);
```

The returned action applies the lower-level retry policy:

- bounded UDP retransmission;
- UDP truncation -> TCP;
- alternate caller-owned server selection;
- optional EDNS downgrade after an appropriate FORMERR response;
- terminal failure when the configured choices are exhausted.

The library owns no timeout duration or scheduling policy.

## Referrals

An iterative response may produce `.referral`:

```zig
switch (action) {
    .referral => |r| {
        var servers = try r.view.nameServers();
        // Consume NS/DS/glue while `response_wire` is still alive.
        _ = servers;

        const next = try resolver.followReferral(
            r.handle,
            selected_server_count,
            .udp,
        );
        _ = next;
    },
    else => {},
}
```

Address selection, bailiwick policy, NS ordering, and server-to-address mapping
remain caller-owned. A stub-style integration can instead call
`acceptReferral` and treat the referral as a terminal semantic result.

## Cache hooks

The high-level state machine intentionally does not prescribe a cache payload
format. Optional hooks can compose it with `dns.cache.Fixed` or an external
cache/database:

```zig
var resolver = Resolver.initInPlaceWithCache(&storage, .{
    .context = cache_context,
    .lookup = lookup,
    .store = store,
});
```

`lookup` runs before network dispatch and again after an accepted alias when
the same packet did not finish the chain. A cached target can therefore finish
a CNAME/DNAME lifecycle without another network request. Security status from
an already-accepted alias is combined with the cache hit. Bogus cache entries
are rejected defensively.

The `store` callback receives the current canonical wire question, semantic
completion kind, composed DNSSEC status, borrowed response message, and caller-
injected response time. Cache expiration, eviction, stale serving, prefetch,
and failure caching remain policy outside this state machine.

## Completion, failure, and lifetime

Terminal actions are `.complete` and `.fail`. Completion reports answer,
NODATA, NXDOMAIN, or an explicitly accepted referral plus source/security
metadata. Failures distinguish malformed/protocol/server/transport/retry and
alias/DNSSEC failures.

After the caller is done with a query, release its slot:

```zig
try resolver.release(handle);
```

`release` can also be used to cancel an in-flight or referral-pending query.
Handles include a generation counter, so an old handle cannot address a later
query that reuses the same slot.

See `examples/high_level_resolver.zig` for a compile-checked CNAME lifecycle.

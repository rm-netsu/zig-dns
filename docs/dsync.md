# Generalized DNS notifications and DSYNC

`dns.dsync` implements the RFC 9859 DSYNC resource record and the bounded
name transformations used to discover generalized-notification endpoints.
`dns.notify` extends RFC 1996 NOTIFY with the RFC 9859 CDS and CSYNC events.

The protocol layer does not resolve target addresses, open sockets, validate a
negative response with DNSSEC, schedule CDS/CDNSKEY/CSYNC processing, or decide
whether a sender is authorized. Those responsibilities stay with the caller.

## DSYNC RDATA

DSYNC RDATA is:

```text
RRtype | Scheme | Port | uncompressed Target
 u16      u8      u16       DNS wire name
```

Parse a borrowed record without allocation:

```zig
const record = try dns.dsync.parse(rr);
if (record.notifyEndpoint()) |endpoint| {
    switch (endpoint.kind) {
        .cds => {},
        .csync => {},
    }
    _ = endpoint.port;
    _ = endpoint.target;
}
```

Unknown RR types and future scheme values remain representable. Consumers
ignore the null scheme, port zero, and currently unsupported combinations.
`validateUnique` checks RFC 9859's per-owner `(RRtype, Scheme)` uniqueness for
an RRset that the caller has already grouped.

The typed builder always emits the Target name uncompressed:

```zig
const target = try dns.name.Uncompressed.init(target_wire);
try builder.addDsync(
    .answer,
    "_dsync.example",
    .IN,
    300,
    .CDS,
    .notify,
    5359,
    target,
);
```

A failed write rolls the builder back, including section count and compression
state.

## Endpoint-discovery names

RFC 9859 begins discovery by inserting `_dsync` after the first label of the
delegation owner:

```zig
var lookup_storage: [dns.Name.max_wire_len]u8 = undefined;
const lookup = try dns.dsync.initialLookupName(child, &lookup_storage);
```

For a DNSSEC-validated negative response, feed the enclosing SOA owner to the
next bounded transformation:

```zig
var next_storage: [dns.Name.max_wire_len]u8 = undefined;
const next = try dns.dsync.nextLookupAfterNegative(
    lookup,
    soa_owner,
    &next_storage,
);
```

The helper returns `null` when the RFC 9859 lookup sequence is exhausted. It
rejects an SOA owner unrelated to the current lookup and leaves the output
buffer untouched on failure. The caller remains responsible for classifying
the DNS response and, when required, validating the negative proof before
using the SOA owner as discovery input.

For example, the RFC sequence is represented as:

```text
subsub.sub.child.example
  -> subsub._dsync.sub.child.example
  -> subsub.sub.child._dsync.example
  -> _dsync.example
  -> end
```

## Generalized NOTIFY

The canonical request builder accepts a typed event:

```zig
var request = try dns.notify.requestBuilder(
    &packet,
    &compression,
    id,
    "child.example",
    .IN,
    .cds,
);
```

Supported events are:

```text
.soa_change -> QTYPE=SOA   (RFC 1996)
.cds        -> QTYPE=CDS   (RFC 9859)
.csync      -> QTYPE=CSYNC (RFC 9859)
```

`validateRequest` and `validateSuccessResponse` retain the RFC 1996 envelope
rules. Generalized notifications additionally reject mixed event types and
messages that combine different child zones. `responseBuilder` echoes the
validated Question tuples and `matches` checks DNS ID and every Question
case-insensitively.

RFC 9859 treats a notification as a prompt to perform the existing delegation
maintenance procedure; the NOTIFY itself is not evidence that CDS, CDNSKEY, or
CSYNC data is valid. Source-address/port checks, TSIG policy, Report-Channel
handling, rate limiting, and actual delegation changes therefore stay outside
`dns.notify`.

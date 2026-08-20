# AXFR and IXFR streaming

`dns.transfer` implements the DNS protocol state for zone transfers without owning sockets, TLS, QUIC streams, files, or a zone database. A transfer consumes one complete DNS message at a time and emits semantic events while keeping persistent state bounded independently of zone size.

## AXFR

Create caller-owned state for one transfer:

```zig
var storage: dns.transfer.axfr.Storage = .{};
var transfer = try dns.transfer.axfr.Transfer.init(
    &storage,
    query_id,
    "example.com",
    .IN,
);
```

For each decoded DNS response, open and fully drain a borrowed cursor before reusing the message buffer:

```zig
var cursor = try transfer.openMessage(message);
while (try cursor.next()) |event| {
    switch (event) {
        .begin => |soa| applyOpeningSoa(soa),
        .record => |rr| applyRecord(rr),
        .end => |soa| commitZone(soa),
        .remote_error => |rcode| handleRemoteError(rcode),
    }
}
```

The receiver validates the AXFR envelope, first and closing SOA, zone/class consistency, message ordering, and premature EOF. `Storage` retains only the zone name and opening SOA snapshot; records remain borrowed from the current DNS message.

Call `transfer.finish()` when the transport reaches EOF/FIN. A transfer that has not reached its closing SOA returns `PrematureEof`.

Apply records transactionally in the caller's zone store. The protocol layer deliberately does not own rollback, duplicate-record suppression, persistence, or database policy.

## IXFR

`dns.transfer.ixfr.Transfer` converts RFC 1995's SOA-delimited wire sequence into semantic events:

```text
begin(current SOA)
delete_begin(old SOA)
delete(rr)*
add_begin(new SOA)
add(rr)*
version_end
...
end(current SOA)
```

The same receiver also recognizes:

- `up_to_date` — a single current SOA when the client serial is equal to or newer than the server under RFC 1982 serial arithmetic;
- `axfr_fallback` — a full-zone response to an IXFR query.

Incremental serial transitions, delta origins, the final current SOA, and ambiguous RFC 1982 half-range comparisons are validated before completion is reported.

## Query composition

AXFR:

```zig
var builder = try dns.transfer.axfr.queryBuilder(
    packet,
    compression,
    id,
    "example.com",
    .IN,
);
// Append OPT and/or TSIG here if required.
const wire = try builder.finish();
```

IXFR adds the client's current SOA in Authority using `ixfr.QuerySoa`. Both protocols also expose `queryBuilderWire` variants for arbitrary-octet wire names.

## TCP and DoT

Feed transport bytes incrementally through `dns.tcp.Decoder`. Each returned message must be consumed by the AXFR/IXFR cursor before the decoder storage is reused:

```text
TCP/TLS bytes
    ↓
tcp.Decoder
    ↓
Message
    ↓
transfer.openMessage(...)
    ↓
borrowed transfer events
```

DoT uses the same DNS framing; TLS ownership remains with the application.

## DoQ

RFC 9250 allows multiple DNS response messages for one zone-transfer query on the same bidirectional QUIC stream. Use:

```zig
var decoder = dns.doq.StreamDecoder.init(
    message_storage,
    .multi_response,
);
```

Each response still has DNS Message ID `0`. Feed every returned message to the transfer state machine, call `decoder.finish()` when QUIC reports STREAM FIN, and then call `transfer.finish()` to verify semantic transfer completion.

Use `.query` for the client-to-server query side and `.single_response` for ordinary one-response DNS transactions. The DoQ layer checks framing/cardinality/ID/role only; it does not decide how many zone-transfer messages are semantically required.

## TSIG

Authentication composes outside the transfer state machine:

1. verify the first response with the request MAC using `dns.tsig.auth.verify`;
2. initialize `dns.tsig.auth.Chain` from the validated first-response MAC;
3. verify each continuation message before passing it to AXFR/IXFR;
4. drain the transfer cursor before the authenticated message buffer is reused.

This keeps shared-secret handling and authentication policy separate from zone-transfer protocol state.

## Memory and lifetimes

The transfer receivers allocate nothing. Persistent state consists of fixed name/SOA snapshots plus scalar state. It does not grow with:

- zone record count;
- number of DNS messages;
- IXFR delta count.

`Event` records borrow the current DNS packet. Do not retain their slices after the packet/decoder storage is reused; copy only data that the caller's zone store needs to retain.

# DNS UPDATE and NOTIFY

`dns.update` and `dns.notify` provide protocol composition and validation while keeping zone storage, authorization, retries, transports, and daemon policy outside the library.

## RFC 2136 UPDATE composition

`dns.update.Composer` owns no allocation. It wraps the normal `dns.Builder`, so Additional records, EDNS, and TSIG remain directly available.

```zig
var packet: [1232]u8 = undefined;
var compression: [48]dns.CompressionEntry = undefined;
var update = try dns.update.Composer.init(
    &packet,
    &compression,
    0x1234,
    "example.com",
    .IN,
);

try update.requireNameExists("host.example.com");
try update.requireRrsetNotExists("host.example.com", .AAAA);
try update.addA("host.example.com", 300, .{ 192, 0, 2, 42 });
try update.deleteRrset("host.example.com", .TXT);
```

The API expresses RFC 2136 semantics instead of exposing its overloaded CLASS values to the caller:

- `requireNameExists` / `requireNameNotExists`;
- `requireRrsetExists` / `requireRrsetNotExists`;
- `requireRecordExists` and typed A/AAAA/name/MX variants;
- `add` plus typed add helpers;
- `deleteName`;
- `deleteRrset`;
- `deleteRecord` plus typed delete helpers.

Local operation errors are checked before record mutation. Owner names outside the Zone section return `NotZone` before changing Builder position, compression state, or section counts.

Unknown ordinary RR types remain available through the generic `add`, `deleteRecord`, and prerequisite APIs with opaque RDATA. The data-type check follows the IANA RR TYPE allocation ranges rather than only known enum cases: the `128..255` QTYPE/Meta-TYPE space, reserved `61440..65279`, value `65535`, and `OPT` are rejected as zone data, while Private Use `65280..65534` remains available as opaque RDATA. This keeps future/unknown ordinary RRTYPEs usable without accidentally accepting meta-types such as `NXNAME`, `TKEY`, `TSIG`, `IXFR`, `AXFR`, or `ANY`.

## UPDATE validation

```zig
const message = try dns.Message.init(packet);
const request = try dns.update.validateRequest(message);

var prerequisites = request.prerequisites();
while (try prerequisites.next()) |rr| {
    // Evaluate against the caller-owned zone store.
    _ = rr;
}

var changes = request.updates();
while (try changes.next()) |rr| {
    // Apply only after all prerequisites and authorization succeed.
    _ = rr;
}
```

`validateRequest` is a protocol prescan, not a zone database. It checks the UPDATE opcode, exactly one SOA Zone question, valid zone class, prerequisite/update metavalues, zone containment, complete section bounds, and Additional framing. It intentionally does not evaluate prerequisite truth, authorization, or transaction rollback in the caller's storage engine.

`dns.validate.messageStrict` is UPDATE-aware: empty ANY/NONE meta-record RDATA is not misparsed as ordinary A/AAAA/TXT data, while real value-dependent RDATA continues to receive normal typed structural checks.

## Signed UPDATE

The normal TSIG API composes directly with the public Builder inside the Composer:

```zig
var key_name: [dns.Name.max_wire_len]u8 = undefined;
const key = try dns.tsig.auth.Key.init("update-key.example", secret, &key_name);

var mac = try dns.tsig.auth.signBuilder(&update.builder, key, .{
    .time_signed = now,
});
defer mac.deinit();

const wire = try update.finish();
```

See `examples/update.zig`. `zig build interop-update` validates both the RFC 2136 semantics and the TSIG of a Zig-generated signed update using dnspython.

## RFC 1996 NOTIFY

The canonical SOA-change request is built with:

```zig
var builder = try dns.notify.requestBuilder(
    &packet,
    &compression,
    id,
    "example.com",
    .IN,
);
```

The returned Builder is intentionally not hidden, so callers can append an optional Answer hint or TSIG. `validateRequest` accepts the RFC 1996 `QDCOUNT > 0` envelope and requires supported SOA notification events; it does not invent transport or master-selection policy.

A successful reply can be produced from the validated request:

```zig
var response = try dns.notify.responseBuilder(
    &response_packet,
    &response_compression,
    request,
);
```

`dns.notify.validateSuccessResponse` validates the canonical `NOERROR` response envelope from RFC 1996 section 4.7. Error responses such as `NOTIMP` remain ordinary `dns.Message` values so callers can classify their RCODE without mistaking them for successful acknowledgements.

`dns.notify.matches` compares DNS ID and all question tuples case-insensitively. UDP source address and source port matching remain the transport caller's responsibility.

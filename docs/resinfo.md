# Resolver Information (RESINFO)

`dns.resinfo` implements the RFC 9606 RESINFO resource record (TYPE 261)
without owning resolver selection, transport security, or recursive lookup.
Parsed attributes borrow the DNS packet and typed construction writes directly
through the normal transactional `dns.Builder`.

## Wire model

RESINFO uses DNS TXT constituent-string framing and the DNS-SD key/value syntax
from RFC 6763. `dns.resinfo.Iterator` returns one borrowed `Attribute` at a time:

```zig
var it = try dns.resinfo.iterator(rr);
while (try it.next()) |attribute| {
    switch (attribute.knownKey()) {
        .qnamemin => {},
        .exterr => {},
        .infourl => {},
        .unknown => {},
    }
}
```

`Attribute.value == null` represents a boolean attribute with no `=`. An empty
non-null value represents `key=`. Key comparison is ASCII case-insensitive, and
`find()` returns the first matching key as required by the DNS-SD duplicate-key
handling model.

Unknown keys are preserved rather than rejected. RFC 9606 requires clients to
ignore unknown keys, and the IANA registry can gain new keys independently of a
library release. `Attribute.isLocal()` recognizes the `temp-` namespace without
turning unrecognized future registered names into wire errors.

## Known values

The current IANA registry defines `qnamemin`, `exterr`, and `infourl`.

`extendedErrors()` parses the `exterr` value allocation-free as individual
`u16` EDE codes or inclusive ranges such as `15-17,22`. Malformed/descending
ranges are rejected locally.

`infoUrl()` parses the URI without allocation and requires an HTTPS scheme plus
a host. RFC 9606 says invalid URLs are ignored by clients, so this error remains
an attribute-level result instead of invalidating the surrounding DNS message.

```zig
if (try dns.resinfo.find(rr, "infourl")) |attribute| {
    const uri = dns.resinfo.infoUrl(attribute) catch null;
    _ = uri;
}
```

## Building

`Builder.addResInfo()` accepts a slice of attributes. All keys and current known
value syntaxes are validated before the RR is opened, so a local validation
failure leaves the builder position, compression table, section count, and
phase unchanged.

```zig
try builder.addResInfo(.answer, "resolver.example.net", 7200, &.{
    .{ .key = "qnamemin", .value = null },
    .{ .key = "exterr", .value = "15-17" },
    .{ .key = "infourl", .value = "https://resolver.example.com/guide" },
});
```

Unknown/future attributes can also be emitted as long as their DNS-SD key and
255-byte constituent-string bounds are valid.

## Message and policy boundaries

RFC 9606 requires a client query to clear RD and requires the client to discard
a response whose AA flag is clear. It also requires an understood RESINFO RRset
to contain exactly one record. These are transaction/application checks rather
than RDATA framing rules and are not silently applied to every DNS message by
the core parser.

`validate.messageStrict` checks only the underlying TXT constituent-string
bounds for RESINFO. It deliberately does not promote a malformed known
attribute or an unknown future key into a whole-message protocol failure because
RFC 9606 tells clients to ignore invalid RESINFO records and unknown keys.

Authentication, resolver reputation, use of an encrypted channel, local DNSSEC
validation, and the decision to select one resolver over another remain caller
policy.

# EDNS operational extensions

The EDNS layer stays transport-neutral. It parses and serializes OPT metadata and
option payloads, but it does not own sockets, encrypted transports, timers,
server identity, secret rotation, recursive error-reporting policy, or message
retry loops.

All parsed option payloads borrow the original DNS packet. Builders write into
caller-owned option buffers and preserve the library-wide transactional rule:
local validation or `NoSpace` failures leave the builder position unchanged.
Unknown option codes continue to be available as raw `edns.Option` values.

## Typed options

The current operational surface includes:

| Option | API | Important semantics |
| --- | --- | --- |
| NSID | `parseNsid`, `addNsidRequest`, `addNsidResponse` | request builder is empty; response payload is opaque binary |
| DAU/DHU/N3U | `parseDau` / `parseDhu` / `parseN3u`, `addDau` / `addDhu` / `addN3u` | borrowed RFC 6975 algorithm lists; one instance of each code per query |
| Key Tag | `parseKeyTag`, `addKeyTags` | one-or-more 16-bit tags per option; multiple query option instances are preserved |
| Update Lease | `parseUpdateLease`, `addUpdateLease` | 4-byte and KEY-specific 8-byte forms |
| ECS | `clientSubnet`, `addClientSubnet` | family/prefix validation and canonical host-bit clearing |
| EXPIRE | `parseExpire`, `addExpireRequest`, `addExpireResponse` | empty request, 32-bit remaining-lifetime response |
| COOKIE | `parseCookie`, `validateCookieResponse`, `edns.cookie` | RFC 7873 framing plus RFC 9018 version-1 generation/verification and secret rollover |
| TCP Keepalive | `parseKeepalive`, `addKeepaliveRequest`, `addKeepaliveResponse` | request/response payload direction and 100 ms timeout units |
| Padding | `parsePadding`, `paddingOption`, `addPadding`, `addBlockPadding` | duplicate rejection; received bytes may be non-zero |
| EDE | `extendedError`, `extendedErrors`, `addExtendedErrorCode` | typed registry codes, unknown-code preservation, UTF-8 diagnostics |
| Report-Channel | `parseReportChannel`, `reportChannel`, `addReportChannel` | response-only, one option, non-root uncompressed agent domain |
| ZONEVERSION | `parseZoneVersion`, `addZoneVersionRequest`, `addZoneVersionSoaSerial` | QUERY-only and label-count validation against the QNAME |
| Multiple-QTYPE | `multipleQtypeQuery`, `multipleQtypeResponse`, typed builders | one-question semantics, duplicate/meta-type rejection, caller-owned duplicate scratch |

`validate.messageStrict` performs the message-context checks that cannot be
expressed by an isolated option payload parser, including opcode/direction,
option multiplicity, ZONEVERSION/QNAME consistency, and Multiple-QTYPE primary
QTYPE validation.

## DNSSEC capability signaling

RFC 6975 DAU/DHU/N3U values are exposed as borrowed octet lists. The parser
preserves unknown and registry-reserved values instead of freezing the current
IANA registries into wire parsing: RFC 6975 permits receivers to ignore such
values, and the registry can evolve independently of this library release.
Strict query validation enforces the RFC rule that each of DAU, DHU, and N3U
appears at most once. Values appearing in a response are ignored as required by
the receiver behavior in RFC 6975.

RFC 8145 Key Tag signaling uses a borrowed network-order list with an iterator
over `u16` tags. `addKeyTags()` requires at least one tag and writes
transactionally. Unlike DAU/DHU/N3U, multiple Key Tag option instances are
valid and intentionally preserved because a recursive resolver may forward its
own and a downstream client's lists separately. Query-side strict validation
requires Key Tag signaling to accompany DNSKEY questions. Response-side values,
including malformed payloads, are ignored rather than promoted to a protocol
failure because RFC 8145 requires clients to ignore this option in responses.

Neither helper decides whether signaling should be enabled. Validator role,
trust-anchor privacy policy, and which currently assigned algorithms to signal
remain caller policy.

## DNS Cookies

`edns.cookie` separates three responsibilities:

- RFC 7873 option framing and client-side echoed-cookie checks;
- RFC 9018 version-1 server-cookie generation/verification;
- caller-owned secret rollover.

The core never reads a wall clock and never owns secret storage. Pass the
current unsigned timestamp explicitly and keep secret lifetime/synchronization
in the application.

```zig
const roll: dns.edns.cookie.SecretRoll = .{
    .generation = &current_secret,
    .alternate_verify = &previous_secret,
};

const server_cookie = roll.make(client_cookie, client_address, now);
const verified = try roll.verify(cookie, client_address, now, .{});
_ = server_cookie;
_ = verified;
```

The version-1 verifier authenticates the received reserved bytes rather than
requiring them to be zero, and uses serial-number-style timestamp arithmetic so
wraparound does not become ordinary unsigned-age overflow.

## Padding

RFC 7830 requires receivers to accept arbitrary padding octets even though zero
is the normal sender choice. `parsePadding` therefore does not reject non-zero
bytes, while `validate.messageStrict` rejects more than one Padding option.

For encrypted DNS, `edns.padding.blockLength` and
`OptionBuilder.addBlockPadding` implement the RFC 8467 block-length calculation
without deciding what the caller considers the privacy-visible message length.
The caller may pass DNS-message length alone or include transport framing when
that is the deployment policy.

```zig
const added = try options.addBlockPadding(
    unpadded_message_len,
    dns.edns.padding.recommended_query_block_length,
    negotiated_payload_limit,
);

if (!added) {
    // The nearest block did not fit. No builder state was changed.
}
```

The library does not automatically enable Padding. RFC 7830's transport-security
requirements and amplification tradeoffs belong to the caller because the core
does not know whether the surrounding transport is encrypted.

## Report-Channel

RFC 9567 Report-Channel is represented as a borrowed, complete, uncompressed
wire name. The typed builder rejects the root agent domain, and strict message
validation rejects Report-Channel in queries or more than one instance in a
response.

`dns.edns.reportChannel(opt)` is a convenient response-side lookup that also
rejects duplicates when strict whole-message validation was not run first.

The library deliberately does not issue error-report queries itself. Recursion
limits, query minimization, transport choice, DNS Cookie use, and reporting
policy remain caller-owned so an error-reporting loop cannot be hidden inside
the protocol engine.

## NSID receiver behavior

A compliant RFC 5001 resolver sends an empty NSID request, so
`addNsidRequest()` always writes zero payload bytes. However, RFC 5001 also
requires a receiving name server to ignore payload bytes if a peer sends them
in a request. Strict validation follows the receiver rule instead of rejecting
the whole DNS message.

Response NSID data is preserved as opaque binary. The library does not assume
text, NUL termination, IP-address syntax, or any operator-specific encoding.

## Multiple-QTYPE

Multiple-QTYPE parsing is allocation-free. Duplicate checking uses explicit
caller-owned scratch rather than a heap set:

```zig
var scratch: dns.edns.MultipleQtypeScratch = .{};
const requested = try dns.edns.multipleQtypeQuery(opt, primary_qtype, &scratch);
_ = requested;
```

The same design keeps future ordinary RRTYPE values representable while
rejecting meta/query-only types where RFC 10029 forbids them.

## Unknown and future options

`OptionCode` is non-exhaustive and the iterator always exposes unknown payloads
as raw borrowed bytes. Adding a typed helper for one option does not make
unrecognized options invalid. Strict validation only applies semantics that are
known to the library and otherwise preserves forward compatibility.

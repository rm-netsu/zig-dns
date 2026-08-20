# Authoritative response composition

`dns.authoritative` composes ordinary authoritative DNS QUERY responses without owning sockets, timers, threads, storage engines, or signing keys.

## Store contract

`dns.authoritative.Composer(Store)` is generic over a structural zone-store contract. A store provides its apex, exact RRset lookup, name existence, nearest delegation, nearest DNAME, and RFC 4592 wildcard selection. Records are borrowed `ZoneRecord` views whose owner and embedded RDATA names are uncompressed wire names.

For small/static zones, `SliceStore` implements the contract over caller-owned `[]const ZoneRecord` with no allocation. It intentionally uses linear scans; large zones should provide an indexed implementation with the same methods.

```zig
var store = dns.authoritative.SliceStore.init(apex, records);
var composer = dns.authoritative.Composer(dns.authoritative.SliceStore).init(&store);
const result = try composer.compose(query, response_buffer, compression, .{});
```

The core can answer exact RRsets, CNAME, DNAME (including synthesized CNAME), wildcard expansion, referrals with in-zone A/AAAA glue, DS-at-delegation queries, NODATA, and NXDOMAIN.

## Bounded response sizing

For UDP without EDNS the composer observes the 512-byte DNS limit. EDNS request payload values below 512 are treated as 512, while `Options.max_udp_payload` applies the server's local ceiling. Stream mode uses the caller's output slice up to the DNS wire limit.

Required RRsets are transactional: if a complete RRset does not fit, it is rolled back and `TC=1` is emitted. Optional Additional glue can be dropped without setting `TC`. A response to an EDNS query reserves space for its OPT pseudo-RR before adding ordinary records, so truncation cannot accidentally consume the OPT budget.

EDNS version other than zero produces BADVERS using the extended RCODE field. The response OPT advertises the server payload limit and preserves the request DO bit.

## DNSSEC

Signing remains external. Set `Options.signed_zone = true` only for a signed zone. When the request has `DO=1`, the composer requires store-provided RRSIG records covering every emitted authoritative RRset. Negative/wildcard/insecure-delegation proofs use an optional structural hook:

```zig
fn dnssecProof(
    store: *Store,
    kind: dns.authoritative.ProofKind,
    qname: dns.name.Uncompressed,
    qtype: dns.Type,
) Store.Error!?Store.RecordIterator
```

The proof iterator yields NSEC/NSEC3 and corresponding RRSIG records. Missing signatures or required proof fail closed with `MissingRrsig` / `MissingDnssecProof`; the library does not silently emit a DNSSEC-incomplete answer for a zone the caller declared signed. Without DO, the same signed store emits the ordinary minimal response.

## Scope and composition

AXFR/IXFR remain in `dns.transfer`. TSIG authentication remains in `dns.tsig`; authenticate the query before authoritative composition. The current `v0.7.0` development snapshot does not yet provide a high-level in-place signer for an already-finished authoritative response or automatic UDP tail reservation for the TSIG RR, so callers needing TSIG must currently compose those low-level pieces explicitly. Transport ownership stays with the caller.

`ANY` behavior is explicit. The default refuses ANY to avoid accidental amplification; callers can select one existing RR type through `AnyPolicy.rr_type` as a minimal policy.

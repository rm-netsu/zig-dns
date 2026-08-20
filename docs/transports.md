# DNS transports

`dns` stops at the DNS-message boundary. It does not open sockets, perform TLS, manage QUIC, or issue HTTP requests.

## UDP

Build a query with `resolver.buildQuery`, send the returned bytes as one datagram, and validate the corresponding response with `client.validateResponse` or `resolver.FixedTransactions.match`.

`udp.needsStreamRetry(message)` reports the TC bit. Transport selection and retry timing remain application policy.

EDNS UDP payload size is explicit. `resolver.QueryOptions.udp_payload_size = null` means that no OPT record is generated; applications should choose a payload policy appropriate for their network environment.

## TCP

`tcp.frame` prepends the two-octet length. `tcp.Decoder` incrementally consumes arbitrary stream fragmentation and returns the number of input bytes used, which allows the caller to process multiple coalesced messages.

Call `decoder.finish()` when the transport reaches EOF. It returns `UnexpectedEof` if a length prefix or message body is incomplete.

A TCP resolver may pipeline multiple queries. `resolver.FixedTransactions` matches responses by ID and original question, so responses do not need to arrive in request order.

## DNS over TLS

`dot` publishes port/ALPN constants and reuses the exact TCP message framing. Feed plaintext obtained from your TLS implementation into `tcp.Decoder` and frame outgoing DNS messages with `tcp.frame`.

## DNS over QUIC

Each DoQ query/response transaction uses a single bidirectional QUIC stream. `doq.StreamDecoder` wraps the common two-octet framing while additionally enforcing:

- DNS Message ID equal to zero;
- query/response role;
- complete stream EOF.

Choose the stream cardinality explicitly:

- `.query` — exactly one client query;
- `.single_response` — exactly one ordinary response;
- `.multi_response` — one or more response messages, as required by AXFR/IXFR.

For `.multi_response`, STREAM FIN ends the framing layer; the AXFR/IXFR state machine independently verifies that the logical transfer reached its closing SOA.

QUIC connection and stream creation remain outside the package.

## DNS over HTTPS

`doh.media_type` is `application/dns-message`.

For POST, use the raw DNS wire message as the body. For GET, `doh.encodeGetParam` and `decodeGetParam` implement unpadded base64url for the `dns` query parameter.

HTTP status handling, redirects, caching, TLS, and HTTP/2 or HTTP/3 connection management belong to the HTTP/runtime layer. `zig-http` can be composed above this package without making it a dependency of `dns`.

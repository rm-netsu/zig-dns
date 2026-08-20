/// Optional composition helpers that coordinate multiple protocol primitives
/// without taking ownership of sockets, timers, TLS, QUIC, HTTP, or threads.
pub const resolver = @import("high_level/resolver.zig");
pub const Resolver = resolver.Resolver;
pub const ResolverConfig = resolver.Config;

const resolver_test = @import("high_level/resolver_test.zig");

test {
    _ = resolver;
    _ = resolver_test;
}

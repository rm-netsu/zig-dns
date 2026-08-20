/// Optional composition helpers that coordinate multiple protocol primitives
/// without taking ownership of sockets, timers, TLS, QUIC, HTTP, or threads.
pub const resolver = @import("high_level/resolver.zig");
pub const Resolver = resolver.Resolver;
pub const ResolverConfig = resolver.Config;
pub const Handle = resolver.Handle;
pub const Transport = resolver.Transport;
pub const BeginOptions = resolver.BeginOptions;
pub const DispatchReason = resolver.DispatchReason;
pub const Dispatch = resolver.Dispatch;
pub const CompletionKind = resolver.CompletionKind;
pub const CompletionSource = resolver.CompletionSource;
pub const Completion = resolver.Completion;
pub const SecurityStatus = resolver.SecurityStatus;
pub const CacheHit = resolver.CacheHit;
pub const CacheHooks = resolver.CacheHooks;
pub const ReferralAction = resolver.ReferralAction;
pub const FailureReason = resolver.FailureReason;
pub const Failure = resolver.Failure;
pub const Action = resolver.Action;
pub const Error = resolver.Error;

const resolver_test = @import("high_level/resolver_test.zig");
const property_test = @import("high_level/property.zig");

test {
    _ = resolver;
    _ = resolver_test;
    _ = property_test;
}

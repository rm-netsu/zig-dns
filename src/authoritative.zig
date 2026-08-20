const api = @import("authoritative/types.zig");
const composer = @import("authoritative/composer.zig");
const store = @import("authoritative/store.zig");

pub const ZoneRecord = api.ZoneRecord;
pub const Transport = api.Transport;
pub const AnyPolicy = api.AnyPolicy;
pub const Options = api.Options;
pub const ProofKind = api.ProofKind;
pub const Kind = api.Kind;
pub const Result = api.Result;
pub const CoreError = api.CoreError;
pub const Composer = composer.Composer;
pub const SliceStore = store.SliceStore;

test {
    _ = composer;
    _ = store;
    _ = @import("authoritative/composer_test.zig");
}

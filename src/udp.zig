const message = @import("message.zig");

pub const legacy_payload_size: u16 = 512;
pub const max_message_size: usize = 65535;

pub fn needsStreamRetry(m: message.Message) bool {
    return m.header.flags.truncated;
}

pub const record = @import("tsig/record.zig");
pub const auth = @import("tsig/auth.zig");

pub const max_time_signed = record.max_time_signed;
pub const recommended_fudge = record.recommended_fudge;
pub const ErrorCode = record.ErrorCode;
pub const Error = record.Error;
pub const Record = record.Record;
pub const Fields = record.Fields;
pub const parse = record.parse;
pub const validateSemantics = record.validateSemantics;
pub const append = record.append;
pub const appendWire = record.appendWire;

test {
    _ = record;
    _ = auth;
}

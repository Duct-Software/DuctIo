//! A checked Rust implementation of DuctIo's fixed-offset wire contract.

use crate::{ffi, Error, Result};
use std::{
    ffi::CString,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr::{self, NonNull},
    sync::Arc,
};

/// Parse one frame without moving payload bytes out of the native input span.
pub enum ParseResult {
    Frame {
        consumed: usize,
        payload_len: usize,
        flags: u8,
        stream_id: u32,
    },
    Need(usize),
    Invalid {
        discard: usize,
    },
}

/// Thread-safe frame codec. A complete payload starts exactly at
/// `header_size()` in each input span; on datagram legs that size includes the
/// native four-byte record prefix. `parse` must report a payload length equal
/// to `consumed - header_size()`. `pack` must produce at most payload length
/// plus `header_size()` bytes. C copies packed bytes during the callback.
pub trait CustomWire: Send + Sync + 'static {
    fn header_size(&self) -> usize;
    fn max_frame(&self) -> usize;
    fn carries_frame_flags(&self) -> bool {
        false
    }
    fn carries_stream_ids(&self) -> bool {
        false
    }
    fn parse(&self, input: &[u8]) -> ParseResult;
    fn pack(&self, payload: &[u8], flags: u8, stream_id: u32) -> Result<Vec<u8>>;
}

#[repr(C)]
struct RustWire {
    base: ffi::duct_wire_t,
    _name: CString,
    codec: Arc<dyn CustomWire>,
}

unsafe extern "C" fn destroy(self_: *mut ffi::duct_wire_t) {
    drop(Box::from_raw(self_ as *mut RustWire));
}
unsafe extern "C" fn create_parser(_self: *const ffi::duct_wire_t) -> *mut ffi::duct_wire_parser_t {
    Box::into_raw(Box::new(0_u8)).cast()
}
unsafe extern "C" fn destroy_parser(
    _self: *const ffi::duct_wire_t,
    parser: *mut ffi::duct_wire_parser_t,
) {
    if !parser.is_null() {
        drop(Box::from_raw(parser.cast::<u8>()));
    }
}
unsafe extern "C" fn parse(
    self_: *const ffi::duct_wire_t,
    input: ffi::duct_view_u8,
    out: *mut ffi::duct_frame_t,
    _parser: *mut ffi::duct_wire_parser_t,
    consumed: *mut usize,
    needed: *mut usize,
) -> i32 {
    let wire = &*(self_ as *const RustWire);
    if out.is_null()
        || consumed.is_null()
        || needed.is_null()
        || (input.size > 0 && input.data.is_null())
    {
        return ffi::duct_result_rc_invalid_arg;
    }
    let bytes = if input.size == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(input.data.cast::<u8>(), input.size)
    };
    match catch_unwind(AssertUnwindSafe(|| wire.codec.parse(bytes))) {
        Ok(ParseResult::Frame {
            consumed: n,
            payload_len,
            flags,
            stream_id,
        }) => {
            let offset = wire.base.header_size;
            if n == 0
                || n > bytes.len()
                || offset > n
                || payload_len != n - offset
                || payload_len > wire.base.max_frame
            {
                return ffi::duct_result_rc_invalid_arg;
            }
            *consumed = n;
            *needed = 0;
            (*out).stream_id = stream_id;
            (*out).flags = flags;
            (*out).payload.data = (input.data as *mut u8).add(offset).cast();
            (*out).payload.size = payload_len;
            ffi::duct_result_rc_ok
        }
        Ok(ParseResult::Need(n)) if n > bytes.len() => {
            *consumed = 0;
            *needed = n;
            ffi::duct_result_rc_again
        }
        Ok(ParseResult::Invalid { discard }) if discard <= bytes.len() => {
            *consumed = discard;
            ffi::duct_result_rc_invalid_arg
        }
        _ => ffi::duct_result_rc_invalid_arg,
    }
}
unsafe extern "C" fn pack(
    self_: *const ffi::duct_wire_t,
    _session: *mut ffi::duct_session_t,
    frame: *const ffi::duct_frame_t,
    stage: *mut ffi::duct_wire_tx_t,
    _codec: *mut ffi::duct_wire_codec_t,
) -> i32 {
    let wire = &*(self_ as *const RustWire);
    if frame.is_null() || stage.is_null() {
        return ffi::duct_result_rc_invalid_arg;
    }
    let frame = &*frame;
    if frame.payload.size > wire.base.max_frame
        || (frame.payload.size > 0 && frame.payload.data.is_null())
    {
        return ffi::duct_result_rc_invalid_arg;
    }
    let bytes = if frame.payload.size == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(frame.payload.data.cast::<u8>(), frame.payload.size)
    };
    match catch_unwind(AssertUnwindSafe(|| {
        wire.codec.pack(bytes, frame.flags, frame.stream_id)
    })) {
        Ok(Ok(packed))
            if !packed.is_empty()
                && packed.len() <= bytes.len().saturating_add(wire.base.header_size) =>
        {
            let data = ffi::duct_view_u8 {
                data: packed.as_ptr().cast_mut().cast(),
                size: packed.len(),
            };
            let empty = ffi::duct_view_u8 {
                data: ptr::null_mut(),
                size: 0,
            };
            ffi::duct_wire_tx_stage(stage, data, empty)
        }
        _ => ffi::duct_result_rc_invalid_arg,
    }
}

pub(crate) fn build(name: &str, codec: Arc<dyn CustomWire>) -> Result<NonNull<ffi::duct_wire_t>> {
    let name = CString::new(name).map_err(|_| Error::InvalidInput)?;
    let header_size = codec.header_size();
    let max_frame = codec.max_frame();
    if header_size > 64 || max_frame == 0 || max_frame > 16 * 1024 {
        return Err(Error::InvalidInput);
    }
    let mut base = ffi::duct_wire_t::default();
    base.header_size = header_size;
    base.max_frame = max_frame;
    if codec.carries_frame_flags() {
        base.flags |= ffi::duct_wire_flags_fl_wire_frame_flags;
    }
    if codec.carries_stream_ids() {
        base.flags |= ffi::duct_wire_flags_fl_wire_stream_ids;
    }
    base.on_parse = Some(parse);
    base.on_pack = Some(pack);
    base.create_parser = Some(create_parser);
    base.destroy_parser = Some(destroy_parser);
    base.destroy = Some(destroy);
    let mut wire = Box::new(RustWire {
        base,
        _name: name,
        codec,
    });
    wire.base.name = wire._name.as_ptr();
    NonNull::new(Box::into_raw(wire) as *mut ffi::duct_wire_t).ok_or(Error::CreationFailed)
}

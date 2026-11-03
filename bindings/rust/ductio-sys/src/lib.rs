//! Raw, unsafe bindings generated from DuctIo's public installed headers.
//! The C API's ownership and thread-affinity contracts still apply.
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    clippy::all
)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

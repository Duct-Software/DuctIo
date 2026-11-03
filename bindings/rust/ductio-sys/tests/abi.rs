use ductio_sys as ffi;
use std::mem::{align_of, offset_of, size_of};

#[test]
fn public_header_layout_matches_compiled_c() {
    unsafe {
        assert_eq!(
            size_of::<ffi::duct_engine_cfg_t>(),
            ffi::ductio_rs_sizeof_engine_cfg()
        );
        assert_eq!(
            align_of::<ffi::duct_engine_cfg_t>(),
            ffi::ductio_rs_alignof_engine_cfg()
        );
        assert_eq!(
            size_of::<ffi::duct_proto_cfg_t>(),
            ffi::ductio_rs_sizeof_proto_cfg()
        );
        assert_eq!(
            align_of::<ffi::duct_proto_cfg_t>(),
            ffi::ductio_rs_alignof_proto_cfg()
        );
        assert_eq!(
            size_of::<ffi::duct_response_t>(),
            ffi::ductio_rs_sizeof_response()
        );
        assert_eq!(
            align_of::<ffi::duct_response_t>(),
            ffi::ductio_rs_alignof_response()
        );
        assert_eq!(
            size_of::<ffi::duct_noise_cfg_t>(),
            ffi::ductio_rs_sizeof_noise_cfg()
        );
        assert_eq!(
            size_of::<ffi::duct_sealed_wire_cfg_t>(),
            ffi::ductio_rs_sizeof_sealed_cfg()
        );
        assert_eq!(
            offset_of!(ffi::duct_proto_cfg_t, on_frame),
            ffi::ductio_rs_offset_proto_on_frame()
        );
        assert_eq!(
            offset_of!(ffi::duct_response_t, payload),
            ffi::ductio_rs_offset_response_payload()
        );
        assert_eq!(
            offset_of!(ffi::duct_response_t, control),
            ffi::ductio_rs_offset_response_control()
        );
        assert_eq!(
            size_of::<ffi::duct_result_t>(),
            ffi::ductio_rs_sizeof_result()
        );
        assert_eq!(
            size_of::<ffi::duct_xport_t>(),
            ffi::ductio_rs_sizeof_xport()
        );
        assert_eq!(
            size_of::<ffi::duct_close_reason_t>(),
            ffi::ductio_rs_sizeof_close_reason()
        );
        assert_eq!(
            size_of::<ffi::duct_send_flags_t>(),
            ffi::ductio_rs_sizeof_send_flags()
        );
        assert_eq!(
            size_of::<ffi::duct_seal_role_t>(),
            ffi::ductio_rs_sizeof_seal_role()
        );
        assert_eq!(
            size_of::<ffi::duct_seal_framing_t>(),
            ffi::ductio_rs_sizeof_seal_framing()
        );
        assert_eq!(
            size_of::<ffi::duct_noise_keypair_t>(),
            ffi::ductio_rs_sizeof_keypair()
        );
        assert_eq!(size_of::<ffi::duct_view_u8>(), ffi::ductio_rs_sizeof_view());
        assert_eq!(
            size_of::<ffi::duct_frame_t>(),
            ffi::ductio_rs_sizeof_frame()
        );
        assert_eq!(
            size_of::<ffi::duct_inter_batch_t>(),
            ffi::ductio_rs_sizeof_inter_batch()
        );
        assert_eq!(size_of::<ffi::duct_wire_t>(), ffi::ductio_rs_sizeof_wire());
        assert_eq!(
            offset_of!(ffi::duct_wire_t, header_size),
            ffi::ductio_rs_offset_wire_header_size()
        );
        assert_eq!(
            offset_of!(ffi::duct_wire_t, on_parse),
            ffi::ductio_rs_offset_wire_on_parse()
        );
        assert_eq!(
            offset_of!(ffi::duct_wire_t, create_parser),
            ffi::ductio_rs_offset_wire_create_parser()
        );
        assert_eq!(
            size_of::<ffi::duct_host_cfg_t>(),
            ffi::ductio_rs_sizeof_host_cfg()
        );
        assert_eq!(
            size_of::<ffi::duct_seal_engine_vtbl_t>(),
            ffi::ductio_rs_sizeof_seal_vtbl()
        );
        assert_eq!(
            align_of::<ffi::duct_seal_engine_vtbl_t>(),
            ffi::ductio_rs_alignof_seal_vtbl()
        );
        assert_eq!(0, ffi::ductio_rs_value_rc_ok());
        assert_eq!(8, ffi::ductio_rs_value_rc_invalid_arg());
        assert_eq!(ffi::duct_result_rc_drop, ffi::ductio_rs_value_rc_drop());
        assert_eq!(2, ffi::ductio_rs_value_x_tcp());
        assert_eq!(2, ffi::ductio_rs_value_fl_send_owned());
        assert_eq!(1, ffi::ductio_rs_value_close_target_session());
        assert_eq!(5, ffi::ductio_rs_value_close_internal_error());
        assert_eq!(1, ffi::ductio_rs_value_seal_role_initiator());
        assert_eq!(2, ffi::ductio_rs_value_seal_role_responder());
        assert_eq!(1, ffi::ductio_rs_value_seal_framing_stream());
        assert_eq!(2, ffi::ductio_rs_value_seal_framing_datagram());
    }
}

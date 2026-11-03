#include "duct.h"
#include "duct_noise.h"
#include "duct_seal_engine.h"
#include <stddef.h>
#include <stdlib.h>

/* duct_wire_destroy is header-only; expose one stable symbol for Rust. */
void ductio_rs_wire_destroy(duct_wire_t *wire) {
    if (wire) duct_wire_destroy(wire);
}

/* The public batch has a flexible array. Build it in C so Rust never relies
 * on its trailing-array layout; DuctIo copies payloads before returning. */
duct_result_t ductio_rs_inter_batch(duct_engine_t *engine, duct_handle_t token,
                                    duct_conn_id_t conn_id, const duct_view_u8 *packets,
                                    unsigned count) {
    if (!engine || !packets || count == 0 || count > 256)
        return rc_invalid_arg;
    duct_inter_batch_t *batch = malloc(duct_inter_batch_bytes(count));
    if (!batch) return rc_no_memory;
    batch->n = count;
    for (unsigned i = 0; i < count; ++i) {
        batch->pkts[i] = (duct_inter_pkt_t){
            .payload = packets[i],
            .stream_id = duct_stream_id_default,
            .flags = fl_frame_none,
        };
    }
    duct_result_t result = duct_io_inter_batch(engine, token, conn_id, batch);
    free(batch);
    return result;
}

size_t ductio_rs_sizeof_engine_cfg(void) { return sizeof(duct_engine_cfg_t); }
size_t ductio_rs_alignof_engine_cfg(void) { return alignof(duct_engine_cfg_t); }
size_t ductio_rs_sizeof_proto_cfg(void) { return sizeof(duct_proto_cfg_t); }
size_t ductio_rs_alignof_proto_cfg(void) { return alignof(duct_proto_cfg_t); }
size_t ductio_rs_sizeof_response(void) { return sizeof(duct_response_t); }
size_t ductio_rs_alignof_response(void) { return alignof(duct_response_t); }
size_t ductio_rs_sizeof_noise_cfg(void) { return sizeof(duct_noise_cfg_t); }
size_t ductio_rs_sizeof_sealed_cfg(void) { return sizeof(duct_sealed_wire_cfg_t); }
size_t ductio_rs_offset_proto_on_frame(void) { return offsetof(duct_proto_cfg_t, on_frame); }
size_t ductio_rs_offset_response_payload(void) { return offsetof(duct_response_t, payload); }
size_t ductio_rs_offset_response_control(void) { return offsetof(duct_response_t, control); }
size_t ductio_rs_sizeof_result(void) { return sizeof(duct_result_t); }
size_t ductio_rs_sizeof_xport(void) { return sizeof(duct_xport_t); }
size_t ductio_rs_sizeof_close_reason(void) { return sizeof(duct_close_reason_t); }
size_t ductio_rs_sizeof_send_flags(void) { return sizeof(duct_send_flags_t); }
size_t ductio_rs_sizeof_seal_role(void) { return sizeof(duct_seal_role_t); }
size_t ductio_rs_sizeof_seal_framing(void) { return sizeof(duct_seal_framing_t); }
size_t ductio_rs_sizeof_keypair(void) { return sizeof(duct_noise_keypair_t); }
size_t ductio_rs_sizeof_view(void) { return sizeof(duct_view_u8); }
size_t ductio_rs_sizeof_frame(void) { return sizeof(duct_frame_t); }
size_t ductio_rs_sizeof_inter_batch(void) { return sizeof(duct_inter_batch_t); }
size_t ductio_rs_sizeof_wire(void) { return sizeof(duct_wire_t); }
size_t ductio_rs_offset_wire_header_size(void) { return offsetof(duct_wire_t, header_size); }
size_t ductio_rs_offset_wire_on_parse(void) { return offsetof(duct_wire_t, on_parse); }
size_t ductio_rs_offset_wire_create_parser(void) { return offsetof(duct_wire_t, create_parser); }
size_t ductio_rs_sizeof_host_cfg(void) { return sizeof(duct_host_cfg_t); }
size_t ductio_rs_sizeof_seal_vtbl(void) { return sizeof(duct_seal_engine_vtbl_t); }
size_t ductio_rs_alignof_seal_vtbl(void) { return alignof(duct_seal_engine_vtbl_t); }
int ductio_rs_value_rc_ok(void) { return rc_ok; }
int ductio_rs_value_rc_invalid_arg(void) { return rc_invalid_arg; }
int ductio_rs_value_rc_drop(void) { return rc_drop; }
unsigned ductio_rs_value_x_tcp(void) { return x_tcp; }
unsigned ductio_rs_value_fl_send_owned(void) { return fl_send_owned; }
unsigned ductio_rs_value_close_target_session(void) { return close_target_session; }
unsigned ductio_rs_value_close_internal_error(void) { return close_internal_error; }
unsigned ductio_rs_value_seal_role_initiator(void) { return seal_role_initiator; }
unsigned ductio_rs_value_seal_role_responder(void) { return seal_role_responder; }
unsigned ductio_rs_value_seal_framing_stream(void) { return seal_framing_stream; }
unsigned ductio_rs_value_seal_framing_datagram(void) { return seal_framing_datagram; }

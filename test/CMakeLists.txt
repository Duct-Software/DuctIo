# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Duct Software

add_executable(ductio_echo_test echo_test.c)
target_link_libraries(ductio_echo_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_echo_test PRIVATE c_std_23)
add_test(NAME echo COMMAND ductio_echo_test)

add_executable(ductio_str_test str_test.c)
target_link_libraries(ductio_str_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_str_test PRIVATE c_std_23)
add_test(NAME str COMMAND ductio_str_test)

add_executable(ductio_file_test file_test.c)
target_link_libraries(ductio_file_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_file_test PRIVATE c_std_23)
add_test(NAME file COMMAND ductio_file_test)

add_executable(ductio_conn_churn_test conn_churn_test.c)
target_link_libraries(ductio_conn_churn_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_conn_churn_test PRIVATE c_std_23)
add_test(NAME conn_churn COMMAND ductio_conn_churn_test)

add_executable(ductio_join_test join_test.c)
target_link_libraries(ductio_join_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_join_test PRIVATE c_std_23)
add_test(NAME join COMMAND ductio_join_test)

add_executable(ductio_join_edge_test join_edge_test.c)
target_link_libraries(ductio_join_edge_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_join_edge_test PRIVATE c_std_23)
add_test(NAME join_edge COMMAND ductio_join_edge_test)

add_executable(ductio_conn_pool_stress conn_pool_stress.c)
target_link_libraries(ductio_conn_pool_stress PRIVATE DuctIo::ductio)
target_include_directories(ductio_conn_pool_stress PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_conn_pool_stress PRIVATE c_std_23)
add_test(NAME conn_pool_stress COMMAND ductio_conn_pool_stress)

add_executable(ductio_session_pool_stress session_pool_stress.c)
target_link_libraries(ductio_session_pool_stress PRIVATE DuctIo::ductio)
target_include_directories(ductio_session_pool_stress PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_session_pool_stress PRIVATE c_std_23)
add_test(NAME session_pool_stress COMMAND ductio_session_pool_stress)

add_executable(ductio_join_lead_test join_lead_test.c)
target_link_libraries(ductio_join_lead_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_join_lead_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_join_lead_test PRIVATE c_std_23)
add_test(NAME join_lead COMMAND ductio_join_lead_test)
set_tests_properties(join_lead PROPERTIES TIMEOUT 10)

add_executable(ductio_coro_test coro_test.c)
target_link_libraries(ductio_coro_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_coro_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_coro_test PRIVATE c_std_23)
add_test(NAME coro COMMAND ductio_coro_test)

add_executable(ductio_core_futex_test core_futex_test.c)
target_link_libraries(ductio_core_futex_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_core_futex_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_core_futex_test PRIVATE c_std_23)
add_test(NAME core_futex COMMAND ductio_core_futex_test)
set_tests_properties(core_futex PROPERTIES TIMEOUT 30)

if(APPLE)
    add_executable(ductio_darwin_xport_test darwin_xport_test.c)
    target_link_libraries(ductio_darwin_xport_test PRIVATE DuctIo::ductio)
    target_include_directories(ductio_darwin_xport_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_definitions(ductio_darwin_xport_test PRIVATE ${DUCT_PLATFORM_COMPILE_DEFINITIONS})
    target_compile_features(ductio_darwin_xport_test PRIVATE c_std_23)
    add_test(NAME darwin_xport COMMAND ductio_darwin_xport_test)
endif()

add_executable(ductio_events_contract_test events_contract_test.c)
target_link_libraries(ductio_events_contract_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_events_contract_test PRIVATE c_std_23)
add_test(NAME events_contract COMMAND ductio_events_contract_test)
set_tests_properties(events_contract PROPERTIES TIMEOUT 30)

if(APPLE AND DUCT_EVENTS_MODEL STREQUAL "kqueue")
    add_executable(ductio_kqueue_promote_test kqueue_promote_test.c)
    target_link_libraries(ductio_kqueue_promote_test PRIVATE DuctIo::ductio)
    target_include_directories(ductio_kqueue_promote_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_definitions(ductio_kqueue_promote_test PRIVATE
        DUCT_RUNTIME_STATS=${DUCT_RUNTIME_STATS} ${DUCT_PLATFORM_COMPILE_DEFINITIONS})
    target_compile_features(ductio_kqueue_promote_test PRIVATE c_std_23)
    add_test(NAME kqueue_promote COMMAND ductio_kqueue_promote_test)
    add_executable(ductio_kqueue_listener_register_test kqueue_listener_register_test.c)
    target_link_libraries(ductio_kqueue_listener_register_test PRIVATE DuctIo::ductio)
    target_include_directories(ductio_kqueue_listener_register_test PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_kqueue_listener_register_test PRIVATE c_std_23)
    add_test(NAME kqueue_listener_register COMMAND ductio_kqueue_listener_register_test)
endif()

add_executable(ductio_core_atomic_ptr_test core_atomic_ptr_test.c)
target_link_libraries(ductio_core_atomic_ptr_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_core_atomic_ptr_test PRIVATE c_std_23)
add_test(NAME core_atomic_ptr COMMAND ductio_core_atomic_ptr_test)

add_executable(ductio_alloc_test alloc_test.c)
target_link_libraries(ductio_alloc_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_alloc_test PRIVATE c_std_23)
add_test(NAME alloc COMMAND ductio_alloc_test)
set_tests_properties(alloc PROPERTIES TIMEOUT 60)

add_executable(ductio_view_test view_test.c)
target_link_libraries(ductio_view_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_view_test PRIVATE c_std_23)
add_test(NAME view COMMAND ductio_view_test)

add_test(NAME alloc_misuse
    COMMAND ${CMAKE_COMMAND}
        -DCC=${CMAKE_C_COMPILER}
        -DSRC=${CMAKE_CURRENT_SOURCE_DIR}/alloc_misuse.c
        "-DINCLUDES=$<JOIN:$<TARGET_PROPERTY:ductio,INTERFACE_INCLUDE_DIRECTORIES>,|>"
        -DGNU=$<STREQUAL:${CMAKE_C_COMPILER_ID},GNU>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/CheckAllocMisuse.cmake)
set_tests_properties(alloc_misuse PROPERTIES TIMEOUT 60)

add_executable(ductio_secret_arena_test secret_arena_test.c)
target_link_libraries(ductio_secret_arena_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_secret_arena_test PRIVATE c_std_23)
add_test(NAME secret_arena COMMAND ductio_secret_arena_test)
set_tests_properties(secret_arena PROPERTIES TIMEOUT 60)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME secret_arena_nolock COMMAND ductio_secret_arena_test nolock)
    set_tests_properties(secret_arena_nolock PROPERTIES TIMEOUT 60)
endif()

add_executable(ductio_crypto_test crypto_test.c)
target_link_libraries(ductio_crypto_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_crypto_test PRIVATE c_std_23)
add_test(NAME crypto COMMAND ductio_crypto_test)
set_tests_properties(crypto PROPERTIES TIMEOUT 10)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ductio_crypto_random_failure_test crypto_random_failure_test.c
        "${PROJECT_SOURCE_DIR}/os/linux/duct_crypto.c")
    target_link_libraries(ductio_crypto_random_failure_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_crypto_random_failure_test PRIVATE c_std_23)
    add_test(NAME crypto_random_failure COMMAND ductio_crypto_random_failure_test)
    set_tests_properties(crypto_random_failure PROPERTIES TIMEOUT 10)
endif()

add_executable(ductio_hex_test hex_test.c)
target_link_libraries(ductio_hex_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_hex_test PRIVATE c_std_23)
add_test(NAME hex COMMAND ductio_hex_test)
set_tests_properties(hex PROPERTIES TIMEOUT 10)

add_executable(ductio_log_test log_test.c)
target_link_libraries(ductio_log_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_log_test PRIVATE c_std_23)
add_test(NAME log COMMAND ductio_log_test)
set_tests_properties(log PROPERTIES TIMEOUT 20)

add_executable(ductio_logfile_test logfile_test.c)
target_link_libraries(ductio_logfile_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_logfile_test PRIVATE c_std_23)
add_test(NAME logfile COMMAND ductio_logfile_test)
set_tests_properties(logfile PROPERTIES TIMEOUT 20)

add_executable(ductio_be_test be_test.c)
target_link_libraries(ductio_be_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_be_test PRIVATE c_std_23)
add_test(NAME be COMMAND ductio_be_test)
set_tests_properties(be PROPERTIES TIMEOUT 10)

add_executable(ductio_engine_report_test engine_report_test.c)
target_link_libraries(ductio_engine_report_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_engine_report_test PRIVATE c_std_23)
add_test(NAME engine_report COMMAND ductio_engine_report_test)
set_tests_properties(engine_report PROPERTIES TIMEOUT 20)

add_executable(ductio_proto_helpers_test proto_helpers_test.c)
target_link_libraries(ductio_proto_helpers_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_proto_helpers_test PRIVATE c_std_23)
add_test(NAME proto_helpers COMMAND ductio_proto_helpers_test)
set_tests_properties(proto_helpers PROPERTIES TIMEOUT 10)

if(NOT WIN32)
    add_executable(ductio_thread_signals_test thread_signals_test.c)
    target_link_libraries(ductio_thread_signals_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_thread_signals_test PRIVATE c_std_23)
    add_test(NAME thread_signals COMMAND ductio_thread_signals_test)
    set_tests_properties(thread_signals PROPERTIES TIMEOUT 20)

    add_executable(ductio_stop_signals_test stop_signals_test.c)
    target_link_libraries(ductio_stop_signals_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_stop_signals_test PRIVATE c_std_23)
    add_test(NAME stop_signals COMMAND ductio_stop_signals_test)
    set_tests_properties(stop_signals PROPERTIES TIMEOUT 20)

    add_executable(ductio_accept_hold_test accept_hold_test.c)
    target_link_libraries(ductio_accept_hold_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_accept_hold_test PRIVATE c_std_23)
    add_test(NAME accept_hold COMMAND ductio_accept_hold_test)
    set_tests_properties(accept_hold PROPERTIES TIMEOUT 30)
endif()

add_executable(ductio_engine_stop_test engine_stop_test.c)
target_link_libraries(ductio_engine_stop_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_engine_stop_test PRIVATE c_std_23)
add_test(NAME engine_stop COMMAND ductio_engine_stop_test)
set_tests_properties(engine_stop PROPERTIES TIMEOUT 20)

if(WIN32)
    add_executable(ductio_stop_console_test stop_console_test.c)
    target_link_libraries(ductio_stop_console_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_stop_console_test PRIVATE c_std_23)
    add_test(NAME stop_console COMMAND ductio_stop_console_test)
    set_tests_properties(stop_console PROPERTIES TIMEOUT 40)
endif()

# Drives control.timer through a real engine (test_helpers.h's th_run +
# duct_engine_launch); the internal include dir is only for duct_time.h /
# duct_timer.h's measurement and bound constants (duct_time_now,
# duct_timer_coalesce_us), not for touching duct_timers_t directly.
add_executable(ductio_timer_test timer_test.c)
target_link_libraries(ductio_timer_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_timer_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_timer_test PRIVATE c_std_23)
add_test(NAME timer COMMAND ductio_timer_test)

add_executable(ductio_stream_slot_test stream_slot_test.c)
target_link_libraries(ductio_stream_slot_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_stream_slot_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_stream_slot_test PRIVATE c_std_23)
add_test(NAME stream_slot COMMAND ductio_stream_slot_test)

add_executable(ductio_dgram_tx_partial_commit_test dgram_tx_partial_commit_test.c)
target_link_libraries(ductio_dgram_tx_partial_commit_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_dgram_tx_partial_commit_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_dgram_tx_partial_commit_test PRIVATE c_std_23)
add_test(NAME dgram_tx_partial_commit COMMAND ductio_dgram_tx_partial_commit_test)

add_executable(ductio_stream_handler_test stream_handler_test.c)
target_link_libraries(ductio_stream_handler_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_stream_handler_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_stream_handler_test PRIVATE c_std_23)
add_test(NAME stream_handler COMMAND ductio_stream_handler_test)

add_executable(ductio_send_done_test send_done_test.c)
target_link_libraries(ductio_send_done_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_send_done_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_send_done_test PRIVATE c_std_23)
add_test(NAME send_done COMMAND ductio_send_done_test)

add_executable(ductio_wire_test wire_test.c)
target_link_libraries(ductio_wire_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_wire_test PRIVATE c_std_23)
add_test(NAME wire COMMAND ductio_wire_test)

add_executable(ductio_wire_frame_flags_test wire_frame_flags_test.c tls_engine_null.c)
target_link_libraries(ductio_wire_frame_flags_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_wire_frame_flags_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_wire_frame_flags_test PRIVATE c_std_23)
add_test(NAME wire_frame_flags COMMAND ductio_wire_frame_flags_test)
set_tests_properties(wire_frame_flags PROPERTIES TIMEOUT 30)

add_executable(ductio_mux_wire_test mux_wire_test.c)
target_link_libraries(ductio_mux_wire_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_mux_wire_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_mux_wire_test PRIVATE c_std_23)
add_test(NAME mux_wire COMMAND ductio_mux_wire_test)
set_tests_properties(mux_wire PROPERTIES TIMEOUT 30)

add_executable(ductio_stream_close_target_test stream_close_target_test.c)
target_link_libraries(ductio_stream_close_target_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_stream_close_target_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_stream_close_target_test PRIVATE c_std_23)
add_test(NAME stream_close_target COMMAND ductio_stream_close_target_test)
set_tests_properties(stream_close_target PROPERTIES TIMEOUT 30)

add_executable(ductio_dgram_shared_ctl_test dgram_shared_ctl_test.c)
target_link_libraries(ductio_dgram_shared_ctl_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_dgram_shared_ctl_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_dgram_shared_ctl_test PRIVATE c_std_23)
add_test(NAME dgram_shared_ctl COMMAND ductio_dgram_shared_ctl_test)
set_tests_properties(dgram_shared_ctl PROPERTIES TIMEOUT 60)

add_executable(ductio_dgram_peer_roam_test dgram_peer_roam_test.c tls_engine_null.c)
target_link_libraries(ductio_dgram_peer_roam_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_dgram_peer_roam_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_dgram_peer_roam_test PRIVATE c_std_23)
add_test(NAME dgram_peer_roam COMMAND ductio_dgram_peer_roam_test)
set_tests_properties(dgram_peer_roam PROPERTIES TIMEOUT 60)

add_executable(ductio_tx_gather_partial_test tx_gather_partial_test.c)
target_link_libraries(ductio_tx_gather_partial_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_tx_gather_partial_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_tx_gather_partial_test PRIVATE c_std_23)
add_test(NAME tx_gather_partial COMMAND ductio_tx_gather_partial_test)
set_tests_properties(tx_gather_partial PROPERTIES TIMEOUT 30)

add_executable(ductio_stream_test stream_test.c)
target_link_libraries(ductio_stream_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_stream_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_stream_test PRIVATE c_std_23)
add_test(NAME stream COMMAND ductio_stream_test)

add_executable(ductio_control_test control_test.c)
target_link_libraries(ductio_control_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_control_test PRIVATE c_std_23)
add_test(NAME control COMMAND ductio_control_test)

add_executable(ductio_peer_disconnect_test peer_disconnect_test.c)
target_link_libraries(ductio_peer_disconnect_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_peer_disconnect_test PRIVATE c_std_23)
add_test(NAME peer_disconnect COMMAND ductio_peer_disconnect_test)

add_executable(ductio_defer_stream_test defer_stream_test.c)
target_link_libraries(ductio_defer_stream_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_defer_stream_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_defer_stream_test PRIVATE c_std_23)
add_test(NAME defer_stream COMMAND ductio_defer_stream_test)

add_executable(ductio_session_reclaim_race_test session_reclaim_race_test.c)
target_link_libraries(ductio_session_reclaim_race_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_session_reclaim_race_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_session_reclaim_race_test PRIVATE c_std_23)
add_test(NAME session_reclaim_race COMMAND ductio_session_reclaim_race_test)

add_executable(ductio_tx_full_batch_test tx_full_batch_test.c)
target_link_libraries(ductio_tx_full_batch_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_tx_full_batch_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_tx_full_batch_test PRIVATE c_std_23)
add_test(NAME tx_full_batch COMMAND ductio_tx_full_batch_test)

add_executable(ductio_tx_full_once_test tx_full_once_test.c)
target_link_libraries(ductio_tx_full_once_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_tx_full_once_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_tx_full_once_test PRIVATE c_std_23)
add_test(NAME tx_full_once COMMAND ductio_tx_full_once_test)

add_executable(ductio_olb_tx_room_test olb_tx_room_test.c)
target_link_libraries(ductio_olb_tx_room_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_olb_tx_room_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_olb_tx_room_test PRIVATE c_std_23)
add_test(NAME olb_tx_room COMMAND ductio_olb_tx_room_test)

add_executable(ductio_spin_next_test spin_next_test.c)
target_link_libraries(ductio_spin_next_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_spin_next_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_spin_next_test PRIVATE c_std_23)
add_test(NAME spin_next COMMAND ductio_spin_next_test)
set_tests_properties(spin_next PROPERTIES TIMEOUT 10)

add_executable(ductio_gso_group_test gso_group_test.c)
target_link_libraries(ductio_gso_group_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_gso_group_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
duct_platform_configure(ductio_gso_group_test)
target_compile_features(ductio_gso_group_test PRIVATE c_std_23)
add_test(NAME gso_group COMMAND ductio_gso_group_test)

add_executable(ductio_olb_rx_group_test olb_rx_group_test.c)
target_link_libraries(ductio_olb_rx_group_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_olb_rx_group_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_olb_rx_group_test PRIVATE c_std_23)
add_test(NAME olb_rx_group COMMAND ductio_olb_rx_group_test)

add_executable(ductio_vnet_cut_test vnet_cut_test.c)
target_link_libraries(ductio_vnet_cut_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_vnet_cut_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
duct_platform_configure(ductio_vnet_cut_test)
target_compile_features(ductio_vnet_cut_test PRIVATE c_std_23)
add_test(NAME vnet_cut COMMAND ductio_vnet_cut_test)

add_executable(ductio_vmq_publish_shrink_test vmq_publish_shrink_test.c)
target_link_libraries(ductio_vmq_publish_shrink_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_vmq_publish_shrink_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_vmq_publish_shrink_test PRIVATE c_std_23)
add_test(NAME vmq_publish_shrink COMMAND ductio_vmq_publish_shrink_test)

add_executable(ductio_vmq_held_reserve_test vmq_held_reserve_test.c)
target_link_libraries(ductio_vmq_held_reserve_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_vmq_held_reserve_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_vmq_held_reserve_test PRIVATE c_std_23)
add_test(NAME vmq_held_reserve COMMAND ductio_vmq_held_reserve_test)

add_executable(ductio_vmq_rewind_test vmq_rewind_test.c)
target_link_libraries(ductio_vmq_rewind_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_vmq_rewind_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_vmq_rewind_test PRIVATE c_std_23)
add_test(NAME vmq_rewind COMMAND ductio_vmq_rewind_test)

add_executable(ductio_vmq_ack_waiter_wake_test vmq_ack_waiter_wake_test.c)
target_link_libraries(ductio_vmq_ack_waiter_wake_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_vmq_ack_waiter_wake_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_vmq_ack_waiter_wake_test PRIVATE c_std_23)
add_test(NAME vmq_ack_waiter_wake COMMAND ductio_vmq_ack_waiter_wake_test)

add_executable(ductio_owned_retry_test owned_retry_test.c)
target_link_libraries(ductio_owned_retry_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_owned_retry_test PRIVATE c_std_23)
add_test(NAME owned_retry COMMAND ductio_owned_retry_test)

add_executable(ductio_dgram_test dgram_test.c)
target_link_libraries(ductio_dgram_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_dgram_test PRIVATE c_std_23)
add_test(NAME dgram COMMAND ductio_dgram_test)

add_executable(ductio_dgram_join_test dgram_join_test.c)
target_link_libraries(ductio_dgram_join_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_dgram_join_test PRIVATE c_std_23)
add_test(NAME dgram_join COMMAND ductio_dgram_join_test)

add_executable(ductio_dgram_shared_test dgram_shared_test.c)
target_link_libraries(ductio_dgram_shared_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_dgram_shared_test PRIVATE c_std_23)
add_test(NAME dgram_shared COMMAND ductio_dgram_shared_test)

add_executable(ductio_dgram_edge_test dgram_edge_test.c)
target_link_libraries(ductio_dgram_edge_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_dgram_edge_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_dgram_edge_test PRIVATE c_std_23)
add_test(NAME dgram_edge COMMAND ductio_dgram_edge_test)

add_executable(ductio_dgram_ephemeral_test dgram_ephemeral_test.c)
target_link_libraries(ductio_dgram_ephemeral_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_dgram_ephemeral_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_dgram_ephemeral_test PRIVATE c_std_23)
add_test(NAME dgram_ephemeral COMMAND ductio_dgram_ephemeral_test)

add_executable(ductio_dgram_join_refused_test dgram_join_refused_test.c)
target_link_libraries(ductio_dgram_join_refused_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_dgram_join_refused_test PRIVATE c_std_23)
add_test(NAME dgram_join_refused COMMAND ductio_dgram_join_refused_test)

add_executable(ductio_connect_test connect_test.c)
target_link_libraries(ductio_connect_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_connect_test PRIVATE c_std_23)
add_test(NAME connect COMMAND ductio_connect_test)

add_executable(ductio_udp_connect_test udp_connect_test.c)
target_link_libraries(ductio_udp_connect_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_udp_connect_test PRIVATE c_std_23)
add_test(NAME udp_connect COMMAND ductio_udp_connect_test)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR APPLE)
    add_executable(ductio_egress_if_test egress_if_test.c)
    target_link_libraries(ductio_egress_if_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_egress_if_test PRIVATE c_std_23)
    add_test(NAME egress_if COMMAND ductio_egress_if_test)
    set_tests_properties(egress_if PROPERTIES TIMEOUT 60)
endif()

if(NOT APPLE)
    add_executable(ductio_path_mtu_test path_mtu_test.c)
    target_link_libraries(ductio_path_mtu_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_path_mtu_test PRIVATE c_std_23)
    add_test(NAME path_mtu COMMAND ductio_path_mtu_test)
    set_tests_properties(path_mtu PROPERTIES TIMEOUT 20)

    add_executable(ductio_tcp_tune_test tcp_tune_test.c)
    target_link_libraries(ductio_tcp_tune_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_tcp_tune_test PRIVATE c_std_23)
    add_test(NAME tcp_tune COMMAND ductio_tcp_tune_test)
    set_tests_properties(tcp_tune PROPERTIES TIMEOUT 30)
endif()

add_executable(ductio_rio_multi_listener_test rio_multi_listener_test.c)
target_link_libraries(ductio_rio_multi_listener_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_rio_multi_listener_test PRIVATE c_std_23)
add_test(NAME rio_multi_listener COMMAND ductio_rio_multi_listener_test)

add_executable(ductio_dgram_shared_large_records_test dgram_shared_large_records_test.c)
target_link_libraries(ductio_dgram_shared_large_records_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_dgram_shared_large_records_test PRIVATE c_std_23)
add_test(NAME dgram_shared_large_records COMMAND ductio_dgram_shared_large_records_test)

add_executable(ductio_dgram_slot_ref_test dgram_slot_ref_test.c)
target_link_libraries(ductio_dgram_slot_ref_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_dgram_slot_ref_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_dgram_slot_ref_test PRIVATE c_std_23)
target_compile_definitions(ductio_dgram_slot_ref_test PRIVATE
    DUCT_RUNTIME_STATS=${DUCT_RUNTIME_STATS}
    ${DUCT_PLATFORM_COMPILE_DEFINITIONS})
add_test(NAME dgram_slot_ref COMMAND ductio_dgram_slot_ref_test)
set_tests_properties(dgram_slot_ref PROPERTIES TIMEOUT 60)

add_executable(ductio_x_slot_test x_slot_test.c)
target_link_libraries(ductio_x_slot_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_x_slot_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_x_slot_test PRIVATE c_std_23)
add_test(NAME x_slot COMMAND ductio_x_slot_test)
set_tests_properties(x_slot PROPERTIES TIMEOUT 60)

if(NOT APPLE)
    # Darwin SO_REUSEPORT does not load-balance shared UDP listeners.
    add_executable(ductio_dgram_shared_stall_test dgram_shared_stall_test.c)
    target_link_libraries(ductio_dgram_shared_stall_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_dgram_shared_stall_test PRIVATE c_std_23)
    add_test(NAME dgram_shared_stall COMMAND ductio_dgram_shared_stall_test)
endif()

add_executable(ductio_dgram_peer_batch_test dgram_peer_batch_test.c)
target_link_libraries(ductio_dgram_peer_batch_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_dgram_peer_batch_test PRIVATE c_std_23)
add_test(NAME dgram_peer_batch COMMAND ductio_dgram_peer_batch_test)
set_tests_properties(dgram_peer_batch PROPERTIES TIMEOUT 60)

add_executable(ductio_e2e_reconnect_test e2e_reconnect_test.c)
target_link_libraries(ductio_e2e_reconnect_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_e2e_reconnect_test PRIVATE c_std_23)
add_test(NAME e2e_reconnect COMMAND ductio_e2e_reconnect_test)

add_executable(ductio_inter_conn_test inter_conn_test.c)
target_link_libraries(ductio_inter_conn_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_inter_conn_test PRIVATE c_std_23)
add_test(NAME inter_conn COMMAND ductio_inter_conn_test)

add_executable(ductio_inter_egress_shutdown_test inter_egress_shutdown_test.c)
target_link_libraries(ductio_inter_egress_shutdown_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_inter_egress_shutdown_test PRIVATE c_std_23)
add_test(NAME inter_egress_shutdown COMMAND ductio_inter_egress_shutdown_test)
set_tests_properties(inter_egress_shutdown PROPERTIES TIMEOUT 60)

add_executable(ductio_mux_dgram_test mux_dgram_test.c)
target_link_libraries(ductio_mux_dgram_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_mux_dgram_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_mux_dgram_test PRIVATE c_std_23)
add_test(NAME mux_dgram COMMAND ductio_mux_dgram_test)

add_executable(ductio_listener_reuseport_test listener_reuseport_test.c)
target_link_libraries(ductio_listener_reuseport_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_listener_reuseport_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_listener_reuseport_test PRIVATE c_std_23)
target_compile_definitions(ductio_listener_reuseport_test PRIVATE
    DUCT_RUNTIME_STATS=${DUCT_RUNTIME_STATS}
    ${DUCT_PLATFORM_COMPILE_DEFINITIONS})
add_test(NAME listener_reuseport COMMAND ductio_listener_reuseport_test)

add_executable(ductio_listener_close_test listener_close_test.c)
target_link_libraries(ductio_listener_close_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_listener_close_test PRIVATE c_std_23)
add_test(NAME listener_close COMMAND ductio_listener_close_test)

add_executable(ductio_listener_add_test listener_add_test.c)
target_link_libraries(ductio_listener_add_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_listener_add_test PRIVATE c_std_23)
add_test(NAME listener_add COMMAND ductio_listener_add_test)

add_executable(ductio_local_listener_test local_listener_test.c)
target_link_libraries(ductio_local_listener_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_local_listener_test PRIVATE c_std_23)
target_compile_definitions(ductio_local_listener_test PRIVATE ${DUCT_PLATFORM_COMPILE_DEFINITIONS})
add_test(NAME local_listener COMMAND ductio_local_listener_test)
set_tests_properties(local_listener PROPERTIES TIMEOUT 60)

add_executable(ductio_local_dial_test local_dial_test.c)
target_link_libraries(ductio_local_dial_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_local_dial_test PRIVATE c_std_23)
target_compile_definitions(ductio_local_dial_test PRIVATE ${DUCT_PLATFORM_COMPILE_DEFINITIONS})
add_test(NAME local_dial COMMAND ductio_local_dial_test)
set_tests_properties(local_dial PROPERTIES TIMEOUT 60)

add_executable(ductio_attach_fd_test attach_fd_test.c)
target_link_libraries(ductio_attach_fd_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_attach_fd_test PRIVATE c_std_23)
add_test(NAME attach_fd COMMAND ductio_attach_fd_test)

add_executable(ductio_attach_packet_fd_test attach_packet_fd_test.c)
target_link_libraries(ductio_attach_packet_fd_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_attach_packet_fd_test PRIVATE c_std_23)
add_test(NAME attach_packet_fd COMMAND ductio_attach_packet_fd_test)
set_tests_properties(attach_packet_fd PROPERTIES TIMEOUT 60)

add_executable(ductio_peer_fin_test peer_fin_test.c)
target_link_libraries(ductio_peer_fin_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_peer_fin_test PRIVATE c_std_23)
add_test(NAME peer_fin COMMAND ductio_peer_fin_test)
set_tests_properties(peer_fin PROPERTIES TIMEOUT 60)

add_executable(ductio_attach_wire_test attach_wire_test.c)
target_link_libraries(ductio_attach_wire_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_attach_wire_test PRIVATE c_std_23)
add_test(NAME attach_wire COMMAND ductio_attach_wire_test)
set_tests_properties(attach_wire PROPERTIES TIMEOUT 30)

if(NOT WIN32 OR DUCT_EVENTS_MODEL MATCHES "^(wsaevent|iocp)$")
    add_executable(ductio_device_attach_test device_attach_test.c)
    target_link_libraries(ductio_device_attach_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_device_attach_test PRIVATE c_std_23)
    add_test(NAME device_attach COMMAND ductio_device_attach_test)
    set_tests_properties(device_attach PROPERTIES TIMEOUT 30)

    add_executable(ductio_session_closing_test session_closing_test.c)
    target_link_libraries(ductio_session_closing_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_session_closing_test PRIVATE c_std_23)
    add_test(NAME session_closing COMMAND ductio_session_closing_test)
    set_tests_properties(session_closing PROPERTIES TIMEOUT 30)
endif()

if(DUCT_EVENTS_MODEL STREQUAL "wsaevent")
    add_executable(ductio_wait_set_full_test wait_set_full_test.c)
    target_link_libraries(ductio_wait_set_full_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_wait_set_full_test PRIVATE c_std_23)
    add_test(NAME wait_set_full COMMAND ductio_wait_set_full_test)
    set_tests_properties(wait_set_full PROPERTIES TIMEOUT 60)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR DUCT_EVENTS_MODEL MATCHES "^(wsaevent|iocp)$")
    add_executable(ductio_device_rx_resume_test device_rx_resume_test.c)
    target_link_libraries(ductio_device_rx_resume_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_device_rx_resume_test PRIVATE c_std_23)
    add_test(NAME device_rx_resume COMMAND ductio_device_rx_resume_test)
    set_tests_properties(device_rx_resume PROPERTIES TIMEOUT 60)

    if(NOT WIN32)
        add_executable(ductio_packet_fd_test packet_fd_test.c)
        target_link_libraries(ductio_packet_fd_test PRIVATE DuctIo::ductio)
        target_compile_features(ductio_packet_fd_test PRIVATE c_std_23)
        add_test(NAME packet_fd COMMAND ductio_packet_fd_test)
        set_tests_properties(packet_fd PROPERTIES TIMEOUT 60)

        add_executable(ductio_packet_fd_multi_test packet_fd_multi_test.c)
        target_link_libraries(ductio_packet_fd_multi_test PRIVATE DuctIo::ductio)
        target_compile_features(ductio_packet_fd_multi_test PRIVATE c_std_23)
        add_test(NAME packet_fd_multi COMMAND ductio_packet_fd_multi_test)
        set_tests_properties(packet_fd_multi PROPERTIES TIMEOUT 60)

        add_executable(ductio_packet_switch_test packet_switch_test.c)
        target_link_libraries(ductio_packet_switch_test PRIVATE DuctIo::ductio)
        target_compile_features(ductio_packet_switch_test PRIVATE c_std_23)
        add_test(NAME packet_switch COMMAND ductio_packet_switch_test)
        set_tests_properties(packet_switch PROPERTIES TIMEOUT 60)

        add_executable(ductio_sealed_packet_fd_test
            sealed_packet_fd_test.c tls_engine_null.c)
        target_link_libraries(ductio_sealed_packet_fd_test PRIVATE DuctIo::ductio)
        target_include_directories(ductio_sealed_packet_fd_test PRIVATE
            ${DUCT_INTERNAL_INCLUDE_DIRS})
        target_compile_features(ductio_sealed_packet_fd_test PRIVATE c_std_23)
        add_test(NAME sealed_packet_fd COMMAND ductio_sealed_packet_fd_test)
        set_tests_properties(sealed_packet_fd PROPERTIES TIMEOUT 60)
    endif()

    add_executable(ductio_device_reattach_test device_reattach_test.c)
    target_link_libraries(ductio_device_reattach_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_device_reattach_test PRIVATE c_std_23)
    add_test(NAME device_reattach COMMAND ductio_device_reattach_test)
    set_tests_properties(device_reattach PROPERTIES TIMEOUT 60)

    add_executable(ductio_device_eof_test device_eof_test.c)
    target_link_libraries(ductio_device_eof_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_device_eof_test PRIVATE c_std_23)
    add_test(NAME device_eof COMMAND ductio_device_eof_test)
    set_tests_properties(device_eof PROPERTIES TIMEOUT 60)

    add_executable(ductio_device_readonly_test device_readonly_test.c)
    target_link_libraries(ductio_device_readonly_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_device_readonly_test PRIVATE c_std_23)
    add_test(NAME device_readonly COMMAND ductio_device_readonly_test)
    set_tests_properties(device_readonly PROPERTIES TIMEOUT 60)

    add_executable(ductio_device_rx_slot_test device_rx_slot_test.c)
    target_link_libraries(ductio_device_rx_slot_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_device_rx_slot_test PRIVATE c_std_23)
    add_test(NAME device_rx_slot COMMAND ductio_device_rx_slot_test)
    set_tests_properties(device_rx_slot PROPERTIES TIMEOUT 60)

    add_executable(ductio_device_rx_pool_test device_rx_pool_test.c)
    target_link_libraries(ductio_device_rx_pool_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_device_rx_pool_test PRIVATE c_std_23)
    add_test(NAME device_rx_pool COMMAND ductio_device_rx_pool_test)
    set_tests_properties(device_rx_pool PROPERTIES TIMEOUT 60)

    add_executable(ductio_worker_shutdown_retry_test worker_shutdown_retry_test.c)
    target_link_libraries(ductio_worker_shutdown_retry_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_worker_shutdown_retry_test PRIVATE c_std_23)
    add_test(NAME worker_shutdown_retry COMMAND ductio_worker_shutdown_retry_test)
    set_tests_properties(worker_shutdown_retry PROPERTIES TIMEOUT 60)

    add_executable(ductio_device_rx_hold_test device_rx_hold_test.c)
    target_link_libraries(ductio_device_rx_hold_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_device_rx_hold_test PRIVATE c_std_23)
    add_test(NAME device_rx_hold COMMAND ductio_device_rx_hold_test)
    set_tests_properties(device_rx_hold PROPERTIES TIMEOUT 60)

    add_executable(ductio_device_tx_test device_tx_test.c)
    target_link_libraries(ductio_device_tx_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_device_tx_test PRIVATE c_std_23)
    add_test(NAME device_tx COMMAND ductio_device_tx_test)
    set_tests_properties(device_tx PROPERTIES TIMEOUT 60)
endif()

add_executable(ductio_open_leg_test open_leg_test.c)
target_link_libraries(ductio_open_leg_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_open_leg_test PRIVATE c_std_23)
add_test(NAME open_leg COMMAND ductio_open_leg_test)

add_executable(ductio_open_leg_connect_test open_leg_connect_test.c)
target_link_libraries(ductio_open_leg_connect_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_open_leg_connect_test PRIVATE c_std_23)
add_test(NAME open_leg_connect COMMAND ductio_open_leg_connect_test)

add_executable(ductio_engine_thread_cpu_test engine_thread_cpu_test.c)
target_link_libraries(ductio_engine_thread_cpu_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_engine_thread_cpu_test PRIVATE c_std_23)
add_test(NAME engine_thread_cpu COMMAND ductio_engine_thread_cpu_test)
set_tests_properties(engine_thread_cpu PROPERTIES TIMEOUT 30)

add_executable(ductio_udp_liveness_test udp_liveness_test.c)
target_link_libraries(ductio_udp_liveness_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_udp_liveness_test PRIVATE c_std_23)
add_test(NAME udp_liveness COMMAND ductio_udp_liveness_test)
set_tests_properties(udp_liveness PROPERTIES TIMEOUT 60)

add_executable(ductio_primary_reattach_test primary_reattach_test.c)
target_link_libraries(ductio_primary_reattach_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_primary_reattach_test PRIVATE c_std_23)
add_test(NAME primary_reattach COMMAND ductio_primary_reattach_test)
set_tests_properties(primary_reattach PROPERTIES TIMEOUT 60)

add_executable(ductio_conn_lost_test conn_lost_test.c)
target_link_libraries(ductio_conn_lost_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_conn_lost_test PRIVATE c_std_23)
add_test(NAME conn_lost COMMAND ductio_conn_lost_test)
set_tests_properties(conn_lost PROPERTIES TIMEOUT 60)

add_executable(ductio_host_invoke_test host_invoke_test.c)
target_link_libraries(ductio_host_invoke_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_host_invoke_test PRIVATE c_std_23)
add_test(NAME host_invoke COMMAND ductio_host_invoke_test)

add_executable(ductio_session_dispatch_test session_dispatch_test.c)
target_link_libraries(ductio_session_dispatch_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_session_dispatch_test PRIVATE c_std_23)
add_test(NAME session_dispatch COMMAND ductio_session_dispatch_test)
set_tests_properties(session_dispatch PROPERTIES TIMEOUT 30)

add_executable(ductio_wire_change_test wire_change_test.c tls_engine_null.c)
target_link_libraries(ductio_wire_change_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_wire_change_test PRIVATE c_std_23)
add_test(NAME wire_change COMMAND ductio_wire_change_test)

add_executable(ductio_probe_wait_test probe_wait_test.c)
target_link_libraries(ductio_probe_wait_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_probe_wait_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_probe_wait_test PRIVATE c_std_23)
add_test(NAME probe_wait COMMAND ductio_probe_wait_test)

add_executable(ductio_accept_seed_order_test accept_seed_order_test.c)
target_link_libraries(ductio_accept_seed_order_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_accept_seed_order_test PRIVATE c_std_23)
add_test(NAME accept_seed_order COMMAND ductio_accept_seed_order_test)
set_tests_properties(accept_seed_order PROPERTIES TIMEOUT 30)

add_executable(ductio_close_timeout_test close_timeout_test.c)
target_link_libraries(ductio_close_timeout_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_close_timeout_test PRIVATE c_std_23)
add_test(NAME close_timeout COMMAND ductio_close_timeout_test)
set_tests_properties(close_timeout PROPERTIES TIMEOUT 30)

add_executable(ductio_idle_timeout_test idle_timeout_test.c)
target_link_libraries(ductio_idle_timeout_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_idle_timeout_test PRIVATE c_std_23)
add_test(NAME idle_timeout COMMAND ductio_idle_timeout_test)
set_tests_properties(idle_timeout PROPERTIES TIMEOUT 60)

add_executable(ductio_park_control_test park_control_test.c)
target_link_libraries(ductio_park_control_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_park_control_test PRIVATE c_std_23)
add_test(NAME park_control COMMAND ductio_park_control_test)
set_tests_properties(park_control PROPERTIES TIMEOUT 30)

add_executable(ductio_tcp_cycle_test tcp_cycle_test.c)
target_link_libraries(ductio_tcp_cycle_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_tcp_cycle_test PRIVATE c_std_23)
if(DUCT_WITH_NOISE)
    target_compile_definitions(ductio_tcp_cycle_test PRIVATE TCP_CYCLE_NOISE)
    target_link_libraries(ductio_tcp_cycle_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
add_test(NAME tcp_cycle COMMAND ductio_tcp_cycle_test)
set_tests_properties(tcp_cycle PROPERTIES TIMEOUT 300)

add_executable(ductio_close_order_test close_order_test.c)
target_link_libraries(ductio_close_order_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_close_order_test PRIVATE c_std_23)
add_test(NAME close_order COMMAND ductio_close_order_test)
set_tests_properties(close_order PROPERTIES TIMEOUT 60)

add_executable(ductio_leg_lost_park_test leg_lost_park_test.c)
target_link_libraries(ductio_leg_lost_park_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_leg_lost_park_test PRIVATE c_std_23)
add_test(NAME leg_lost_park COMMAND ductio_leg_lost_park_test)
set_tests_properties(leg_lost_park PROPERTIES TIMEOUT 60)

add_executable(ductio_codel_test codel_test.c)
target_link_libraries(ductio_codel_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_codel_test PRIVATE c_std_23)
add_test(NAME codel COMMAND ductio_codel_test)
set_tests_properties(codel PROPERTIES TIMEOUT 30)

add_executable(ductio_frame_ip_test frame_ip_test.c)
target_link_libraries(ductio_frame_ip_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_frame_ip_test PRIVATE c_std_23)
add_test(NAME frame_ip COMMAND ductio_frame_ip_test)
set_tests_properties(frame_ip PROPERTIES TIMEOUT 30)

add_executable(ductio_conn_counters_test conn_counters_test.c)
target_link_libraries(ductio_conn_counters_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_conn_counters_test PRIVATE c_std_23)
if(NOT WIN32 OR DUCT_EVENTS_MODEL MATCHES "^(wsaevent|iocp)$")
    target_compile_definitions(ductio_conn_counters_test PRIVATE CONN_COUNTERS_DEVICE)
endif()
add_test(NAME conn_counters COMMAND ductio_conn_counters_test)
set_tests_properties(conn_counters PROPERTIES TIMEOUT 60)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ductio_tun_test tun_test.c)
    target_link_libraries(ductio_tun_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_tun_test PRIVATE c_std_23)
    add_test(NAME tun COMMAND ductio_tun_test)
    set_tests_properties(tun PROPERTIES TIMEOUT 60)

    add_executable(ductio_ticks_test ticks_test.c)
    target_link_libraries(ductio_ticks_test PRIVATE DuctIo::ductio)
    target_compile_features(ductio_ticks_test PRIVATE c_std_23)
    add_test(NAME ticks COMMAND ductio_ticks_test)
    set_tests_properties(ticks PROPERTIES TIMEOUT 10)
endif()

add_executable(ductio_redial_test redial_test.c)
target_link_libraries(ductio_redial_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_redial_test PRIVATE c_std_23)
add_test(NAME redial COMMAND ductio_redial_test)
set_tests_properties(redial PROPERTIES TIMEOUT 10)

add_executable(ductio_liveness_test liveness_test.c)
target_link_libraries(ductio_liveness_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_liveness_test PRIVATE c_std_23)
add_test(NAME liveness COMMAND ductio_liveness_test)
set_tests_properties(liveness PROPERTIES TIMEOUT 10)

add_executable(ductio_cookie_test cookie_test.c)
target_link_libraries(ductio_cookie_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_cookie_test PRIVATE c_std_23)
add_test(NAME cookie COMMAND ductio_cookie_test)
set_tests_properties(cookie PROPERTIES TIMEOUT 30)

add_executable(ductio_pmtu_drive_test pmtu_drive_test.c)
target_link_libraries(ductio_pmtu_drive_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_pmtu_drive_test PRIVATE c_std_23)
add_test(NAME pmtu_drive COMMAND ductio_pmtu_drive_test)
set_tests_properties(pmtu_drive PROPERTIES TIMEOUT 30)

add_executable(ductio_timer_key_test timer_key_test.c)
target_link_libraries(ductio_timer_key_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_timer_key_test PRIVATE c_std_23)
add_test(NAME timer_key COMMAND ductio_timer_key_test)
set_tests_properties(timer_key PROPERTIES TIMEOUT 60)

add_executable(ductio_timer_start_test timer_start_test.c)
target_link_libraries(ductio_timer_start_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_timer_start_test PRIVATE c_std_23)
add_test(NAME timer_start COMMAND ductio_timer_start_test)
set_tests_properties(timer_start PROPERTIES TIMEOUT 30)

add_executable(ductio_stats_sections_test stats_sections_test.c)
target_link_libraries(ductio_stats_sections_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_stats_sections_test PRIVATE c_std_23)
add_test(NAME stats_sections COMMAND ductio_stats_sections_test)
set_tests_properties(stats_sections PROPERTIES TIMEOUT 60)

add_executable(ductio_dgram_spoof_migration_test
    dgram_spoof_migration_test.c tls_engine_null.c)
target_link_libraries(ductio_dgram_spoof_migration_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_dgram_spoof_migration_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_dgram_spoof_migration_test PRIVATE c_std_23)
add_test(NAME dgram_spoof_migration COMMAND ductio_dgram_spoof_migration_test)
set_tests_properties(dgram_spoof_migration PROPERTIES TIMEOUT 30)

add_executable(ductio_dgram_prefix_roam_test
    dgram_prefix_roam_test.c tls_engine_null.c)
target_link_libraries(ductio_dgram_prefix_roam_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_dgram_prefix_roam_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_dgram_prefix_roam_test PRIVATE c_std_23)
add_test(NAME dgram_prefix_roam COMMAND ductio_dgram_prefix_roam_test)
set_tests_properties(dgram_prefix_roam PROPERTIES TIMEOUT 30)

add_executable(ductio_tls_null_test tls_null_test.c tls_engine_null.c)
target_link_libraries(ductio_tls_null_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_tls_null_test PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_tls_null_test PRIVATE c_std_23)
add_test(NAME tls_null COMMAND ductio_tls_null_test)

if(DUCT_WITH_OPENSSL)
    add_executable(ductio_tls_openssl_test tls_openssl_test.c)
    target_link_libraries(ductio_tls_openssl_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_tls_openssl_test PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_tls_openssl_test PRIVATE c_std_23)
    add_test(NAME tls_openssl COMMAND ductio_tls_openssl_test)
    set_tests_properties(tls_openssl PROPERTIES TIMEOUT 20)
endif()

if(DUCT_WITH_NOISE)
    add_executable(ductio_noise_engine_test noise_engine_test.c)
    target_link_libraries(ductio_noise_engine_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_noise_engine_test PRIVATE c_std_23)
    add_test(NAME noise_engine COMMAND ductio_noise_engine_test)
    set_tests_properties(noise_engine PROPERTIES TIMEOUT 20)

    add_executable(ductio_noise_keypair_test noise_keypair_test.c)
    target_link_libraries(ductio_noise_keypair_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_noise_keypair_test PRIVATE c_std_23)
    add_test(NAME noise_keypair COMMAND ductio_noise_keypair_test)
    set_tests_properties(noise_keypair PROPERTIES TIMEOUT 10)

    # noise_kat_test includes ../src/wire/duct_noise.c directly to swap the ephemeral
    # key generator for a table. Exclude duct_noise.c from the source list to avoid
    # duplicate symbols, as handler_dispatch_test does with duct_worker.c below.
    set(DUCTIO_SRC_NOISE_KAT ${DUCTIO_SRC})
    list(REMOVE_ITEM DUCTIO_SRC_NOISE_KAT "${PROJECT_SOURCE_DIR}/src/wire/duct_noise.c")
    add_executable(ductio_noise_kat_test
        noise_kat_test.c
        ${DUCTIO_SRC_NOISE_KAT}
        ${DUCTIO_SRC_OS}
    )
    duct_platform_configure(ductio_noise_kat_test)
    target_link_libraries(ductio_noise_kat_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_noise_kat_test PRIVATE
        "${PROJECT_SOURCE_DIR}/include"
        "${DUCT_GENERATED_INCLUDE_DIR}"
        ${DUCT_INTERNAL_INCLUDE_DIRS}
    )
    target_compile_features(ductio_noise_kat_test PRIVATE c_std_23)
    target_compile_options(ductio_noise_kat_test PRIVATE
        -Wall -Wextra -Wenum-conversion -Wformat=2
    )
    if(DUCT_ENABLE_RUNTIME_STATS)
        target_compile_definitions(ductio_noise_kat_test PRIVATE DUCT_RUNTIME_STATS=1)
    else()
        target_compile_definitions(ductio_noise_kat_test PRIVATE DUCT_RUNTIME_STATS=0)
    endif()
    add_test(NAME noise_kat COMMAND ductio_noise_kat_test)
    set_tests_properties(noise_kat PROPERTIES TIMEOUT 10)

    add_executable(ductio_noise_peer_psk_test noise_peer_psk_test.c)
    target_link_libraries(ductio_noise_peer_psk_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_noise_peer_psk_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_noise_peer_psk_test PRIVATE c_std_23)
    add_test(NAME noise_peer_psk COMMAND ductio_noise_peer_psk_test)
    set_tests_properties(noise_peer_psk PROPERTIES TIMEOUT 20)

    add_executable(ductio_hmac_sha256_test hmac_sha256_test.c)
    target_link_libraries(ductio_hmac_sha256_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_hmac_sha256_test PRIVATE c_std_23)
    add_test(NAME hmac_sha256 COMMAND ductio_hmac_sha256_test)
    set_tests_properties(hmac_sha256 PROPERTIES TIMEOUT 10)

    add_executable(ductio_seal_prefix_test seal_prefix_test.c)
    target_link_libraries(ductio_seal_prefix_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_seal_prefix_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_seal_prefix_test PRIVATE c_std_23)
    add_test(NAME seal_prefix COMMAND ductio_seal_prefix_test)
    set_tests_properties(seal_prefix PROPERTIES TIMEOUT 30)

    add_executable(ductio_peer_auth_test peer_auth_test.c)
    target_link_libraries(ductio_peer_auth_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_peer_auth_test PRIVATE c_std_23)
    add_test(NAME peer_auth COMMAND ductio_peer_auth_test)
    set_tests_properties(peer_auth PROPERTIES TIMEOUT 30)

    add_executable(ductio_stream_lead_test stream_lead_test.c)
    target_link_libraries(ductio_stream_lead_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_stream_lead_test PRIVATE c_std_23)
    add_test(NAME stream_lead COMMAND ductio_stream_lead_test)
    set_tests_properties(stream_lead PROPERTIES TIMEOUT 30)

    add_executable(ductio_noise_join_test noise_join_test.c)
    target_link_libraries(ductio_noise_join_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_noise_join_test PRIVATE c_std_23)
    add_test(NAME noise_join COMMAND ductio_noise_join_test)
    set_tests_properties(noise_join PROPERTIES TIMEOUT 30)

    add_executable(ductio_handshake_deadline_test handshake_deadline_test.c)
    target_link_libraries(ductio_handshake_deadline_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_handshake_deadline_test PRIVATE c_std_23)
    add_test(NAME handshake_deadline COMMAND ductio_handshake_deadline_test)
    set_tests_properties(handshake_deadline PROPERTIES TIMEOUT 30)

    add_executable(ductio_handshake_retry_test handshake_retry_test.c)
    target_link_libraries(ductio_handshake_retry_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_handshake_retry_test PRIVATE c_std_23)
    add_test(NAME handshake_retry COMMAND ductio_handshake_retry_test)
    set_tests_properties(handshake_retry PROPERTIES TIMEOUT 60)

    add_executable(ductio_noise_dgram_test noise_dgram_test.c)
    target_link_libraries(ductio_noise_dgram_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_noise_dgram_test PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_noise_dgram_test PRIVATE c_std_23)
    add_test(NAME noise_dgram COMMAND ductio_noise_dgram_test)
    set_tests_properties(noise_dgram PROPERTIES TIMEOUT 20)
    add_test(NAME noise_dgram_xk COMMAND ductio_noise_dgram_test xk)
    set_tests_properties(noise_dgram_xk PROPERTIES TIMEOUT 20)

    add_executable(ductio_noise_compact_test noise_compact_test.c)
    target_link_libraries(ductio_noise_compact_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_noise_compact_test PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_noise_compact_test PRIVATE c_std_23)
    add_test(NAME noise_compact COMMAND ductio_noise_compact_test)
    set_tests_properties(noise_compact PROPERTIES TIMEOUT 20)

    add_executable(ductio_noise_xk_engine_test noise_xk_engine_test.c)
    target_link_libraries(ductio_noise_xk_engine_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_noise_xk_engine_test PRIVATE c_std_23)
    add_test(NAME noise_xk_engine COMMAND ductio_noise_xk_engine_test)
    set_tests_properties(noise_xk_engine PROPERTIES TIMEOUT 30)

    add_executable(ductio_noise_xk_test noise_xk_test.c)
    target_link_libraries(ductio_noise_xk_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_noise_xk_test PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_noise_xk_test PRIVATE c_std_23)
    add_test(NAME noise_xk COMMAND ductio_noise_xk_test)
    set_tests_properties(noise_xk PROPERTIES TIMEOUT 20)

    add_executable(ductio_noise_mask_test noise_mask_test.c)
    target_link_libraries(ductio_noise_mask_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_noise_mask_test PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_noise_mask_test PRIVATE c_std_23)
    add_test(NAME noise_mask COMMAND ductio_noise_mask_test)
    set_tests_properties(noise_mask PROPERTIES TIMEOUT 60)

    add_executable(ductio_dgram_lead_test dgram_lead_test.c)
    target_link_libraries(ductio_dgram_lead_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_dgram_lead_test PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_dgram_lead_test PRIVATE c_std_23)
    add_test(NAME dgram_lead COMMAND ductio_dgram_lead_test)
    set_tests_properties(dgram_lead PROPERTIES TIMEOUT 30)

    add_executable(ductio_noise_stream_open_test noise_stream_open_test.c)
    target_link_libraries(ductio_noise_stream_open_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_noise_stream_open_test PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_noise_stream_open_test PRIVATE c_std_23)
    add_test(NAME noise_stream_open COMMAND ductio_noise_stream_open_test)
    set_tests_properties(noise_stream_open PROPERTIES TIMEOUT 20)
    add_test(NAME noise_stream_open_xk COMMAND ductio_noise_stream_open_test xk)
    set_tests_properties(noise_stream_open_xk PROPERTIES TIMEOUT 20)

    add_executable(ductio_noise_wire_test noise_wire_test.c)
    target_link_libraries(ductio_noise_wire_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_noise_wire_test PRIVATE c_std_23)
    add_test(NAME noise_wire COMMAND ductio_noise_wire_test)
    set_tests_properties(noise_wire PROPERTIES TIMEOUT 20)
    add_test(NAME noise_wire_xk COMMAND ductio_noise_wire_test xk)
    set_tests_properties(noise_wire_xk PROPERTIES TIMEOUT 20)

    add_executable(ductio_noise_rekey_lazy_test noise_rekey_lazy_test.c)
    target_link_libraries(ductio_noise_rekey_lazy_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_noise_rekey_lazy_test PRIVATE c_std_23)
    add_test(NAME noise_rekey_lazy COMMAND ductio_noise_rekey_lazy_test)
    set_tests_properties(noise_rekey_lazy PROPERTIES TIMEOUT 20)
    add_test(NAME noise_rekey_lazy_xk COMMAND ductio_noise_rekey_lazy_test xk)
    set_tests_properties(noise_rekey_lazy_xk PROPERTIES TIMEOUT 20)

    add_executable(ductio_noise_test noise_test.c)
    target_link_libraries(ductio_noise_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_noise_test PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_noise_test PRIVATE c_std_23)
    add_test(NAME noise COMMAND ductio_noise_test)
    set_tests_properties(noise PROPERTIES TIMEOUT 20)

    add_executable(ductio_noise_tunnel_test noise_tunnel_test.c)
    target_link_libraries(ductio_noise_tunnel_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_noise_tunnel_test PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_noise_tunnel_test PRIVATE c_std_23)
    add_test(NAME noise_tunnel COMMAND ductio_noise_tunnel_test)
    set_tests_properties(noise_tunnel PROPERTIES TIMEOUT 20)

    if(NOT APPLE)
        add_executable(ductio_unseal_redirect_test unseal_redirect_test.c)
        target_link_libraries(ductio_unseal_redirect_test PRIVATE DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
        target_include_directories(ductio_unseal_redirect_test PRIVATE
            ${DUCT_INTERNAL_INCLUDE_DIRS})
        target_compile_features(ductio_unseal_redirect_test PRIVATE c_std_23)
        add_test(NAME unseal_redirect COMMAND ductio_unseal_redirect_test)
        set_tests_properties(unseal_redirect PROPERTIES TIMEOUT 30)
    endif()
endif()

if(WIN32 AND NOT DUCT_EVENTS_MODEL STREQUAL "poll" AND NOT DUCT_RIO_FORCE_DISABLE)
    add_executable(ductio_rio_probe_test rio_probe.c)
    target_link_libraries(ductio_rio_probe_test PRIVATE DuctIo::ductio)
    target_include_directories(ductio_rio_probe_test PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_rio_probe_test PRIVATE c_std_23)
    add_test(NAME rio_probe COMMAND ductio_rio_probe_test)
endif()


# handler_dispatch_test includes ../src/duct_worker.c directly to access
# static symbols (s_worker_on_frame, duct_tls_worker, duct_worker_t).
# Exclude duct_worker.c from the source list to avoid duplicate symbols.
set(DUCTIO_SRC_DISPATCH ${DUCTIO_SRC})
list(REMOVE_ITEM DUCTIO_SRC_DISPATCH "${PROJECT_SOURCE_DIR}/src/duct_worker.c")
add_executable(ductio_handler_dispatch_test
    handler_dispatch_test.c
    ${DUCTIO_SRC_DISPATCH}
    ${DUCTIO_SRC_OS}
)
duct_platform_configure(ductio_handler_dispatch_test)
if(DUCT_WITH_OPENSSL OR DUCT_WITH_NOISE)
    target_link_libraries(ductio_handler_dispatch_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
target_include_directories(ductio_handler_dispatch_test PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
    "${DUCT_GENERATED_INCLUDE_DIR}"
    ${DUCT_INTERNAL_INCLUDE_DIRS}
)
target_compile_features(ductio_handler_dispatch_test PRIVATE c_std_23)
target_compile_options(ductio_handler_dispatch_test PRIVATE
    -Wall -Wextra -Wenum-conversion -Wformat=2
)
if(DUCT_ENABLE_RUNTIME_STATS)
    target_compile_definitions(ductio_handler_dispatch_test PRIVATE DUCT_RUNTIME_STATS=1)
else()
    target_compile_definitions(ductio_handler_dispatch_test PRIVATE DUCT_RUNTIME_STATS=0)
endif()
add_test(NAME handler_dispatch COMMAND ductio_handler_dispatch_test)

# retry_drain_quota_test includes ../src/duct_worker.c directly too (same
# reason and exclusion as handler_dispatch_test above).
add_executable(ductio_retry_drain_quota_test
    retry_drain_quota_test.c
    ${DUCTIO_SRC_DISPATCH}
    ${DUCTIO_SRC_OS}
)
duct_platform_configure(ductio_retry_drain_quota_test)
if(DUCT_WITH_OPENSSL OR DUCT_WITH_NOISE)
    target_link_libraries(ductio_retry_drain_quota_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
target_include_directories(ductio_retry_drain_quota_test PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
    "${DUCT_GENERATED_INCLUDE_DIR}"
    ${DUCT_INTERNAL_INCLUDE_DIRS}
)
target_compile_features(ductio_retry_drain_quota_test PRIVATE c_std_23)
target_compile_options(ductio_retry_drain_quota_test PRIVATE
    -Wall -Wextra -Wenum-conversion -Wformat=2
)
if(DUCT_ENABLE_RUNTIME_STATS)
    target_compile_definitions(ductio_retry_drain_quota_test PRIVATE DUCT_RUNTIME_STATS=1)
else()
    target_compile_definitions(ductio_retry_drain_quota_test PRIVATE DUCT_RUNTIME_STATS=0)
endif()
add_test(NAME retry_drain_quota COMMAND ductio_retry_drain_quota_test)

# retry_frame_ordering_test includes ../src/duct_worker.c directly too (same
# reason and exclusion as handler_dispatch_test above).
add_executable(ductio_retry_frame_ordering_test
    retry_frame_ordering_test.c
    ${DUCTIO_SRC_DISPATCH}
    ${DUCTIO_SRC_OS}
)
duct_platform_configure(ductio_retry_frame_ordering_test)
if(DUCT_WITH_OPENSSL OR DUCT_WITH_NOISE)
    target_link_libraries(ductio_retry_frame_ordering_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
target_include_directories(ductio_retry_frame_ordering_test PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
    "${DUCT_GENERATED_INCLUDE_DIR}"
    ${DUCT_INTERNAL_INCLUDE_DIRS}
)
target_compile_features(ductio_retry_frame_ordering_test PRIVATE c_std_23)
target_compile_options(ductio_retry_frame_ordering_test PRIVATE
    -Wall -Wextra -Wenum-conversion -Wformat=2
)
if(DUCT_ENABLE_RUNTIME_STATS)
    target_compile_definitions(ductio_retry_frame_ordering_test PRIVATE DUCT_RUNTIME_STATS=1)
else()
    target_compile_definitions(ductio_retry_frame_ordering_test PRIVATE DUCT_RUNTIME_STATS=0)
endif()
add_test(NAME retry_frame_ordering COMMAND ductio_retry_frame_ordering_test)

# tx_hold_multi_leg_test includes ../src/duct_worker.c directly too (same
# reason and exclusion as handler_dispatch_test above).
add_executable(ductio_tx_hold_multi_leg_test
    tx_hold_multi_leg_test.c
    ${DUCTIO_SRC_DISPATCH}
    ${DUCTIO_SRC_OS}
)
duct_platform_configure(ductio_tx_hold_multi_leg_test)
if(DUCT_WITH_OPENSSL OR DUCT_WITH_NOISE)
    target_link_libraries(ductio_tx_hold_multi_leg_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
target_include_directories(ductio_tx_hold_multi_leg_test PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
    "${DUCT_GENERATED_INCLUDE_DIR}"
    ${DUCT_INTERNAL_INCLUDE_DIRS}
)
target_compile_features(ductio_tx_hold_multi_leg_test PRIVATE c_std_23)
target_compile_options(ductio_tx_hold_multi_leg_test PRIVATE
    -Wall -Wextra -Wenum-conversion -Wformat=2
)
if(DUCT_ENABLE_RUNTIME_STATS)
    target_compile_definitions(ductio_tx_hold_multi_leg_test PRIVATE DUCT_RUNTIME_STATS=1)
else()
    target_compile_definitions(ductio_tx_hold_multi_leg_test PRIVATE DUCT_RUNTIME_STATS=0)
endif()
add_test(NAME tx_hold_multi_leg COMMAND ductio_tx_hold_multi_leg_test)
set_tests_properties(tx_hold_multi_leg PROPERTIES TIMEOUT 10)

add_executable(ductio_pmtu_test pmtu_test.c)
target_link_libraries(ductio_pmtu_test PRIVATE DuctIo::ductio)
target_compile_features(ductio_pmtu_test PRIVATE c_std_23)
add_test(NAME pmtu COMMAND ductio_pmtu_test)
set_tests_properties(pmtu PROPERTIES TIMEOUT 10)

add_executable(ductio_xopening_test xopening_test.c)
target_link_libraries(ductio_xopening_test PRIVATE DuctIo::ductio)
target_include_directories(ductio_xopening_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
target_compile_features(ductio_xopening_test PRIVATE c_std_23)
add_test(NAME xopening COMMAND ductio_xopening_test)
set_tests_properties(xopening PROPERTIES TIMEOUT 10)

# tx_pool_test includes ../src/duct_worker.c directly too (same reason and
# exclusion as handler_dispatch_test above).
add_executable(ductio_tx_pool_test
    tx_pool_test.c
    ${DUCTIO_SRC_DISPATCH}
    ${DUCTIO_SRC_OS}
)
duct_platform_configure(ductio_tx_pool_test)
if(DUCT_WITH_OPENSSL OR DUCT_WITH_NOISE)
    target_link_libraries(ductio_tx_pool_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
target_include_directories(ductio_tx_pool_test PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
    "${DUCT_GENERATED_INCLUDE_DIR}"
    ${DUCT_INTERNAL_INCLUDE_DIRS}
)
target_compile_features(ductio_tx_pool_test PRIVATE c_std_23)
target_compile_options(ductio_tx_pool_test PRIVATE
    -Wall -Wextra -Wenum-conversion -Wformat=2
)
if(DUCT_ENABLE_RUNTIME_STATS)
    target_compile_definitions(ductio_tx_pool_test PRIVATE DUCT_RUNTIME_STATS=1)
else()
    target_compile_definitions(ductio_tx_pool_test PRIVATE DUCT_RUNTIME_STATS=0)
endif()
add_test(NAME tx_pool COMMAND ductio_tx_pool_test)

# vnet_train_test includes ../src/duct_worker.c directly too, and drives a seqpacket
# socketpair in the tun's place, which only Linux has.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ductio_vnet_train_test
        vnet_train_test.c
        ${DUCTIO_SRC_DISPATCH}
        ${DUCTIO_SRC_OS}
    )
    duct_platform_configure(ductio_vnet_train_test)
    if(DUCT_WITH_OPENSSL OR DUCT_WITH_NOISE)
        target_link_libraries(ductio_vnet_train_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    target_include_directories(ductio_vnet_train_test PRIVATE
        "${PROJECT_SOURCE_DIR}/include"
        "${DUCT_GENERATED_INCLUDE_DIR}"
        ${DUCT_INTERNAL_INCLUDE_DIRS}
    )
    target_compile_features(ductio_vnet_train_test PRIVATE c_std_23)
    target_compile_options(ductio_vnet_train_test PRIVATE
        -Wall -Wextra -Wenum-conversion -Wformat=2 -UNDEBUG
    )
    if(DUCT_ENABLE_RUNTIME_STATS)
        target_compile_definitions(ductio_vnet_train_test PRIVATE DUCT_RUNTIME_STATS=1)
    else()
        target_compile_definitions(ductio_vnet_train_test PRIVATE DUCT_RUNTIME_STATS=0)
    endif()
    add_test(NAME vnet_train COMMAND ductio_vnet_train_test)
    set_tests_properties(vnet_train PROPERTIES TIMEOUT 10)
endif()

# shutdown_abandon_test, dgram_scratch_test and tick_sweep_test include ../src/duct_io.c
# directly to reach the io module state, its static message kinds, sweep and thread pointer.
# Exclude duct_io.c from the source list to avoid duplicate symbols, as
# handler_dispatch_test does with duct_worker.c above. socketpair pairs stand in
# for the fds the messages own.
if(NOT WIN32)
    set(DUCTIO_SRC_IO_INCLUDED ${DUCTIO_SRC})
    list(REMOVE_ITEM DUCTIO_SRC_IO_INCLUDED "${PROJECT_SOURCE_DIR}/src/duct_io.c")
    foreach(_io_test shutdown_abandon dgram_scratch tick_sweep)
        add_executable(ductio_${_io_test}_test
            ${_io_test}_test.c
            ${DUCTIO_SRC_IO_INCLUDED}
            ${DUCTIO_SRC_OS}
        )
        duct_platform_configure(ductio_${_io_test}_test)
        if(DUCT_WITH_OPENSSL OR DUCT_WITH_NOISE)
            target_link_libraries(ductio_${_io_test}_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
        endif()
        target_include_directories(ductio_${_io_test}_test PRIVATE
            "${PROJECT_SOURCE_DIR}/include"
            "${DUCT_GENERATED_INCLUDE_DIR}"
            ${DUCT_INTERNAL_INCLUDE_DIRS}
        )
        target_compile_features(ductio_${_io_test}_test PRIVATE c_std_23)
        target_compile_options(ductio_${_io_test}_test PRIVATE
            -Wall -Wextra -Wenum-conversion -Wformat=2 -UNDEBUG
        )
        if(DUCT_ENABLE_RUNTIME_STATS)
            target_compile_definitions(ductio_${_io_test}_test PRIVATE DUCT_RUNTIME_STATS=1)
        else()
            target_compile_definitions(ductio_${_io_test}_test PRIVATE DUCT_RUNTIME_STATS=0)
        endif()
        add_test(NAME ${_io_test} COMMAND ductio_${_io_test}_test)
        set_tests_properties(${_io_test} PROPERTIES TIMEOUT 10)
    endforeach()
endif()

# Per-test hard timeouts so a stalled runtime/engine fails the suite instead
# of hanging CI. In-process SIGALRM guards cover the pool stress tests; this
# is the outer belt-and-suspenders for the io/engine tests.
set_tests_properties(echo              PROPERTIES TIMEOUT 10)
set_tests_properties(conn_churn        PROPERTIES TIMEOUT 30)
set_tests_properties(join              PROPERTIES TIMEOUT 10)
set_tests_properties(join_edge         PROPERTIES TIMEOUT 30)
set_tests_properties(conn_pool_stress  PROPERTIES TIMEOUT 15)
set_tests_properties(session_pool_stress PROPERTIES TIMEOUT 20)
set_tests_properties(coro                 PROPERTIES TIMEOUT 10)
set_tests_properties(wire                 PROPERTIES TIMEOUT 30)
set_tests_properties(stream               PROPERTIES TIMEOUT 30)
set_tests_properties(stream_slot          PROPERTIES TIMEOUT 10)
set_tests_properties(dgram_tx_partial_commit PROPERTIES TIMEOUT 10)
set_tests_properties(timer                PROPERTIES TIMEOUT 10)
set_tests_properties(control              PROPERTIES TIMEOUT 30)
set_tests_properties(peer_disconnect      PROPERTIES TIMEOUT 10)
set_tests_properties(defer_stream         PROPERTIES TIMEOUT 10)
set_tests_properties(handler_dispatch     PROPERTIES TIMEOUT 10)
set_tests_properties(retry_drain_quota    PROPERTIES TIMEOUT 10)
set_tests_properties(tx_pool              PROPERTIES TIMEOUT 10)
set_tests_properties(tx_full_batch        PROPERTIES TIMEOUT 30)
set_tests_properties(tx_full_once         PROPERTIES TIMEOUT 60)
set_tests_properties(owned_retry          PROPERTIES TIMEOUT 30)
set_tests_properties(retry_frame_ordering PROPERTIES TIMEOUT 10)
if(WIN32 AND NOT DUCT_EVENTS_MODEL STREQUAL "poll" AND NOT DUCT_RIO_FORCE_DISABLE)
    set_tests_properties(rio_probe PROPERTIES TIMEOUT 5)
endif()
set_tests_properties(session_reclaim_race PROPERTIES TIMEOUT 60)
set_tests_properties(connect              PROPERTIES TIMEOUT 90)
set_tests_properties(e2e_reconnect        PROPERTIES TIMEOUT 60)
set_tests_properties(inter_conn           PROPERTIES TIMEOUT 30)
set_tests_properties(mux_dgram            PROPERTIES TIMEOUT 30)
set_tests_properties(probe_wait           PROPERTIES TIMEOUT 20)
set_tests_properties(listener_close       PROPERTIES TIMEOUT 30)
set_tests_properties(listener_add         PROPERTIES TIMEOUT 30)
set_tests_properties(dgram_shared         PROPERTIES TIMEOUT 20)
if(NOT APPLE)
    set_tests_properties(dgram_shared_stall PROPERTIES TIMEOUT 30)
endif()
set_tests_properties(rio_multi_listener   PROPERTIES TIMEOUT 20)
set_tests_properties(tls_null             PROPERTIES TIMEOUT 20)
set_tests_properties(wire_change          PROPERTIES TIMEOUT 30)

add_executable(ductio_bench_echo bench_echo.c)
target_link_libraries(ductio_bench_echo PRIVATE DuctIo::ductio)
target_include_directories(ductio_bench_echo PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS}
)
duct_platform_configure(ductio_bench_echo)
target_compile_features(ductio_bench_echo PRIVATE c_std_23)

if(DUCT_ENABLE_RUNTIME_STATS)
    target_compile_definitions(ductio_bench_echo PRIVATE DUCT_BENCH=1 DUCT_RUNTIME_STATS=1)
else()
    target_compile_definitions(ductio_bench_echo PRIVATE DUCT_BENCH=1 DUCT_RUNTIME_STATS=0)
endif()

add_executable(ductio_bench_hops bench_hops.c)
target_link_libraries(ductio_bench_hops PRIVATE DuctIo::ductio)
target_include_directories(ductio_bench_hops PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS}
)
duct_platform_configure(ductio_bench_hops)
target_compile_features(ductio_bench_hops PRIVATE c_std_23)

if(DUCT_ENABLE_RUNTIME_STATS)
    target_compile_definitions(ductio_bench_hops PRIVATE DUCT_RUNTIME_STATS=1)
else()
    target_compile_definitions(ductio_bench_hops PRIVATE DUCT_RUNTIME_STATS=0)
endif()

add_executable(ductio_bench_wake bench_wake.c)
target_link_libraries(ductio_bench_wake PRIVATE DuctIo::ductio)
target_include_directories(ductio_bench_wake PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS}
)
duct_platform_configure(ductio_bench_wake)
target_compile_features(ductio_bench_wake PRIVATE c_std_23)

add_executable(ductio_bench_recv bench_recv.c)
target_link_libraries(ductio_bench_recv PRIVATE DuctIo::ductio)
target_include_directories(ductio_bench_recv PRIVATE
    ${DUCT_INTERNAL_INCLUDE_DIRS}
)
duct_platform_configure(ductio_bench_recv)
target_compile_features(ductio_bench_recv PRIVATE c_std_23)

if(DUCT_ENABLE_RUNTIME_STATS)
    target_compile_definitions(ductio_bench_recv PRIVATE DUCT_RUNTIME_STATS=1)
else()
    target_compile_definitions(ductio_bench_recv PRIVATE DUCT_RUNTIME_STATS=0)
endif()

# Use the archive and generated headers from this exact CMake build: Cargo
# must not silently compile a second engine with different tunables/backend.
find_program(DUCT_CARGO cargo)
set(_duct_rust_default OFF)
if(DUCT_WITH_NOISE AND DUCT_CARGO AND NOT CMAKE_CROSSCOMPILING AND NOT WIN32)
    set(_duct_rust_default ON)
endif()
option(DUCT_BUILD_RUST_TESTS "Run the Rust workspace in the native CTest suite"
    ${_duct_rust_default})
if(DUCT_BUILD_RUST_TESTS)
    if(CMAKE_CROSSCOMPILING)
        message(FATAL_ERROR "Rust CTests require a native build; use DUCT_BUILD_RUST_TESTS=OFF for cross builds")
    endif()
    if(NOT DUCT_WITH_NOISE)
        message(FATAL_ERROR "Rust SDK tests require DUCT_WITH_NOISE=ON")
    endif()
    if(NOT DUCT_CARGO)
        message(FATAL_ERROR "DUCT_BUILD_RUST_TESTS=ON needs cargo on PATH")
    endif()
    get_filename_component(_duct_crypto_libdir "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)
    set(_duct_rust_features)
    if(DUCT_WITH_OPENSSL)
        list(APPEND _duct_rust_features --all-features)
    endif()
    add_test(NAME rust_sdk COMMAND "${CMAKE_COMMAND}" -E env
        "CC=${CMAKE_C_COMPILER}" "AR=${CMAKE_AR}"
        "MACOSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}"
        "DUCTIO_SYS_LIB_DIR=$<TARGET_FILE_DIR:ductio>"
        "DUCTIO_SYS_INCLUDE_DIR=${PROJECT_SOURCE_DIR}/include"
        "DUCTIO_SYS_GENERATED_INCLUDE_DIR=${DUCT_GENERATED_INCLUDE_DIR}"
        "OPENSSL_LIB_DIR=${_duct_crypto_libdir}"
        "OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}"
        "CARGO_TARGET_DIR=${CMAKE_BINARY_DIR}/rust"
        "${DUCT_CARGO}" test --locked --workspace ${_duct_rust_features}
        --manifest-path "${PROJECT_SOURCE_DIR}/bindings/rust/Cargo.toml"
        -- --test-threads=1)
    set_tests_properties(rust_sdk PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE LABELS "rust;sdk")
endif()
# A failed regression must terminate in CI even if its cleanup blocks.
get_property(_duct_tests DIRECTORY PROPERTY TESTS)
foreach(_duct_test IN LISTS _duct_tests)
    get_test_property("${_duct_test}" TIMEOUT _duct_timeout)
    if(_duct_timeout STREQUAL "NOTFOUND")
        set_tests_properties("${_duct_test}" PROPERTIES TIMEOUT 60)
    endif()
endforeach()

# White-box tests use assert for both fixture setup and their oracles. Keep
# assertions enabled even when the engine archive is built as Release.
foreach(_duct_whitebox handler_dispatch retry_drain_quota retry_frame_ordering tx_hold_multi_leg)
    target_compile_options(ductio_${_duct_whitebox}_test PRIVATE -UNDEBUG)
endforeach()

if(NOT WIN32)
    add_executable(ductio_socket_prepare_test socket_prepare_test.c)
    target_include_directories(ductio_socket_prepare_test PRIVATE ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_link_libraries(ductio_socket_prepare_test PRIVATE DuctIo::ductio)
    duct_platform_configure(ductio_socket_prepare_test)
    target_compile_options(ductio_socket_prepare_test PRIVATE -UNDEBUG)
    add_test(NAME socket_prepare COMMAND ductio_socket_prepare_test)
endif()

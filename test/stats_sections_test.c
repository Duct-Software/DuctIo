/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file stats_sections_test.c
 *  @brief The statistics sections a protocol hands the engine to sum, on an engine of two I/O threads and three workers.
 *
 *  @c sc_engine expects a reading to open with the engine section: the pool's free
 *  slots, its refusals and the stats flag, then every counter of @c duct_rt_stats_t in a
 *  build with runtime stats. @c sc_refused expects a table the engine cannot place to be
 *  refused. @c sc_sums expects counters written on every worker and on an I/O thread to
 *  read as their sum, a field the table leaves out to stay unreported, and each engine
 *  thread to write a shard of its own. @c sc_host expects a host thread to get no shard.
 *  @c sc_saturate expects counters summing past @c UINT64_MAX to read @c UINT64_MAX.
 *  @c sc_race expects a reading looped on a host thread while every worker writes to see no
 *  counter fall and to leave the final sum exact. @c sc_gone expects a stopped engine to take
 *  no section and a section to end with its engine.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

static constexpr unsigned io_threads = 2u;
static constexpr unsigned workers    = 3u;
static constexpr unsigned wait_ms    = 5000u;
/** @brief One for a member of @c duct_rt_stats_members. */
#define rt_one(member) + 1u
/** @brief Counters of @c duct_rt_stats_t, which a reading of a stats build reports under the engine section. */
static constexpr unsigned rt_counters = 0u duct_rt_stats_members(rt_one);
#undef rt_one
/** @brief Additions each worker makes in @c sc_race. */
static constexpr unsigned race_adds   = 500000u;

/** @brief Shard of the test's sections: the field between the two counters is left out of the table. */
typedef struct {
    uint64_t _Atomic up,
                     gap,
                     down;
} tally_t;

/** @brief Tokens that tell a timer's fire what to write. */
enum : uintptr_t {
    token_tally = 1u,
    token_big,
    token_race,
};

static duct_engine_t *g_e;
static duct_proto_t  *g_timers,
                     *g_content,
                     *g_fallback;
static duct_stats_t  *g_st;
static atomic_int     g_fires,
                      g_io_calls;
static void *_Atomic  g_shards[8];

/** @brief One counter of a reading. */
typedef struct {
    char     section[16],
             field[40];
    uint64_t value;
} row_t;

/** @brief A whole reading, in the order it was visited. */
typedef struct {
    row_t    row[96];
    unsigned n;
} rows_t;

static void s_visit(void *ctx, const char *section, const char *field, uint64_t value)
{
    auto rows = (rows_t *)ctx;
    if (rows->n < sizeof rows->row / sizeof rows->row[0]) {
        auto row = &rows->row[rows->n++];
        snprintf(row->section, sizeof row->section, "%s", section);
        snprintf(row->field, sizeof row->field, "%s", field);
        row->value = value;
    }
}

static const row_t *s_row(const rows_t *rows, const char *section, const char *field)
{
    for (unsigned i = 0u; i < rows->n; ++i)
        if (strcmp(rows->row[i].section, section) == 0 && strcmp(rows->row[i].field, field) == 0)
            return &rows->row[i];
    return nullptr;
}

/** @brief Count the rows of the section @p section. */
static unsigned s_rows_of(const rows_t *rows, const char *section)
{
    unsigned n = 0u;
    for (unsigned i = 0u; i < rows->n; ++i)
        n += strcmp(rows->row[i].section, section) == 0;
    return n;
}

static void s_note_shard(void *shard)
{
    for (unsigned i = 0u; i < sizeof g_shards / sizeof g_shards[0]; ++i) {
        void *none = nullptr;
        if (duct_atomic_cas(strong, &g_shards[i], &none, shard, acq_rel, acquire) || none == shard)
            return;
    }
}

static unsigned s_distinct_shards(void)
{
    unsigned n = 0u;
    for (unsigned i = 0u; i < sizeof g_shards / sizeof g_shards[0]; ++i)
        n += duct_atomic_load(&g_shards[i], acquire) != nullptr;
    return n;
}

static void s_reset(void)
{
    duct_atomic_store(&g_fires, 0, relaxed);
    duct_atomic_store(&g_io_calls, 0, relaxed);
    for (unsigned i = 0u; i < sizeof g_shards / sizeof g_shards[0]; ++i)
        duct_atomic_store(&g_shards[i], nullptr, relaxed);
}

static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              [[maybe_unused]] const duct_frame_t *frame,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief Write the shard of the worker this fire runs on, as the token asks. */
static duct_result_t on_timer([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state, uint64_t arg)
{
    tally_t *shard = duct_stats_shard(g_st);
    if (shard) {
        s_note_shard(shard);
        if (arg == token_big)
            duct_atomic_store(&shard->up, UINT64_MAX / 2u + 1u, relaxed);
        for (unsigned i = 0u; arg == token_race && i < race_adds; ++i)
            duct_stat_add(shard, up, 1u);
        if (arg == token_tally) {
            duct_stat_add(shard, up, 1u);
            duct_stat_add(shard, gap, 1000u);
            duct_stat_add(shard, down, 2u);
        }
    }
    duct_atomic_fetch(add, &g_fires, 1, release);
    return rc_ok;
}

/** @brief Write the shard of the I/O thread that classifies a connection. */
static duct_resolve_disposition_t
on_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
            [[maybe_unused]] duct_view_u8 peek, [[maybe_unused]] duct_handle_t *out_tok,
            [[maybe_unused]] duct_conn_id_t *out_conn_id, [[maybe_unused]] void **out_user_ctx,
            [[maybe_unused]] size_t *out_lead)
{
    tally_t *shard = duct_stats_shard(g_st);
    if (shard) {
        s_note_shard(shard);
        duct_stat_add(shard, up, 100u);
    }
    duct_atomic_fetch(add, &g_io_calls, 1, release);
    return resolve_reject;
}

static const duct_stat_field_t tally_fields[] = {
    duct_stat_field(tally_t, up),
    duct_stat_field(tally_t, down),
};

/** @brief The table of the section @p name over @c tally_t. */
static duct_stats_cfg_t tally_cfg(const char *name)
{
    return (duct_stats_cfg_t){ .name = name, .fields = tally_fields,
                               .n_fields = sizeof tally_fields / sizeof tally_fields[0],
                               .shard_size = sizeof(tally_t) };
}

/** @brief Start @p n timers of token @p token one after the other, so that they take the workers in turn, and wait for their fires. */
static const char *s_fire(unsigned n, uintptr_t token)
{
    duct_atomic_store(&g_fires, 0, release);
    for (unsigned i = 0u; i < n; ++i)
        expect(duct_timer_start(g_e, g_timers, nullptr, 0u, token) == rc_ok, "a timer was refused");
    expect(th_wait_int(&g_fires, (int)n, wait_ms), "the timers did not all fire");
    return nullptr;
}

static const char *sc_engine(void)
{
    rows_t rows = {};
    duct_stats_read(g_e, s_visit, &rows);
    expect(rows.n >= 3u, "a reading of an engine with no section is shorter than the engine's own");
    expect(strcmp(rows.row[0].section, "engine") == 0 && strcmp(rows.row[0].field, "conns_free") == 0
               && strcmp(rows.row[1].field, "conns_refused") == 0
               && strcmp(rows.row[2].field, "stats_enabled") == 0,
           "the engine section does not open the reading with the pool and the flag");
    expect(rows.row[0].value == duct_conns_free() && rows.row[1].value == duct_conns_refused(),
           "the pool's figures differ from the accessors'");
    duct_rt_stats_t rt;
    bool counted = duct_engine_stats(g_e, &rt);
    expect(rows.row[2].value == counted, "the stats flag differs from duct_engine_stats");
    expect(s_rows_of(&rows, "engine") == (counted ? 3u + rt_counters : 3u),
           "the engine section does not hold the pool, the flag and every counter of a stats build");
    expect(!counted || s_row(&rows, "engine", "wfq_drain"), "a counter of duct_rt_stats_t is not reported");
    expect(rows.n == s_rows_of(&rows, "engine"), "a section nobody made is reported");
    return nullptr;
}

static const char *sc_refused(void)
{
    static const duct_stat_field_t fine[] = { { "up", 0u } },
                                   nameless[] = { { nullptr, 0u } },
                                   blank[] = { { "", 0u } },
                                   unaligned[] = { { "up", 4u } },
                                   past[] = { { "up", 8u } };
    auto cfg = tally_cfg("tally");
    expect(!duct_stats_create(nullptr, &cfg), "a null engine took a section");
    expect(!duct_stats_create(g_e, nullptr), "a null table was taken");
    cfg.name = nullptr;
    expect(!duct_stats_create(g_e, &cfg), "a section with no name was taken");
    cfg.name = "";
    expect(!duct_stats_create(g_e, &cfg), "a section with an empty name was taken");
    cfg = tally_cfg("tally");
    cfg.fields = nullptr;
    expect(!duct_stats_create(g_e, &cfg), "a section with no fields was taken");
    cfg = tally_cfg("tally");
    cfg.n_fields = 0u;
    expect(!duct_stats_create(g_e, &cfg), "a section of no counters was taken");
    cfg = tally_cfg("tally");
    cfg.shard_size = 0u;
    expect(!duct_stats_create(g_e, &cfg), "a shard of no size was taken");
    cfg = (duct_stats_cfg_t){ .name = "bad", .fields = nameless, .n_fields = 1u, .shard_size = 8u };
    expect(!duct_stats_create(g_e, &cfg), "a counter with no name was taken");
    cfg.fields = blank;
    expect(!duct_stats_create(g_e, &cfg), "a counter with an empty name was taken");
    cfg.fields = unaligned;
    cfg.shard_size = 16u;
    expect(!duct_stats_create(g_e, &cfg), "a counter off an 8-byte boundary was taken");
    cfg.fields = past;
    cfg.shard_size = 8u;
    expect(!duct_stats_create(g_e, &cfg), "a counter past its shard was taken");
    cfg.fields = fine;
    cfg.name = "single";
    expect(duct_stats_create(g_e, &cfg), "a table that fits its shard exactly was refused");
    rows_t rows = {};
    duct_stats_read(g_e, s_visit, &rows);
    expect(s_rows_of(&rows, "bad") == 0u, "a refused table left a counter in the reading");
    expect(s_row(&rows, "single", "up") && s_rows_of(&rows, "single") == 1u,
           "the section made after the refusals is not read");
    return nullptr;
}

static const char *sc_sums(void)
{
    auto cfg = tally_cfg("tally");
    g_st = duct_stats_create(g_e, &cfg);
    expect(g_st, "the section was refused");
    constexpr unsigned timers = 4u * workers;
    const char *err = s_fire(timers, token_tally);
    if (err)
        return err;
    uint16_t port = 0u;
    g_content = duct_proto_create(&(duct_proto_cfg_t){
        .name = "stats-io", .on_frame = on_frame, .max_response = 64u,
        .preparse = on_preparse, .preparse_mode = resolve_sync });
    g_fallback = duct_proto_create(&(duct_proto_cfg_t){
        .name = "stats-fallback", .on_frame = on_frame, .max_response = 64u });
    expect(g_content && g_fallback, "a protocol was not made");
    auto rc = duct_listener_bind(g_e, &(duct_listener_cfg_t){
        .addr = "127.0.0.1", .n_protos = 2u,
        .protos = (const duct_proto_t *[]){ g_content, g_fallback },
        .probe_wait_ms = 500u }, &port, nullptr, 0u, nullptr);
    expect(rc == rc_ok, "the listener was not bound");
    auto fd = th_connect(port);
    expect(fd != duct_sock_bad, "the connection was not made");
    th_sleep_ms(100u);
    err = send(fd, "x", 1, 0) != 1 ? "the byte was not sent"
        : !th_wait_int(&g_io_calls, 1, wait_ms) ? "the classification of the connection never ran"
        : nullptr;
    duct_sock_close(fd);
    if (err)
        return err;

    rows_t rows = {};
    duct_stats_read(g_e, s_visit, &rows);
    auto up = s_row(&rows, "tally", "up");
    auto down = s_row(&rows, "tally", "down");
    expect(up && down, "a counter of the table is not reported");
    expect(up->value == timers + 100u, "up is not the sum of the workers' and the I/O thread's writes");
    expect(down->value == 2u * timers, "down is not the sum of the workers' writes");
    expect(s_rows_of(&rows, "tally") == 2u && !s_row(&rows, "tally", "gap"),
           "a field the table leaves out is reported");
    expect(s_distinct_shards() == workers + 1u, "the workers and the I/O thread do not write a shard each");
    return nullptr;
}

static const char *sc_host(void)
{
    expect(g_st, "the section of the earlier scenario is gone");
    expect(!duct_stats_shard(g_st), "a host thread got a shard");
    return nullptr;
}

static const char *sc_saturate(void)
{
    const char *err = s_fire(2u, token_big);
    if (err)
        return err;
    rows_t rows = {};
    duct_stats_read(g_e, s_visit, &rows);
    auto up = s_row(&rows, "tally", "up");
    expect(up, "the counter is not reported");
    expect(up->value == UINT64_MAX, "two shards at half the range and a bit do not read as the maximum");
    return nullptr;
}

/** @brief What the reader thread of @c sc_race keeps. */
typedef struct {
    atomic_int stop;
    uint64_t   last;    /**< Latest value of the counter read. */
    unsigned   reads,   /**< Readings made. */
               regress; /**< Readings that found the counter below an earlier one. */
} reader_t;

static void s_reader_visit(void *ctx, const char *section, const char *field, uint64_t value)
{
    auto reader = (reader_t *)ctx;
    if (strcmp(section, "race") != 0 || strcmp(field, "up") != 0)
        return;
    reader->regress += value < reader->last;
    reader->last = value;
}

static void *s_reader(void *arg)
{
    auto reader = (reader_t *)arg;
    while (!duct_atomic_load(&reader->stop, acquire)) {
        duct_stats_read(g_e, s_reader_visit, reader);
        ++reader->reads;
    }
    return nullptr;
}

static const char *sc_race(void)
{
    auto cfg = tally_cfg("race");
    g_st = duct_stats_create(g_e, &cfg);
    expect(g_st, "the section was refused");
    reader_t reader = {};
    pthread_t thread;
    expect(pthread_create(&thread, nullptr, s_reader, &reader) == 0, "the reader did not start");
    const char *err = s_fire(workers, token_race);
    th_sleep_ms(20u);
    duct_atomic_store(&reader.stop, 1, release);
    pthread_join(thread, nullptr);
    if (err)
        return err;
    rows_t rows = {};
    duct_stats_read(g_e, s_visit, &rows);
    auto up = s_row(&rows, "race", "up");
    expect(up && up->value == (uint64_t)workers * race_adds, "the sum is not exact once the writers are quiet");
    expect(reader.reads > 0u && reader.regress == 0u, "a counter read below an earlier reading");
    return nullptr;
}

static const char *sc_gone(void)
{
    duct_engine_stop(g_e);
    auto cfg = tally_cfg("late");
    expect(!duct_stats_create(g_e, &cfg), "a stopped engine took a section");
    duct_engine_destroy(g_e);
    g_e = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = io_threads, .workers = workers });
    expect(g_e, "the next engine did not start");
    rows_t rows = {};
    duct_stats_read(g_e, s_visit, &rows);
    expect(rows.n == s_rows_of(&rows, "engine"), "a section outlived its engine");
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    g_timers = duct_proto_create(&(duct_proto_cfg_t){
        .name = "stats-timers", .on_frame = on_frame, .on_timer = on_timer, .max_response = 64u });
    g_e = g_timers ? duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = io_threads, .workers = workers })
                   : nullptr;
    if (!g_e) {
        fprintf(stderr, "stats_sections: setup failed\n");
        return 1;
    }
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "engine",   sc_engine },
        { "refused",  sc_refused },
        { "sums",     sc_sums },
        { "host",     sc_host },
        { "saturate", sc_saturate },
        { "race",     sc_race },
        { "gone",     sc_gone },
    };
    int failed = 0;
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        s_reset();
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "stats_sections: %s: %s\n", cases[i].name, err);
            ++failed;
        }
    }
    duct_engine_stop(g_e);
    duct_engine_destroy(g_e);
    duct_proto_destroy(g_timers);
    duct_proto_destroy(g_content);
    duct_proto_destroy(g_fallback);
    if (failed)
        return 1;
    printf("stats_sections: OK (the engine section, refusals, sums over workers and an I/O thread, "
           "saturation, a reading under writers, a section ending with its engine)\n");
    return 0;
}

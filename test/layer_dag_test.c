/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file layer_dag_test.c
 *  @brief The include-layer DAG law, enforced on the live tree.
 *
 *  Walks the engine's own sources (include/, src/, os/), parses every
 *  quoted #include, resolves it against the includer's directory and the
 *  header roots, and checks each edge against the tier table of the
 *  layering map (tasks/duct-layering-sever.md §1 as corrected by its S1
 *  checkpoint): an edge may only run from a consumer at or above its
 *  provider, minus the map's sanctioned pairs. A Tarjan pass then proves
 *  the whole resolved graph is acyclic. Any layering violation or any SCC
 *  fails the test with the offending pairs printed.
 *
 *  Tests and examples are consumers above everything, not engine modules,
 *  so the walk never enters them.
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef DUCT_LAYER_ROOT
#error "layer_dag: compile with DUCT_LAYER_ROOT=\"<repo source root>\""
#endif

/** @brief Tier ids, ordered bottom-up. Consumers sit at or above providers. */
enum {
    tier_api = 0,        /**< include/ — the public vocabulary root. */
    tier_core = 1,       /**< bits/hash/time/treiber/proto/vnet/log … */
    tier_channels = 2,   /**< vmq, wfq, wfq_msg, timer, relay, codel, coro,
                          *   coop, dgram_rec, dgram_lead, dgram_out, msg, exec. */
    tier_pool = 3,       /**< block_pool, x_slot. */
    tier_oscontract = 4, /**< os/include + os/<plat>/include headers. */
    tier_conn = 5,       /**< conn, conn_block geometry, olb, xopening. */
    tier_session = 6,    /**< session, stream, join — wire's peer tier. */
    tier_wire = 6,       /**< wire, codec, tx, noise, tls. */
    tier_worker = 7,     /**< worker, pmtu, redial, liveness. */
    tier_io = 7,         /**< io, frame_rx, listener, pre_conn, os impls. */
    tier_host = 8,       /**< duct_host. */
    tier_engine = 9,     /**< duct.c. */
    tier_count = 10,
};

static const char *const s_tier_name[tier_count] = {
    "api", "core", "channels", "pool", "oscontract",
    "conn", "session|wire", "worker|io", "host", "engine",
};

static constexpr unsigned max_files = 1024u;
static constexpr unsigned max_incs = 16u * 1024u;
static constexpr unsigned max_path = 512u;
static constexpr unsigned no_edge = 0xffffffffu;

static char s_files[max_files][max_path];
static unsigned s_nfiles;
/** @brief Resolved include edges, as indices into @c s_files. */
static struct { unsigned from, to; } s_edges[max_incs];
static unsigned s_nedges;

static int
s_under(const char *path, const char *prefix)
{
    return strncmp(path, prefix, strlen(prefix)) == 0;
}

static const char *
s_base(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int
s_base_is(const char *path, const char *prefix)
{
    return strncmp(s_base(path), prefix, strlen(prefix)) == 0;
}

/** @brief The tier of a repo-relative path, canon table of the layering map.
 *
 *  os/ implementation files are io-tier citizens whatever platform directory
 *  bundles them; the channels families are recognized by name wherever the
 *  tree keeps them.
 */
static unsigned
s_tier(const char *path)
{
    if (s_under(path, "include/"))
        return tier_api;
    if (s_under(path, "os/include/") ||
        (s_under(path, "os/") && strstr(path, "/include/")))
        return tier_oscontract;
    if (s_under(path, "os/"))
        return tier_io;
    if (strcmp(path, "src/duct.c") == 0)
        return tier_engine;
    if (s_base_is(path, "duct_host"))
        return tier_host;
    if (s_under(path, "src/pool/") || s_base_is(path, "duct_block_pool") ||
        s_base_is(path, "duct_x_slot"))
        return tier_pool;
    if (s_under(path, "src/conn/") || s_base_is(path, "duct_conn") ||
        s_base_is(path, "duct_olb") || s_base_is(path, "duct_span"))
        return tier_conn;
    if (s_under(path, "src/session/") || s_base_is(path, "duct_session") ||
        s_base_is(path, "duct_stream") || s_base_is(path, "duct_join"))
        return tier_session;
    if (s_under(path, "src/wire/") || s_base_is(path, "duct_wire") ||
        s_base_is(path, "duct_tls") || s_base_is(path, "duct_noise"))
        return tier_wire;
    if (s_base_is(path, "duct_io") || s_base_is(path, "duct_frame_rx") ||
        s_base_is(path, "duct_listener") || s_base_is(path, "duct_pre_conn"))
        return tier_io;
    if (s_base_is(path, "duct_worker") || s_base_is(path, "duct_liveness") ||
        s_base_is(path, "duct_pmtu") || s_base_is(path, "duct_redial"))
        return tier_worker;
    if (s_base_is(path, "duct_timer") || s_base_is(path, "duct_relay") ||
        s_base_is(path, "duct_coro") || s_base_is(path, "duct_coop") ||
        s_base_is(path, "duct_wfq") || s_base_is(path, "duct_vmq") ||
        s_base_is(path, "duct_codel") || s_base_is(path, "duct_dgram_rec") ||
        s_base_is(path, "duct_dgram_lead") || s_base_is(path, "duct_dgram_out") ||
        s_base_is(path, "duct_vnet") || s_base_is(path, "duct_msg") ||
        s_base_is(path, "duct_exec"))
        return tier_channels;
    return tier_core;
}

/** @brief The map's sanctioned edges (layering map §1 rules + duct-conn-close §3). */
static const struct { const char *from, *to; } s_sanctioned[] = {
    { "src/conn/duct_conn.c", "src/include/duct_io.h" }, /* teardown anchor */
    { "src/include/duct_worker.h", "include/duct.h" },   /* own fn vocabulary */
    { "src/include/duct_session.h", "include/duct.h" },  /* own fn vocabulary */
};

static int
s_edge_sanctioned(const char *from, const char *to)
{
    for (unsigned i = 0u; i < sizeof s_sanctioned / sizeof s_sanctioned[0]; ++i)
        if (strcmp(from, s_sanctioned[i].from) == 0 &&
            strcmp(to, s_sanctioned[i].to) == 0)
            return 1;
    return 0;
}

static int
s_file_known(const char *path)
{
    for (unsigned i = 0u; i < s_nfiles; ++i)
        if (strcmp(s_files[i], path) == 0)
            return (int)i;
    return -1;
}

/** @brief Add @p path (repo-relative, '/'-separated) unless already present. */
static unsigned
s_file_add(const char *path)
{
    int hit = s_file_known(path);
    if (hit >= 0)
        return (unsigned)hit;
    if (s_nfiles == max_files || strlen(path) >= max_path) {
        fprintf(stderr, "layer_dag: file table full at %s\n", path);
        exit(2);
    }
    strcpy(s_files[s_nfiles], path);
    return s_nfiles++;
}

static int
s_ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}

/** @brief Collect every .c/.h under @p dir into the file table. */
static void
s_walk(const char *dir)
{
    char full[max_path];
    snprintf(full, sizeof full, "%s/%s", DUCT_LAYER_ROOT, dir);
    DIR *d = opendir(full);
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char rel[2 * max_path];
        int n = snprintf(rel, sizeof rel, "%s/%s", dir, e->d_name);
        if (n < 0 || (size_t)n >= sizeof rel)
            continue;
        /* d_name tops at NAME_MAX (255): full (≤ max_path-1) + '/' + name fits */
        char child[max_path + 256u];
        snprintf(child, sizeof child, "%s/%s", full, e->d_name);
        struct stat st;
        if (stat(child, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            s_walk(rel);
            continue;
        }
        if (!S_ISREG(st.st_mode) || !(s_ends_with(e->d_name, ".c") ||
                                      s_ends_with(e->d_name, ".h")))
            continue;
        s_file_add(rel);
    }
    closedir(d);
}

/** @brief Resolve one quoted include of @p from, or @c nullptr when it names
 *  nothing the law tracks (system headers never appear quoted here). */
static const char *
s_resolve(const char *from, const char *name)
{
    char cand[max_path];
    const char *slash = strrchr(from, '/');
    size_t dir_len = slash ? (size_t)(slash - from) + 1u : 0u;
    /* the includer's own directory first, then the header roots */
    if (dir_len + strlen(name) + 1u < sizeof cand) {
        memcpy(cand, from, dir_len);
        strcpy(cand + dir_len, name);
        if (s_file_known(cand) >= 0)
            return s_files[s_file_known(cand)];
    }
    static const char *const roots[] = { "include/", "src/include/", "os/include/" };
    for (unsigned r = 0u; r < sizeof roots / sizeof roots[0]; ++r) {
        if (strlen(roots[r]) + strlen(name) + 1u >= sizeof cand)
            continue;
        snprintf(cand, sizeof cand, "%s%s", roots[r], name);
        if (s_file_known(cand) >= 0)
            return s_files[s_file_known(cand)];
    }
    /* same basename in exactly one tracked file (the per-OS contract pattern) */
    const char *base = strrchr(name, '/');
    base = base ? base + 1 : name;
    const char *hit = nullptr;
    unsigned hits = 0u;
    for (unsigned i = 0u; i < s_nfiles; ++i)
        if (strcmp(s_base(s_files[i]), base) == 0) {
            hit = s_files[i];
            ++hits;
        }
    return hits == 1u ? hit : nullptr;
}

/** @brief Record the quoted include on @p line, if it is one, from @p from. */
static void
s_add_include(const char *from, const char *line)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t')
        ++p;
    if (*p != '#')
        return;
    for (++p; *p == ' ' || *p == '\t'; ++p)
        ;
    if (strncmp(p, "include", 7u) != 0)
        return;
    for (p += 7u; *p == ' ' || *p == '\t'; ++p)
        ;
    if (*p != '"')
        return;
    char name[max_path];
    unsigned n = 0u;
    for (++p; *p && *p != '"' && n + 1u < sizeof name; ++p)
        name[n++] = *p;
    if (*p != '"')
        return;
    name[n] = '\0';
    const char *to = s_resolve(from, name);
    if (!to)
        return;
    unsigned f = (unsigned)s_file_known(from), t = (unsigned)s_file_known(to);
    if (f == t)
        return;
    for (unsigned i = 0u; i < s_nedges; ++i)
        if (s_edges[i].from == f && s_edges[i].to == t)
            return;
    if (s_nedges == max_incs) {
        fprintf(stderr, "layer_dag: edge table full\n");
        exit(2);
    }
    s_edges[s_nedges].from = f;
    s_edges[s_nedges].to = t;
    ++s_nedges;
}

static void
s_read_includes(const char *from)
{
    char full[max_path];
    snprintf(full, sizeof full, "%s/%s", DUCT_LAYER_ROOT, from);
    FILE *f = fopen(full, "rb");
    if (!f)
        return;
    char line[2048];
    while (fgets(line, sizeof line, f))
        if (strchr(line, '#'))
            s_add_include(from, line);
    fclose(f);
}

/** @brief Tarjan state; the graph is small enough for the recursive form. */
static int s_index[max_files];
static int s_low[max_files];
static unsigned s_stack[max_files];
static unsigned s_stack_n;
static char s_onstack[max_files];
static unsigned s_adj_head[max_files];
static struct { unsigned to, next; } s_adj[max_incs];
static unsigned s_tarjan_counter;
static unsigned s_sccs;

static void
s_dfs(unsigned v)
{
    s_index[v] = s_low[v] = (int)s_tarjan_counter++;
    s_stack[s_stack_n++] = v;
    s_onstack[v] = 1;
    for (unsigned a = s_adj_head[v]; a != no_edge; a = s_adj[a].next) {
        unsigned w = s_adj[a].to;
        if (s_index[w] < 0) {
            s_dfs(w);
            if (s_low[w] < s_low[v])
                s_low[v] = s_low[w];
        } else if (s_onstack[w] && s_index[w] < s_low[v]) {
            s_low[v] = s_index[w];
        }
    }
    if (s_low[v] == s_index[v]) {
        unsigned size = 0u, w;
        do {
            w = s_stack[--s_stack_n];
            s_onstack[w] = 0;
            ++size;
        } while (w != v);
        if (size > 1u) {
            ++s_sccs;
            printf("layer_dag: cycle of %u files rooted at %s\n", size, s_files[v]);
        }
    }
}

int
main(void)
{
    s_walk("include");
    s_walk("src");
    s_walk("os");

    for (unsigned i = 0u; i < s_nfiles; ++i)
        s_read_includes(s_files[i]);

    /* the layering law: consumer at or above provider, or sanctioned */
    unsigned bad = 0u;
    for (unsigned e = 0u; e < s_nedges; ++e) {
        const char *from = s_files[s_edges[e].from];
        const char *to = s_files[s_edges[e].to];
        unsigned tf = s_tier(from), tt = s_tier(to);
        if (tf >= tt || s_edge_sanctioned(from, to))
            continue;
        printf("layer_dag: %s (%s) -> %s (%s): consumer below provider\n",
               from, s_tier_name[tf], to, s_tier_name[tt]);
        ++bad;
    }

    /* the acyclicity half: Tarjan over the whole resolved graph */
    for (unsigned i = 0u; i < max_files; ++i) {
        s_adj_head[i] = no_edge;
        s_index[i] = -1;
    }
    for (unsigned e = 0u; e < s_nedges; ++e) {
        s_adj[e].to = s_edges[e].to;
        s_adj[e].next = s_adj_head[s_edges[e].from];
        s_adj_head[s_edges[e].from] = e;
    }
    for (unsigned v = 0u; v < s_nfiles; ++v)
        if (s_index[v] < 0)
            s_dfs(v);

    printf("layer_dag: %u files, %u edges, %u layering violations, %u sccs\n",
           s_nfiles, s_nedges, bad, s_sccs);
    return bad == 0u && s_sccs == 0u ? 0 : 1;
}

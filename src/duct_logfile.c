/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_logfile.c
 *  @brief The file sink: the open, the line's fan-out and the self-removal on a refused write.
 *
 *  One carrier, two fields: the slot logger, the append file. A line runs a write to the
 *  file, its flush, then one fwrite to the stream the call named; a sink whose open was
 *  refused hands the line to that stream alone. A refusal on the file way takes the sink
 *  out of the slot, gives the line whole to the call's stream and says the file's fate
 *  through @c duct_diag, the file staying open for the fini.
 */

#include "duct_logfile.h"

#include "duct_file.h"

/** @brief One finished line of @c duct_log, run through the file and the stream of the call.
 *  The file way is a write and its flush: the default buffer of @c duct_file exceeds a cut
 *  line, so a refusal surfaces at the flush, and the two arms are the one fatal edge. The
 *  fatal order: the slot's compare-and-swap — of several threads in flight the first takes
 *  the sink out and the rest pass — then the line whole to the stream the call named, then
 *  one @c duct_diag on the file's fate, out through the emptied slot raw to @c stderr. The
 *  file stays open: closing belongs to duct_logfile_fini on the host's thread.
 */
static void s_write(void *ctx, FILE *out, const char *line, size_t len)
{
    auto sink = (duct_logfile_t *)ctx;
    if (!sink->file) {
        duct_discard fwrite(line, 1u, len, out);
        return;
    }
    bool fatal = duct_file_write(sink->file, line, len) != rc_ok
              || duct_file_flush(sink->file) != rc_ok;
    if (fatal)
        duct_logger_fini(&sink->logger);
    duct_discard fwrite(line, 1u, len, out);
    if (fatal)
        duct_diag("log file: the writes keep failing, the file sink removed itself");
}

bool duct_logfile_init(duct_logfile_t *sink, const char *path)
{
    sink->logger = (duct_logger_t){ .write = s_write, .ctx = sink };
    sink->file = duct_file_open(path, duct_file_app);
    return sink->file != nullptr;
}

void duct_logfile_fini(duct_logfile_t *sink)
{
    duct_logger_fini(&sink->logger);
    duct_file_close(sink->file);
    sink->file = nullptr;
}

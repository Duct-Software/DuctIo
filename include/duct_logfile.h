/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_logfile.h
 *  @brief The engine log's file arm: a file sink over the process's logger slot, and the
 *  resolver of the platform's default log directory.
 *
 *  The host opens the file at boot, installs the sink as the process's logger and names the
 *  product's name; @c duct_log then hands the sink every finished line of the process through
 *  the slot, the stream of the call beside it, and the sink writes the line to the file and to
 *  that stream. The file grows by append across runs.
 *
 *  The process holds one logger slot: the sink occupies it for its whole stand, and a
 *  second install by the host displaces it. The file closes in @ref duct_logfile_fini, on
 *  the host's thread, once the slot has let the sink go.
 */

#ifndef DUCT_LOGFILE_H
#define DUCT_LOGFILE_H

#include "duct_core.h"

struct duct_file;
typedef struct duct_file duct_file_t;

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Carrier of the file arm: the slot logger and the append file, one object the host
 *  keeps for the whole stand.
 */
typedef struct {
    duct_logger_t logger; /**< The logger the slot stores: @c write is the sink's function, @c ctx the sink itself. */
    duct_file_t  *file;   /**< The file open for append; null before the open and after the close. */
} duct_logfile_t;

/** @brief Open @p path for append and ready @p sink for the install.
 *  The file comes into being at this call, ahead of the install: a host that leaves after
 *  printing its usage leaves the file behind. While the sink stands in the slot, every line
 *  goes to the file and to the stream its call named; with the open refused, @c file stays
 *  null and a sink installed anyway hands every line to its stream alone.
 *  @return true with the file open, the host installing @p sink through @c duct_logger_init
 *          on @c sink->logger; false with the open refused, @c sink->file null and
 *          @c duct_logfile_fini safe to call — the host tells the file's fate through
 *          @c duct_diag ahead of the install and runs console-only.
 */
[[nodiscard]] duct_nonnull(1, 2) bool duct_logfile_init(duct_logfile_t *sink, const char *path);

/** @brief Take @p sink out of the logger slot and close its file.
 *  The slot empties first: lines after it reach the raw stream again, and a thread already
 *  inside the write finishes its line against the file still open. The host stops the
 *  threads that log ahead of the call. The call repeats safely: a sink out of the slot or
 *  with a refused open closes a null handle.
 */
duct_nonnull(1) void duct_logfile_fini(duct_logfile_t *sink);

/** @brief Fill @p buf with the platform's default directory for @p product and make it.
 *  The directory stands one level under the platform's base: @c %LOCALAPPDATA% on Windows,
 *  @c %ProgramData% behind it for a service or a system account; @c $XDG_STATE_HOME on
 *  Linux, @c $HOME/.local/state behind it, @c /var/log for the system context;
 *  @c $HOME/Library/Logs on darwin, the sandbox container on iOS. A standing directory
 *  is the answer. Android leaves the naming to the host: the call answers false there.
 *  @return true with the product directory in @p buf, the host appending @c .log and the
 *          file name; false with the platform's variables empty or the directory refused —
 *          the host passes an explicit path or runs console-only, its diag naming the loss
 *          without a path.
 */
[[nodiscard]] duct_nonnull(1, 3) bool duct_logfile_default_dir(char *buf, size_t cap, const char *product);

#ifdef __cplusplus
}
#endif

#endif

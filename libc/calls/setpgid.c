/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include "libc/calls/calls.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/intrin/pgrp.h"
#include "libc/intrin/weaken.h"
#include "libc/proc/proc.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/thread/tls.h"

// a process group is bookkeeping here: our own lives in the pib and goes
// through execve(), a child's is kept in its process table entry
static int sys_setpgid_nt(int pid, int pgid) {
  struct CosmoPib *pib = __get_pib();
  if (!pid || pid == pib->pid) {
    pib->pgid = pgid ? pgid : pib->pid;
    if (_weaken(__pgrp_self_set))
      _weaken(__pgrp_self_set)(pib->pgid);
    // a vfork()'d child's table entry is its own to update
    if (__get_tls_win32()->tib_vfork && pib->proc)
      pib->proc->pgid = pib->pgid;
    return 0;
  }
  if (_weaken(__proc_setpgid) && !_weaken(__proc_setpgid)(pid, pgid))
    return 0;
  return esrch();
}

/**
 * Changes process group for process.
 *
 * @param pid is process id (may be zero for current process)
 * @param pgid is process group id (may be zero for current process)
 * @return 0 on success, or -1 w/ errno
 * @vforksafe
 */
int setpgid(int pid, int pgid) {
  int rc;
  if (!IsWindows() && !IsMetal()) {
    rc = sys_setpgid(pid, pgid);
  } else if (IsWindows()) {
    rc = sys_setpgid_nt(pid, pgid);
  } else {
    rc = 0;
  }
  STRACE("setpgid(%d, %d) → %d% m", pid, pgid, rc);
  return rc;
}

/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2020 Justine Alexandra Roberts Tunney                              │
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
#include "libc/calls/internal.h"
#include "libc/calls/syscall-nt.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/intrin/fds.h"
#include "libc/nt/enum/filelockflags.h"
#include "libc/nt/files.h"
#include "libc/nt/errors.h"
#include "libc/nt/events.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/overlapped.h"
#include "libc/sysv/consts/lock.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

// flock() covers the whole file however long it is or becomes, so lock
// every byte there could ever be rather than the current size (which
// locks nothing at all on an empty file)
#define _LOCK_LEN 0xffffffffu

textwindows static bool32 sys_flock_nt_wait(int64_t h, bool32 ok,
                                            struct NtOverlapped *ov) {
  uint32_t exchanged;
  if (!ok && GetLastError() == kNtErrorIoPending)
    ok = true;
  if (ok)
    ok = GetOverlappedResult(h, ov, &exchanged, true);
  return ok;
}

textwindows int sys_flock_nt(int fd, int op) {
  int64_t h;
  bool32 ok;
  if (!__isfdkind(fd, kFdFile))
    return ebadf();
  h = __get_pib()->fds.p[fd].handle;

  uint32_t flags = 0;
  if (op & LOCK_UN) {
    if (op & ~LOCK_UN)
      return einval();
  } else {
    if (op & ~(LOCK_SH | LOCK_EX | LOCK_NB))
      return einval();
    if (!(op & LOCK_SH) == !(op & LOCK_EX))
      return einval();
    if (op & LOCK_EX)
      flags |= kNtLockfileExclusiveLock;
    if (op & LOCK_NB)
      flags |= kNtLockfileFailImmediately;
  }

  // a lock request replaces whatever lock this handle holds, which is
  // how a shared lock gets converted to an exclusive one and back
  intptr_t event = CreateEventTls();
  struct NtOverlapped ov = {.hEvent = event};
  ok = sys_flock_nt_wait(
      h, UnlockFileEx(h, 0, _LOCK_LEN, _LOCK_LEN, &ov), &ov);
  if (!ok && GetLastError() == kNtErrorNotLocked)
    ok = true;
  if (ok && !(op & LOCK_UN)) {
    ov = (struct NtOverlapped){.hEvent = event};
    ok = sys_flock_nt_wait(
        h, LockFileEx(h, flags, 0, _LOCK_LEN, _LOCK_LEN, &ov), &ov);
  }
  CloseEventTls(event);
  return ok ? 0 : __winerr();
}

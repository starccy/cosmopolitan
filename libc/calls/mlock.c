/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2023 Justine Alexandra Roberts Tunney                              │
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
#include "libc/atomic.h"
#include "libc/intrin/atomic.h"
#include "libc/calls/calls.h"
#include "libc/calls/syscall_support-sysv.internal.h"
#include "libc/thread/thread.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/nt/memory.h"
#include "libc/runtime/runtime.h"

static textwindows int sys_mlock_nt(const void *addr, size_t len) {
  if (VirtualLock(addr, len)) {
    return 0;
  } else {
    return __winerr();
  }
}

/**
 * Locks virtual memory interval into RAM, preventing it from swapping.
 *
 * @return 0 on success, or -1 w/ errno
 */
int mlock(const void *addr, size_t len) {
  int rc;
  if (!IsWindows()) {
    rc = sys_mlock(addr, len);
  } else {
    rc = sys_mlock_nt(addr, len);
  }
  if (!rc && !IsLinux())
    __mlock_count(addr, len, true);
  return rc;
}

// what this process has locked, for the VmLck line of its
// /proc/self/status off linux: the kernels keep no count. the ranges
// are kept, since locking pages twice locks them once
atomic_size_t __mlocked_bytes;

struct LockedRange {
  size_t beg, end;
};

// a fixed table, since this package can't allocate; a 65th range is
// not counted
static struct LockedRange g_locked[64];
static int g_nlocked;
static const int g_caplocked = 64;
static pthread_mutex_t g_lockedlock = PTHREAD_MUTEX_INITIALIZER;

static void locked_total(void) {
  size_t n = 0;
  for (int i = 0; i < g_nlocked; ++i)
    n += g_locked[i].end - g_locked[i].beg;
  atomic_store_explicit(&__mlocked_bytes, n, memory_order_relaxed);
}

// takes [beg, end) out of the ranges, splitting one it falls inside
static void locked_cut(size_t beg, size_t end) {
  for (int i = 0; i < g_nlocked;) {
    struct LockedRange *r = &g_locked[i];
    if (end <= r->beg || beg >= r->end) {
      ++i;
    } else if (beg <= r->beg && end >= r->end) {
      *r = g_locked[--g_nlocked];
    } else if (beg > r->beg && end < r->end) {
      if (g_nlocked < g_caplocked)
        g_locked[g_nlocked++] = (struct LockedRange){end, r->end};
      r->end = beg;
      ++i;
    } else if (beg <= r->beg) {
      r->beg = end;
      ++i;
    } else {
      r->end = beg;
      ++i;
    }
  }
}

void __mlock_count(const void *addr, size_t len, bool on) {
  size_t beg = (uintptr_t)addr & -__pagesize;
  size_t end = ((uintptr_t)addr + len + __pagesize - 1) & -__pagesize;
  pthread_mutex_lock(&g_lockedlock);
  locked_cut(beg, end);
  if (on && g_nlocked < g_caplocked)
    g_locked[g_nlocked++] = (struct LockedRange){beg, end};
  locked_total();
  pthread_mutex_unlock(&g_lockedlock);
}

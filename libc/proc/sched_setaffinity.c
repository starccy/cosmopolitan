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
#include "libc/calls/sched-sysv.internal.h"
#include "libc/calls/struct/cpuset.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/cosmo.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/nt/errors.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/proc/proc.h"
#include "libc/str/str.h"
#include "libc/sysv/errfuns.h"

static dontinline textwindows int sys_sched_setaffinity_nt(
    int pid, uint64_t size, const cpu_set_t *bitset) {
  int64_t handle;
  if (!(handle = __proc_handle(pid))) {
    return esrch();
  }
  if (SetProcessAffinityMask(handle, bitset->__bits[0])) {
    return 0;
  } else if (GetLastError() == kNtErrorInvalidHandle) {
    return esrch();
  } else {
    return __winerr();
  }
}

// XNU can't pin threads to CPUs. A mask that allows every CPU asks for
// nothing and is accepted, so what getaffinity reports can be set back
static int sys_setaffinity_xnu(const cpu_set_t *bitset) {
  bool any = false, all = true;
  int n = cosmo_cpu_count();
  for (int i = 0; i < n && i < CPU_SETSIZE; ++i) {
    if (CPU_ISSET(i, bitset)) {
      any = true;
    } else {
      all = false;
    }
  }
  if (!any)
    return einval();
  if (!all)
    return enosys();
  return 0;
}

/**
 * Asks kernel to only schedule process on particular CPUs.
 *
 * Affinity masks are inherited across fork() and execve() boundaries.
 *
 * @param pid is the process or process id (or 0 for caller)
 * @param size is bytes in bitset, which should be `sizeof(cpuset_t)`
 * @return 0 on success, or -1 w/ errno
 * @raise ENOSYS if not Linux, FreeBSD, NetBSD, or Windows, except that on
 *     MacOS a mask holding every online CPU is accepted as a no-op
 * @see pthread_getaffinity_np() for threads
 */
static int sched_setaffinity_impl(int pid, size_t size,
                                  const cpu_set_t *bitset) {
  if (IsWindows())
    return sys_sched_setaffinity_nt(pid, size, bitset);
  if (IsXnu())
    return sys_setaffinity_xnu(bitset);
  if (IsFreebsd())
    return sys_sched_setaffinity_freebsd(CPU_LEVEL_WHICH, CPU_WHICH_PID, pid,
                                         32, bitset);
  if (IsNetbsd())
    return sys_sched_setaffinity_netbsd(P_ALL_LWPS, pid, 32, bitset);
  return sys_sched_setaffinity(pid, size, bitset);
}

int sched_setaffinity(int pid, size_t size, const cpu_set_t *bitset) {
  int rc;
  cpu_set_t cpuset;
  if (!size || (size & (sizeof(long) - 1))) {
    rc = einval();
  } else if (size == sizeof(cpu_set_t)) {
    rc = sched_setaffinity_impl(pid, size, bitset);
  } else if (size < sizeof(cpu_set_t)) {
    // CPU_ALLOC_SIZE() hands out only as many words as the cpu count
    // needs, and the kernel takes any word multiple, so widen it
    bzero(&cpuset, sizeof(cpuset));
    memcpy(&cpuset, bitset, size);
    rc = sched_setaffinity_impl(pid, sizeof(cpuset), &cpuset);
  } else {
    // a set for more cpus than we track is fine while it's empty up
    // there, since those are cpus we couldn't have reported either
    const char *tail = (const char *)bitset + sizeof(cpuset);
    size_t n = size - sizeof(cpuset);
    rc = 0;
    for (size_t i = 0; i < n; ++i)
      if (tail[i])
        rc = einval();
    if (!rc)
      rc = sched_setaffinity_impl(pid, sizeof(cpuset), bitset);
  }
  STRACE("sched_setaffinity(%d, %'zu, %p) → %d% m", pid, size, bitset, rc);
  return rc;
}

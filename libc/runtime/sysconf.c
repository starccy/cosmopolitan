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
#include "libc/runtime/sysconf.h"
#include "libc/calls/calls.h"
#include "libc/calls/struct/rlimit.h"
#include "libc/calls/struct/sysinfo.h"
#include "libc/calls/struct/sysinfo.internal.h"
#include "libc/cosmo.h"
#include "libc/dce.h"
#include "libc/intrin/maps.h"
#include "libc/limits.h"
#include "libc/macros.h"
#include "libc/runtime/clktck.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/sysconf.h"
#include "libc/stdio/stdio.h"
#include "libc/sysv/consts/_posix.h"
#include "libc/sysv/consts/auxv.h"
#include "libc/sysv/consts/iov.h"
#include "libc/sysv/consts/limits.h"
#include "libc/sysv/consts/ss.h"
#include "libc/sysv/errfuns.h"
#include "libc/thread/thread.h"

static long sysconf_getrlimit(int resource) {
  struct rlimit rl;
  if (getrlimit(resource, &rl) == -1)
    return -1;
  return MIN(rl.rlim_cur, LONG_MAX);
}

/**
 * Returns configuration value about system.
 *
 * Every `_SC_XXX` name in sysconf.h answers here. A name for an option
 * we don't have returns -1 without touching errno, which POSIX spells
 * "unsupported or indeterminate" and is how callers tell that apart
 * from the EINVAL raised for a name that isn't one of ours. The options
 * that are supported answer with the same `_POSIX_XXX` value the
 * headers define, so a compile-time and a runtime test agree.
 *
 * Some of the more interesting parameters:
 *
 * - `_SC_PAGESIZE` returns page size for mmap()
 * - `_SC_GRANSIZE` returns addr alignment for mmap()
 * - `_SC_CLK_TCK` returns number of clock ticks per second
 * - `_SC_ARG_MAX` will perform expensive rlimit calculations
 * - `_SC_SIGSTKSZ` returns recommended `SIGSTKSZ` for platform
 * - `_SC_MINSIGSTKSZ` returns size of kernel pushed signal frame
 * - `_SC_AVPHYS_PAGES` returns average physical memory pages
 * - `_SC_PHYS_PAGES` returns physical memory pages available
 * - `_SC_NPROCESSORS_ONLN` returns number of effective CPUs
 * - `_SC_CHILD_MAX` returns maximum number of processes
 * - `_SC_OPEN_MAX` returns maximum number of open files
 *
 * @return value on success, or -1 w/ errno
 * @raise EINVAL if `name` isn't valid
 */
long sysconf(int name) {
  switch (name) {

    // system parameters
    case _SC_CLK_TCK:
      return CLK_TCK;
    case _SC_PAGESIZE:
      return __pagesize;
    case _SC_GRANSIZE:
      return __gransize;
    case _SC_ARG_MAX:
      return __get_arg_max();
    case _SC_SIGSTKSZ:
      return __get_minsigstksz() + SIGSTKSZ;
    case _SC_MINSIGSTKSZ:
      return __get_minsigstksz();
    case _SC_CHILD_MAX:
      return sysconf_getrlimit(RLIMIT_NPROC);
    case _SC_OPEN_MAX:
      return sysconf_getrlimit(RLIMIT_NOFILE);
    case _SC_NPROCESSORS_CONF:
    case _SC_NPROCESSORS_ONLN:
      return cosmo_cpu_count();
    case _SC_PHYS_PAGES:
      return __get_phys_pages();
    case _SC_AVPHYS_PAGES:
      return __get_avphys_pages();
    case _SC_NGROUPS_MAX:
      return NGROUPS_MAX;
    case _SC_IOV_MAX:
      return IOV_MAX;
    case _SC_STREAM_MAX:
      return FOPEN_MAX;
    case _SC_ATEXIT_MAX:
      return INT_MAX;
    case _SC_NZERO:
      return NZERO;
    case _SC_SYMLOOP_MAX:
      return _POSIX_SYMLOOP_MAX;
    case _SC_HOST_NAME_MAX:
      return _POSIX_HOST_NAME_MAX;
    case _SC_LOGIN_NAME_MAX:
      return LOGIN_NAME_MAX;
    case _SC_TTY_NAME_MAX:
      return TTY_NAME_MAX;
    case _SC_TZNAME_MAX:
      return _POSIX_TZNAME_MAX;
    case _SC_GETGR_R_SIZE_MAX:
    case _SC_GETPW_R_SIZE_MAX:
      return 1024;
    case _SC_PASS_MAX:
      return 8192;

    // versions
    case _SC_VERSION:
      return _POSIX_VERSION;
    case _SC_2_VERSION:
    case _SC_2_C_BIND:
      return _POSIX2_VERSION;
    case _SC_XOPEN_VERSION:
      return _XOPEN_VERSION;

    // options we have
    case _SC_JOB_CONTROL:
    case _SC_SAVED_IDS:
    case _SC_REGEXP:
    case _SC_SHELL:
    case _SC_XOPEN_UNIX:
    case _SC_XOPEN_SHM:
    case _SC_V6_LP64_OFF64:
    case _SC_V7_LP64_OFF64:
    case _SC_XBS5_LP64_OFF64:
      return 1;
    case _SC_MAPPED_FILES:
      return _POSIX_MAPPED_FILES;
    case _SC_FSYNC:
      return _POSIX_FSYNC;
    case _SC_SYNCHRONIZED_IO:
    case _SC_MEMORY_PROTECTION:
    case _SC_ADVISORY_INFO:
    case _SC_CLOCK_SELECTION:
    case _SC_REALTIME_SIGNALS:
    case _SC_TIMERS:
      return _POSIX_VERSION;
    case _SC_MEMLOCK:
    case _SC_MEMLOCK_RANGE:
      return _POSIX_MEMLOCK_RANGE;
    case _SC_SEMAPHORES:
      return _POSIX_SEMAPHORES;
    case _SC_SHARED_MEMORY_OBJECTS:
      return _POSIX_SHARED_MEMORY_OBJECTS;
    case _SC_SPAWN:
      return _POSIX_SPAWN;
    case _SC_IPV6:
      return _POSIX_IPV6;
    case _SC_RAW_SOCKETS:
      return _POSIX_VERSION;
    case _SC_MONOTONIC_CLOCK:
      return _POSIX_MONOTONIC_CLOCK;
    case _SC_CPUTIME:
      return _POSIX_CPUTIME;
    case _SC_BARRIERS:
      return _POSIX_BARRIERS;
    case _SC_SPIN_LOCKS:
      return _POSIX_SPIN_LOCKS;
    case _SC_READER_WRITER_LOCKS:
      return _POSIX_READER_WRITER_LOCKS;
    case _SC_TIMEOUTS:
      return _POSIX_TIMEOUTS;

    // threads
    case _SC_THREADS:
      return _POSIX_THREADS;
    case _SC_THREAD_SAFE_FUNCTIONS:
      return _POSIX_THREAD_SAFE_FUNCTIONS;
    case _SC_THREAD_ATTR_STACKADDR:
      return _POSIX_THREAD_ATTR_STACKADDR;
    case _SC_THREAD_ATTR_STACKSIZE:
      return _POSIX_THREAD_ATTR_STACKSIZE;
    case _SC_THREAD_PRIORITY_SCHEDULING:
      return _POSIX_THREAD_PRIORITY_SCHEDULING;
    case _SC_THREAD_PROCESS_SHARED:
      return _POSIX_THREAD_PROCESS_SHARED;
    case _SC_THREAD_CPUTIME:
      return _POSIX_THREAD_CPUTIME;
    case _SC_THREAD_DESTRUCTOR_ITERATIONS:
      return PTHREAD_DESTRUCTOR_ITERATIONS;
    case _SC_THREAD_KEYS_MAX:
      return PTHREAD_KEYS_MAX;
    case _SC_THREAD_STACK_MIN:
      return PTHREAD_STACK_MIN;
    case _SC_THREAD_THREADS_MAX:
      return LONG_MAX;

    // posix.2 utility limits
    case _SC_LINE_MAX:
      return _POSIX2_LINE_MAX;
    case _SC_RE_DUP_MAX:
      return _POSIX2_RE_DUP_MAX;
    case _SC_COLL_WEIGHTS_MAX:
      return _POSIX2_COLL_WEIGHTS_MAX;
    case _SC_EXPR_NEST_MAX:
      return _POSIX2_EXPR_NEST_MAX;
    case _SC_BC_BASE_MAX:
      return _POSIX2_BC_BASE_MAX;
    case _SC_BC_DIM_MAX:
      return _POSIX2_BC_DIM_MAX;
    case _SC_BC_SCALE_MAX:
      return _POSIX2_BC_SCALE_MAX;
    case _SC_BC_STRING_MAX:
      return _POSIX2_BC_STRING_MAX;

    // realtime signals and timers
    case _SC_RTSIG_MAX:
      return NSIG - 32;
    case _SC_SIGQUEUE_MAX:
      return _POSIX_SIGQUEUE_MAX;
    case _SC_DELAYTIMER_MAX:
      return _POSIX_DELAYTIMER_MAX;
    case _SC_SEM_VALUE_MAX:
      return SEM_VALUE_MAX;

    // options we don't have. -1 without errno says so
    case _SC_AIO_LISTIO_MAX:
    case _SC_AIO_MAX:
    case _SC_AIO_PRIO_DELTA_MAX:
    case _SC_ASYNCHRONOUS_IO:
    case _SC_MESSAGE_PASSING:
    case _SC_MQ_OPEN_MAX:
    case _SC_MQ_PRIO_MAX:
    case _SC_PRIORITIZED_IO:
    case _SC_PRIORITY_SCHEDULING:
    case _SC_SEM_NSEMS_MAX:
    case _SC_SPORADIC_SERVER:
    case _SC_SS_REPL_MAX:
    case _SC_STREAMS:
    case _SC_THREAD_PRIO_INHERIT:
    case _SC_THREAD_PRIO_PROTECT:
    case _SC_THREAD_ROBUST_PRIO_INHERIT:
    case _SC_THREAD_ROBUST_PRIO_PROTECT:
    case _SC_THREAD_SPORADIC_SERVER:
    case _SC_TIMER_MAX:
    case _SC_TRACE:
    case _SC_TRACE_EVENT_FILTER:
    case _SC_TRACE_EVENT_NAME_MAX:
    case _SC_TRACE_INHERIT:
    case _SC_TRACE_LOG:
    case _SC_TRACE_NAME_MAX:
    case _SC_TRACE_SYS_MAX:
    case _SC_TRACE_USER_EVENT_MAX:
    case _SC_TYPED_MEMORY_OBJECTS:
    case _SC_V6_ILP32_OFF32:
    case _SC_V6_ILP32_OFFBIG:
    case _SC_V6_LPBIG_OFFBIG:
    case _SC_V7_ILP32_OFF32:
    case _SC_V7_ILP32_OFFBIG:
    case _SC_V7_LPBIG_OFFBIG:
    case _SC_XBS5_ILP32_OFF32:
    case _SC_XBS5_ILP32_OFFBIG:
    case _SC_XBS5_LPBIG_OFFBIG:
    case _SC_XOPEN_CRYPT:
    case _SC_XOPEN_ENH_I18N:
    case _SC_XOPEN_LEGACY:
    case _SC_XOPEN_REALTIME:
    case _SC_XOPEN_REALTIME_THREADS:
    case _SC_XOPEN_STREAMS:
    case _SC_XOPEN_XCU_VERSION:
    case _SC_XOPEN_XPG2:
    case _SC_XOPEN_XPG3:
    case _SC_XOPEN_XPG4:
    case _SC_2_CHAR_TERM:
    case _SC_2_C_DEV:
    case _SC_2_FORT_DEV:
    case _SC_2_FORT_RUN:
    case _SC_2_LOCALEDEF:
    case _SC_2_PBS:
    case _SC_2_PBS_ACCOUNTING:
    case _SC_2_PBS_CHECKPOINT:
    case _SC_2_PBS_LOCATE:
    case _SC_2_PBS_MESSAGE:
    case _SC_2_PBS_TRACK:
    case _SC_2_SW_DEV:
    case _SC_2_UPE:
      return -1;

    default:
      return einval();
  }
}

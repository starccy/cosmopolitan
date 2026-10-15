#include "libc/calls/calls.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/struct/timespec.internal.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/fmt/wintime.internal.h"
#include "libc/intrin/strace.h"
#include "libc/nt/accounting.h"
#include "libc/nt/enum/processaccess.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/proc/proc.h"
#include "libc/runtime/syslib.internal.h"
#include "libc/sysv/consts/clock.h"
#include "libc/sysv/errfuns.h"
#include "libc/atomic.h"

// Linux's CPU clock of a process: pid in the upper bits, CPUCLOCK_SCHED
// below. The same ids are handed out on the other hosts, where
// clock_gettime() routes them here.
#define CPUCLOCK_SCHED 2
#define CPUCLOCK_MASK  7
#define PROCESS_CPUCLOCK(pid) ((~(pid) << 3) | CPUCLOCK_SCHED)
#define CPUCLOCK_PID(clock) (~((clock) >> 3))

#define XNU_RTLD_NOW        2
#define XNU_PROC_PIDTASKINFO 4

struct XnuTaskInfo {
  uint64_t pti_virtual_size;
  uint64_t pti_resident_size;
  uint64_t pti_total_user;
  uint64_t pti_total_system;
  uint64_t pti_threads_user;
  uint64_t pti_threads_system;
  int32_t pti_policy;
  int32_t pti_faults;
  int32_t pti_pageins;
  int32_t pti_cow_faults;
  int32_t pti_messages_sent;
  int32_t pti_messages_received;
  int32_t pti_syscalls_mach;
  int32_t pti_syscalls_unix;
  int32_t pti_csw;
  int32_t pti_threadnum;
  int32_t pti_numrunning;
  int32_t pti_priority;
};

struct XnuTimebase {
  uint32_t numer, denom;
};

static struct {
  atomic_int state;  // 0 untouched, 1 loading, 2 done
  int (*pidinfo)(int, int, uint64_t, void *, int);
  struct XnuTimebase tb;
} g_xnu;

static void XnuInit(void) {
  int want = 0;
  if (!atomic_compare_exchange_strong(&g_xnu.state, &want, 1)) {
    while (atomic_load_explicit(&g_xnu.state, memory_order_acquire) != 2)
      ;
    return;
  }
  if (!IsXnuSilicon() || !__syslib || __syslib->__version < 6) {
    atomic_store_explicit(&g_xnu.state, 2, memory_order_release);
    return;
  }
  void *h = __syslib->__dlopen("/usr/lib/libSystem.B.dylib", XNU_RTLD_NOW);
  int (*timebase)(struct XnuTimebase *) =
      h ? __syslib->__dlsym(h, "mach_timebase_info") : 0;
  if (timebase && !timebase(&g_xnu.tb) && g_xnu.tb.denom)
    g_xnu.pidinfo = __syslib->__dlsym(h, "proc_pidinfo");
  atomic_store_explicit(&g_xnu.state, 2, memory_order_release);
}

// -errno, with the time in ts unless it's null
static int XnuProcessTime(int pid, struct timespec *ts) {
  struct XnuTaskInfo ti;
  XnuInit();
  if (!g_xnu.pidinfo)
    return -ENOSYS;
  int e = errno;
  int got = g_xnu.pidinfo(pid, XNU_PROC_PIDTASKINFO, 0, &ti, sizeof(ti));
  if (got != sizeof(ti)) {
    int err = got <= 0 && errno != e ? errno : ESRCH;
    errno = e;
    return -err;
  }
  if (ts) {
    uint64_t ticks = ti.pti_total_user + ti.pti_total_system;
    uint64_t nanos = ticks * g_xnu.tb.numer / g_xnu.tb.denom;
    *ts = timespec_fromnanos(nanos);
  }
  return 0;
}

static int NtProcessTime(int pid, struct timespec *ts) {
  struct NtFileTime ftExit, ftUser, ftKernel, ftCreation;
  int64_t h = __proc_handle(pid), closeme = 0;
  if (!h) {
    if (!(h = OpenProcess(kNtProcessQueryLimitedInformation, false, pid)))
      return -ESRCH;
    closeme = h;
  }
  int rc = 0;
  // a handle we still hold keeps the times of a process that's gone
  if (!GetProcessTimes(h, &ftCreation, &ftExit, &ftKernel, &ftUser) ||
      ReadFileTime(ftExit)) {
    rc = -ESRCH;
  } else if (ts) {
    *ts = WindowsDurationToTimeSpec(ReadFileTime(ftUser) +
                                    ReadFileTime(ftKernel));
  }
  if (closeme)
    CloseHandle(closeme);
  return rc;
}

static int HostProcessTime(int pid, struct timespec *ts) {
  if (IsWindows())
    return NtProcessTime(pid, ts);
  if (IsXnu())
    return XnuProcessTime(pid, ts);
  return -ENOSYS;
}

/**
 * Reads the CPU clock of another process on Windows and XNU.
 *
 * @return 0 on success, or -errno
 */
int __clock_gettime_pid(int clock, struct timespec *ts) {
  if ((clock & CPUCLOCK_MASK) != CPUCLOCK_SCHED)
    return -EINVAL;
  int pid = CPUCLOCK_PID(clock);
  if (!pid || pid == getpid())
    return clock_gettime(CLOCK_PROCESS_CPUTIME_ID, ts) ? -errno : 0;
  return HostProcessTime(pid, ts);
}

/**
 * Returns clock id for the CPU time of a process.
 *
 * @param pid is a process id, or 0 for the calling process
 * @return 0 on success, or an errno number
 * @raise ESRCH if no such process
 * @raise EPERM if the process can't be looked at
 */
int clock_getcpuclockid(int pid, int *clock) {
  int rc;
  if (pid < 0) {
    rc = EINVAL;
  } else if (IsLinux()) {
    int clk = PROCESS_CPUCLOCK(pid);
    int e = errno;
    rc = sys_clock_getres(clk, 0);
    if (rc == -1) {
      rc = errno == EINVAL ? ESRCH : errno;
      errno = e;
    } else {
      *clock = clk;
    }
  } else if (!pid || pid == getpid()) {
    *clock = CLOCK_PROCESS_CPUTIME_ID;
    rc = 0;
  } else if ((rc = -HostProcessTime(pid, 0)) == ENOSYS) {
    int e = errno;
    rc = kill(pid, 0) == -1 && errno == ESRCH ? ESRCH : EPERM;
    errno = e;
  } else if (!rc) {
    *clock = PROCESS_CPUCLOCK(pid);
  }
  STRACE("clock_getcpuclockid(%d, [%d]) → %d", pid, rc ? 0 : *clock, rc);
  return rc;
}

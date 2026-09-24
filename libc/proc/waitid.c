#include "libc/calls/calls.h"
#include "libc/calls/cp.internal.h"
#include "libc/calls/struct/rusage.h"
#include "libc/calls/struct/siginfo-meta.internal.h"
#include "libc/calls/struct/siginfo.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/strace.h"
#include "libc/proc/proc.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/sicode.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/consts/w.h"
#include "libc/sysv/consts/waitid.h"
#include "libc/sysv/errfuns.h"

__HOSTCONST(int, WCONTINUED);
__HOSTCONST(int, WEXITED);
__HOSTCONST(int, WNOWAIT);
__HOSTCONST(int, WSTOPPED);

// the siginfo waitid hands back, built from a wait status
static void __wstatus2siginfo(int pid, int ws, siginfo_t *si) {
  *si = (siginfo_t){0};
  if (!pid)
    return;
  si->si_signo = SIGCHLD;
  si->si_pid = pid;
  si->si_uid = getuid();
  if (WIFSTOPPED(ws)) {
    si->si_code = CLD_STOPPED;
    si->si_status = WSTOPSIG(ws);
  } else if (WIFCONTINUED(ws)) {
    si->si_code = CLD_CONTINUED;
    si->si_status = SIGCONT;
  } else if (WIFEXITED(ws)) {
    si->si_code = CLD_EXITED;
    si->si_status = WEXITSTATUS(ws);
  } else {
    si->si_code = WCOREDUMP(ws) ? CLD_DUMPED : CLD_KILLED;
    si->si_status = WTERMSIG(ws);
  }
}

// for hosts without a waitid of their own (OpenBSD before 7.1). a status
// can't be looked at without reaping it there, so WNOWAIT is refused
static int __waitid_wait4(int idtype, int id, siginfo_t *infop, int options) {
  int pid;
  if (options & WNOWAIT)
    return einval();
  switch (idtype) {
    case P_ALL:
      pid = -1;
      break;
    case P_PID:
      pid = id;
      break;
    case P_PGID:
      pid = id ? -id : 0;
      break;
    default:
      return einval();
  }
  int wopts = options & WNOHANG;
  if (options & WSTOPPED)
    wopts |= WUNTRACED;
  if (options & WCONTINUED)
    wopts |= WCONTINUED;
  int ws = 0;
  int rc = wait4(pid, &ws, wopts, 0);
  if (rc == -1)
    return -1;
  if (infop)
    __wstatus2siginfo(rc, ws, infop);
  return 0;
}

static int __waitid_options2host(int options) {
  int res = options & WNOHANG;
  if (options & WEXITED)
    res |= __host_WEXITED;
  if (options & WSTOPPED) {
    res |= __host_WSTOPPED;
    // linux reports ptrace stops under WSTOPPED; the bsds want WTRAPPED
    if (IsFreebsd())
      res |= 32;
    else if (IsNetbsd())
      res |= 0x40;
    else if (IsOpenbsd())
      res |= 0x20;
  }
  if (options & WCONTINUED)
    res |= __host_WCONTINUED;
  if (options & WNOWAIT)
    res |= __host_WNOWAIT;
  return res;
}

static int __waitid_idtype2host(int idtype) {
  if (IsFreebsd()) {
    switch (idtype) {
      case P_PID:
        return 0;
      case P_PGID:
        return 2;
      default:
        return 7;
    }
  } else if (IsNetbsd()) {
    return idtype == P_PGID ? 4 : idtype;
  } else if (IsOpenbsd()) {
    switch (idtype) {
      case P_PID:
        return 2;
      case P_PGID:
        return 1;
      default:
        return 0;
    }
  }
  return idtype;
}

// XNU and OpenBSD have waitid, FreeBSD and NetBSD have wait6. all of them
// fill a siginfo in the host's layout
static int __waitid_host(int idtype, int id, siginfo_t *infop, int options) {
  union siginfo_meta m;
  int rc;
  int hostopts = __waitid_options2host(options);
  int hostid = __waitid_idtype2host(idtype);
  if (idtype == P_PGID && !id)
    id = getpgrp();
  memset(&m, 0, sizeof(m));
  if (IsXnu() || IsOpenbsd()) {
    rc = sys_waitid(hostid, id, &m, hostopts, 0);
    if (rc == -1 && errno == ENOSYS && IsOpenbsd())
      return __waitid_wait4(idtype, id, infop, options);
  } else {
    int ws;
    rc = sys_wait6(hostid, id, &ws, hostopts, 0, &m);
    if (rc == 0)
      memset(&m, 0, sizeof(m));
  }
  if (rc == -1)
    return -1;
  if (infop) {
    if (m.linux.si_signo) {
      __siginfo2cosmo(infop, &m);
    } else {
      // WNOHANG with nothing to report
      *infop = (siginfo_t){0};
    }
  }
  return 0;
}

/**
 * Waits for a child's state to change, POSIX style.
 *
 * @param idtype is P_ALL, P_PID or P_PGID (P_PIDFD on Linux only)
 * @param id is the pid or pgid `idtype` names, ignored for P_ALL
 * @param infop optionally receives who and what; with WNOHANG and nothing
 *     to report its `si_pid` and `si_signo` are zeroed
 * @param options picks the events with WEXITED, WSTOPPED and WCONTINUED
 *     (at least one), plus WNOHANG and WNOWAIT
 * @return 0 on success, or -1 w/ errno
 * @raise ECHILD if there's no child `idtype` and `id` could name
 * @raise EINVAL if `options` or `idtype` are bad
 * @cancelationpoint
 */
int waitid(int idtype, int id, siginfo_t *infop, int options) {
  int rc;
  BEGIN_CANCELATION_POINT;
  if (IsLinux()) {
    rc = sys_waitid(idtype, id, infop, options, 0);
  } else if ((options & ~(WNOHANG | WNOWAIT | WEXITED | WSTOPPED | WCONTINUED)) ||
             !(options & (WEXITED | WSTOPPED | WCONTINUED)) ||
             (idtype == P_PID && id <= 0) || (idtype == P_PGID && id < 0)) {
    rc = einval();
  } else if (IsWindows()) {
    int ws = 0;
    rc = sys_waitid_nt(idtype, id, &ws, options);
    if (rc != -1) {
      if (infop)
        __wstatus2siginfo(rc, ws, infop);
      rc = 0;
    }
  } else {
    rc = __waitid_host(idtype, id, infop, options);
  }
  END_CANCELATION_POINT;
  STRACE("waitid(%d, %d, %p, %#x) → %d% m", idtype, id, infop, options, rc);
  return rc;
}

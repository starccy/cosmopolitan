#include "libc/calls/calls.h"
#include "libc/calls/struct/rlimit.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/describeflags.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/errfuns.h"

/**
 * Gets and sets resource limits of a process.
 *
 * For the calling process this is getrlimit() and setrlimit(), on every
 * host. Another process can only be reached on Linux.
 *
 * @param pid is the process, or 0 for the calling one
 * @param newlim is installed after oldlim is read, if not null
 * @param oldlim receives the previous limit, if not null
 * @return 0 on success, or -1 w/ errno
 * @raise ENOSYS if pid is another process and the host isn't Linux
 */
int prlimit(int pid, int resource, const struct rlimit *newlim,
            struct rlimit *oldlim) {
  int rc;
  if (!pid || pid == getpid()) {
    rc = 0;
    if (oldlim)
      rc = getrlimit(resource, oldlim);
    if (!rc && newlim)
      rc = setrlimit(resource, newlim);
  } else if (IsLinux()) {
    rc = sys_prlimit(pid, resource, newlim, oldlim);
  } else {
    rc = enosys();
  }
  STRACE("prlimit(%d, %s, %p, %p) → %d% m", pid, DescribeRlimitName(resource),
         newlim, oldlim, rc);
  return rc;
}

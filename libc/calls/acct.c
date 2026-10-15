#include "libc/calls/calls.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/errfuns.h"

/**
 * Turns process accounting on or off.
 *
 * @param file is the accounting file, or NULL to turn it off
 * @return 0 on success, or -1 w/ errno
 * @raise ENOSYS on Windows
 */
int acct(const char *file) {
  int rc;
  if (IsWindows()) {
    rc = enosys();
  } else {
    rc = sys_acct(file);
  }
  STRACE("acct(%#s) → %d% m", file, rc);
  return rc;
}

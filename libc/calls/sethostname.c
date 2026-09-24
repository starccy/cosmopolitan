#include "libc/calls/calls.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/runtime/runtime.h"
#include "libc/sysv/errfuns.h"

/**
 * Changes the machine's host name.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise ENOSYS on Windows, MacOS, OpenBSD and NetBSD
 * @raise EPERM if not root
 */
int sethostname(const char *name, size_t len) {
  int rc;
  if (IsWindows()) {
    rc = enosys();
  } else {
    rc = sys_sethostname(name, len);
  }
  STRACE("sethostname(%#.*s, %'zu) → %d% m", (int)len, name, len, rc);
  return rc;
}

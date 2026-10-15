#include "libc/calls/mount.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/consts/unmount.h"
#include "libc/sysv/errfuns.h"

#define MNT_FORCE_linux 1

/**
 * Unmounts file system, with Linux flag values.
 *
 * `MNT_FORCE` is understood everywhere. `MNT_DETACH`, `MNT_EXPIRE` and
 * `UMOUNT_NOFOLLOW` only exist on Linux.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise EINVAL on BSDs when a Linux-only flag is given
 * @raise ENOSYS on Windows
 */
int umount2(const char *target, int flags) {
  int rc;
  if (IsLinux()) {
    rc = sys_umount2(target, flags);
  } else if (IsWindows()) {
    rc = enosys();
  } else if (flags & ~MNT_FORCE_linux) {
    rc = einval();
  } else {
    rc = sys_unmount(target, flags ? MNT_FORCE : 0);
  }
  STRACE("umount2(%#s, %#x) → %d% m", target, flags, rc);
  return rc;
}

/**
 * Unmounts file system.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise ENOSYS on Windows
 */
int umount(const char *target) {
  return umount2(target, 0);
}

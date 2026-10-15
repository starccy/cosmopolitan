#include "libc/calls/fanotify.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/errfuns.h"

/**
 * Creates a fanotify group.
 *
 * @return file descriptor on success, or -1 w/ errno
 * @raise ENOSYS if not Linux
 */
int fanotify_init(unsigned flags, unsigned event_f_flags) {
  int rc;
  if (IsLinux()) {
    rc = sys_fanotify_init(flags, event_f_flags);
  } else {
    rc = enosys();
  }
  STRACE("fanotify_init(%#x, %#x) → %d% m", flags, event_f_flags, rc);
  return rc;
}

/**
 * Adds, removes or flushes fanotify marks.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise ENOSYS if not Linux
 */
int fanotify_mark(int fd, unsigned flags, uint64_t mask, int dirfd,
                  const char *path) {
  int rc;
  if (IsLinux()) {
    rc = sys_fanotify_mark(fd, flags, mask, dirfd, path);
  } else {
    rc = enosys();
  }
  STRACE("fanotify_mark(%d, %#x, %#lx, %d, %#s) → %d% m", fd, flags, mask,
         dirfd, path, rc);
  return rc;
}

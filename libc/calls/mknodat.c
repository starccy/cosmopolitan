#include "libc/calls/fifo.internal.h"
#include "libc/intrin/weaken.h"
#include "libc/calls/calls.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-sysv.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/kprintf.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/s.h"
#include "libc/str/str.h"
#include "libc/sysv/errfuns.h"

/**
 * Creates filesystem inode relative to directory.
 *
 * @param mode is octal mode or'd with S_IFIFO, S_IFREG, S_IFDIR, etc.
 * @return 0 on success, or -1 w/ errno
 * @raise ENOSYS on Windows for anything but files and directories
 * @see mknod()
 */
int mknodat(int dirfd, const char *path, uint32_t mode, uint64_t dev) {
  int rc;
  if (kisdangerous(path)) {
    rc = efault();
  } else if (__is_evil_path(path)) {
    rc = eilseq();
  } else if ((mode & S_IFMT) == S_IFREG) {
    rc = openat(dirfd, path, O_WRONLY | O_CREAT | O_EXCL, mode & ~S_IFMT);
    if (rc != -1) {
      close(rc);
      rc = 0;
    }
  } else if ((mode & S_IFMT) == S_IFDIR) {
    rc = mkdirat(dirfd, path, mode & ~S_IFMT);
  } else if (!IsWindows()) {
    int e = errno;
    rc = sys_mknodat(__dirfd2host(dirfd), path, mode, dev);
    // xnu has only mknod(): a relative path is put after the directory
    // the descriptor names
    if (rc == -1 && errno == ENOSYS) {
      char full[2048];
      const char *p = path;
      if (dirfd != AT_FDCWD && *path != '/') {
        size_t n;
        if (__sys_fcntl(dirfd, 50, (uintptr_t)full) == -1)
          return -1;
        n = strlen(full);
        if (n + 1 + strlen(path) >= sizeof(full))
          return enametoolong();
        full[n] = '/';
        strcpy(full + n + 1, path);
        p = full;
      }
      errno = e;
      rc = sys_mknod(p, mode, dev);
    }
  } else if ((mode & S_IFMT) == S_IFIFO) {
    rc = __mkfifo_nt(dirfd, path, mode);
  } else {
    rc = enosys();
  }
  STRACE("mknodat(%d, %#s, %#o, %#lx) → %d% m", dirfd, path, mode, dev, rc);
  return rc;
}

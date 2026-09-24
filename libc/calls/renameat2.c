#include "libc/calls/calls.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/syscall-nt.internal.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-sysv.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/describeflags.h"
#include "libc/intrin/kprintf.h"
#include "libc/intrin/strace.h"
#include "libc/intrin/weaken.h"
#include "libc/limits.h"
#include "libc/runtime/zipos.internal.h"
#include "libc/stdio/rand.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/rename.h"
#include "libc/sysv/errfuns.h"

#define RENAME_SWAP_xnu 2
#define RENAME_EXCL_xnu 4

// The "fail if the target exists" rename, built from a hard link and an
// unlink. Names that can't be hard linked (directories, and filesystems
// without links) get a stat then a plain rename, which leaves a window.
static int RenameNoReplace(int olddirfd, const char *oldpath, int newdirfd,
                           const char *newpath) {
  struct stat st;
  if (!linkat(olddirfd, oldpath, newdirfd, newpath, 0)) {
    if (unlinkat(olddirfd, oldpath, 0) == -1) {
      int e = errno;
      unlinkat(newdirfd, newpath, 0);
      errno = e;
      return -1;
    }
    return 0;
  }
  if (errno == EEXIST)
    return -1;
  if (!fstatat(newdirfd, newpath, &st, AT_SYMLINK_NOFOLLOW))
    return eexist();
  if (errno != ENOENT)
    return -1;
  return renameat(olddirfd, oldpath, newdirfd, newpath);
}

// Swaps two names through a third one next to the second. Three renames,
// so a crash or a failure in the middle can leave the temporary name in
// place; each step is undone as far as it can be when a later one fails.
static int RenameExchange(int olddirfd, const char *oldpath, int newdirfd,
                          const char *newpath) {
  int e;
  struct stat st;
  char tmp[PATH_MAX];
  if (fstatat(olddirfd, oldpath, &st, AT_SYMLINK_NOFOLLOW) == -1)
    return -1;
  if (fstatat(newdirfd, newpath, &st, AT_SYMLINK_NOFOLLOW) == -1)
    return -1;
  if (ksnprintf(tmp, sizeof(tmp), "%s.%lx~", newpath, _rand64()) >=
      sizeof(tmp))
    return enametoolong();
  if (renameat(newdirfd, newpath, newdirfd, tmp) == -1)
    return -1;
  if (renameat(olddirfd, oldpath, newdirfd, newpath) == -1) {
    e = errno;
    renameat(newdirfd, tmp, newdirfd, newpath);
    errno = e;
    return -1;
  }
  if (renameat(newdirfd, tmp, olddirfd, oldpath) == -1) {
    e = errno;
    if (!renameat(newdirfd, newpath, olddirfd, oldpath))
      renameat(newdirfd, tmp, newdirfd, newpath);
    errno = e;
    return -1;
  }
  return 0;
}

static int RenameEmulated(int olddirfd, const char *oldpath, int newdirfd,
                          const char *newpath, unsigned flags) {
  if (flags & RENAME_EXCHANGE) {
    return RenameExchange(olddirfd, oldpath, newdirfd, newpath);
  } else {
    return RenameNoReplace(olddirfd, oldpath, newdirfd, newpath);
  }
}

static int RenameXnu(int olddirfd, const char *oldpath, int newdirfd,
                     const char *newpath, unsigned flags) {
  int rc;
  unsigned xflags = 0;
  if (flags & RENAME_NOREPLACE)
    xflags |= RENAME_EXCL_xnu;
  if (flags & RENAME_EXCHANGE)
    xflags |= RENAME_SWAP_xnu;
  rc = sys_renameatx_np(__dirfd2host(olddirfd), oldpath,
                        __dirfd2host(newdirfd), newpath, xflags);
  if (rc == -1 && (errno == ENOTSUP || errno == ENOSYS))
    rc = RenameEmulated(olddirfd, oldpath, newdirfd, newpath, flags);
  return rc;
}

/**
 * Renames files relative to directories, with flags.
 *
 * With no flags this is renameat(). `RENAME_NOREPLACE` makes the call
 * fail with EEXIST rather than replace an existing `newpath`, and
 * `RENAME_EXCHANGE` swaps the two names, both of which must exist.
 * `RENAME_WHITEOUT` is Linux only.
 *
 * Linux and MacOS do the flags in the kernel (renameat2, renameatx_np)
 * and the rename stays atomic. Elsewhere, and on filesystems that turn
 * the flags down, they're built from other calls: `RENAME_NOREPLACE` is
 * linkat() plus unlinkat() where the name can be hard linked, and a
 * stat followed by renameat() where it can't (directories, FAT, and
 * everything on Windows, where MoveFileEx() without the replace flag
 * does the check itself); `RENAME_EXCHANGE` is three renames through a
 * temporary name next to `newpath`, which a crash in the middle can
 * leave behind.
 *
 * @param flags is `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, or zero
 * @return 0 on success, or -1 w/ errno
 * @raise EINVAL if `flags` has an unknown bit, or both of them
 * @raise EEXIST if `RENAME_NOREPLACE` and `newpath` exists
 * @raise ENOENT if `RENAME_EXCHANGE` and either path is missing
 * @raise EROFS if either path is under /zip/...
 * @see renameat() for the rest of the errors
 */
int renameat2(int olddirfd, const char *oldpath, int newdirfd,
              const char *newpath, unsigned flags) {
  int rc;
  if (!flags) {
    rc = renameat(olddirfd, oldpath, newdirfd, newpath);
  } else if ((flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT)) ||
             ((flags & RENAME_NOREPLACE) && (flags & RENAME_EXCHANGE)) ||
             ((flags & RENAME_WHITEOUT) && !IsLinux())) {
    rc = einval();
  } else if (kisdangerous(oldpath) || kisdangerous(newpath)) {
    rc = efault();
  } else if (__is_evil_path(newpath)) {
    rc = eilseq();
  } else if (_weaken(__zipos_notat) &&
             ((rc = __zipos_notat(olddirfd, oldpath)) == -1 ||
              (rc = __zipos_notat(newdirfd, newpath)) == -1)) {
    rc = erofs();
  } else if (IsLinux()) {
    rc = sys_renameat2(__dirfd2host(olddirfd), oldpath,
                       __dirfd2host(newdirfd), newpath, flags);
    if (rc == -1 && errno == ENOSYS)
      rc = RenameEmulated(olddirfd, oldpath, newdirfd, newpath, flags);
  } else if (IsXnu()) {
    rc = RenameXnu(olddirfd, oldpath, newdirfd, newpath, flags);
  } else if (IsWindows()) {
    rc = sys_renameat2_nt(olddirfd, oldpath, newdirfd, newpath, flags);
  } else {
    rc = RenameEmulated(olddirfd, oldpath, newdirfd, newpath, flags);
  }
  STRACE("renameat2(%s, %#s, %s, %#s, %#x) → %d% m", DescribeDirfd(olddirfd),
         oldpath, DescribeDirfd(newdirfd), newpath, flags, rc);
  return rc;
}

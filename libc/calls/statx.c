#include "libc/calls/calls.h"
#include "libc/calls/makedev.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/struct/statx.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/kprintf.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/errfuns.h"

static void statx_time(struct statx_timestamp *o, struct timespec ts) {
  o->tv_sec = ts.tv_sec;
  o->tv_nsec = ts.tv_nsec;
  o->__reserved = 0;
}

/**
 * Returns extended file status.
 *
 * On Linux this is the system call. Elsewhere it's fstatat() with the
 * result laid out the linux way; the mask reports the basic fields and
 * STATX_BTIME when the host has a creation time.
 *
 * @param flags may have AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
 *     AT_NO_AUTOMOUNT, AT_STATX_SYNC_TYPE bits
 * @param mask selects fields; unknown bits are ignored like the kernel
 *     does, STATX__RESERVED is EINVAL
 * @raise EFAULT if `path` or `out` is a bad pointer
 */
int statx(int dirfd, const char *path, int flags, unsigned mask,
          struct statx *out) {
  if (IsLinux())
    return sys_statx(dirfd, path, flags, mask, out);
  if (!path || kisdangerous(path) || !out || kisdangerous(out))
    return efault();
  if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT |
                AT_STATX_SYNC_TYPE))
    return einval();
  if (mask & STATX__RESERVED)
    return einval();
  struct stat st;
  int rc;
  if ((flags & AT_EMPTY_PATH) && !*path) {
    rc = fstat(dirfd, &st);
  } else {
    rc = fstatat(dirfd, path, &st, flags & AT_SYMLINK_NOFOLLOW);
  }
  if (rc == -1)
    return -1;
  bzero(out, sizeof(*out));
  out->stx_mask = STATX_BASIC_STATS;
  out->stx_blksize = st.st_blksize;
  out->stx_nlink = st.st_nlink;
  out->stx_uid = st.st_uid;
  out->stx_gid = st.st_gid;
  out->stx_mode = st.st_mode;
  out->stx_ino = st.st_ino;
  out->stx_size = st.st_size;
  out->stx_blocks = st.st_blocks;
  statx_time(&out->stx_atime, st.st_atim);
  statx_time(&out->stx_ctime, st.st_ctim);
  statx_time(&out->stx_mtime, st.st_mtim);
  if (st.st_birthtim.tv_sec || st.st_birthtim.tv_nsec) {
    statx_time(&out->stx_btime, st.st_birthtim);
    out->stx_mask |= STATX_BTIME;
  }
  out->stx_rdev_major = major(st.st_rdev);
  out->stx_rdev_minor = minor(st.st_rdev);
  out->stx_dev_major = major(st.st_dev);
  out->stx_dev_minor = minor(st.st_dev);
  return 0;
}

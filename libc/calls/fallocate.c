#include "libc/calls/calls.h"
#include "libc/calls/cp.internal.h"
#include "libc/calls/internal.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/syscall-nt.internal.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/consts/falloc.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

#define F_PREALLOCATE  42  // xnu fcntl
#define F_ALLOCATEALL  4
#define F_PEOFPOSMODE  3

struct fstore {
  uint32_t fst_flags;
  int32_t fst_posmode;
  int64_t fst_offset;
  int64_t fst_length;
  int64_t fst_bytesalloc;
};

static int fallocate_xnu(int fd, int64_t end, int64_t size) {
  if (end > size) {
    struct fstore fst = {F_ALLOCATEALL, F_PEOFPOSMODE, 0, end - size, 0};
    if (__sys_fcntl(fd, F_PREALLOCATE, &fst) == -1)
      return -1;
  }
  return 0;
}

static int fallocate_unix(int fd, int mode, int64_t offset, int64_t length) {
  struct stat st;
  if (fstat(fd, &st) == -1)
    return -1;
  if (S_ISFIFO(st.st_mode))
    return espipe();
  if (!S_ISREG(st.st_mode))
    return enodev();
  int64_t end = offset + length;
  int rc = 0;
  if (IsXnu()) {
    rc = fallocate_xnu(fd, end, st.st_size);
  } else if (IsFreebsd() || IsNetbsd()) {
    rc = sys_posix_fallocate(fd, offset, length);
    if (rc > 0) {
      errno = rc;
      rc = -1;
    }
  }
  if (!rc && !(mode & FALLOC_FL_KEEP_SIZE) && end > st.st_size)
    rc = ftruncate(fd, end);
  return rc;
}

/**
 * Reserves disk space for a file.
 *
 * Linux has this as a system call. Elsewhere only `mode` 0 and
 * `FALLOC_FL_KEEP_SIZE` are understood: the space is preallocated where
 * the host can (NT, XNU, FreeBSD, NetBSD) and the file grows to cover
 * the range unless `FALLOC_FL_KEEP_SIZE` is given.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise EINVAL if `offset` or `length` is bad
 * @raise EOPNOTSUPP if `mode` isn't supported on this host
 * @raise ESPIPE if `fd` is a pipe
 * @raise ENODEV if `fd` isn't a regular file
 * @cancelationpoint
 */
int fallocate(int fd, int mode, int64_t offset, int64_t length) {
  int rc;
  BEGIN_CANCELATION_POINT;
  if (offset < 0 || length <= 0 || offset > INT64_MAX - length) {
    rc = einval();
  } else if (fd < 0) {
    rc = ebadf();
  } else if (__isfdkind(fd, kFdZip)) {
    rc = erofs();
  } else if (IsLinux()) {
    rc = sys_fallocate(fd, mode, offset, length);
  } else if (mode & ~FALLOC_FL_KEEP_SIZE) {
    rc = eopnotsupp();
  } else if (IsMetal()) {
    rc = enosys();
  } else if (!IsWindows()) {
    rc = fallocate_unix(fd, mode, offset, length);
  } else if (__isfdkind(fd, kFdFile)) {
    rc = sys_fallocate_nt(__get_pib()->fds.p[fd].handle, offset, length,
                          !!(mode & FALLOC_FL_KEEP_SIZE));
  } else if (__isfdopen(fd)) {
    rc = enodev();
  } else {
    rc = ebadf();
  }
  END_CANCELATION_POINT;
  STRACE("fallocate(%d, %#x, %'ld, %'ld) → %d% m", fd, mode, offset, length,
         rc);
  return rc;
}

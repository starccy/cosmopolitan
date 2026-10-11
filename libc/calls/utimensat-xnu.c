#include "libc/calls/internal.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/struct/timespec.internal.h"
#include "libc/calls/syscall_support-sysv.internal.h"
#include "libc/errno.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/clock.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/utime.h"
#include "libc/sysv/errfuns.h"

#define ATTR_BIT_MAP_COUNT 5
#define ATTR_CMN_MODTIME   0x00000400
#define ATTR_CMN_ACCTIME   0x00001000
#define FSOPT_NOFOLLOW     0x00000001

struct attrlist_xnu {
  uint16_t bitmapcount;
  uint16_t reserved;
  uint32_t commonattr;
  uint32_t volattr;
  uint32_t dirattr;
  uint32_t fileattr;
  uint32_t forkattr;
};

int sys_setattrlistat(int, const char *, struct attrlist_xnu *, void *, size_t,
                      uint32_t);

// utimensat() for a path on xnu, through setattrlistat() the way
// apple's libc does it, which takes a dirfd, AT_SYMLINK_NOFOLLOW and
// nanoseconds. the attribute values go in bit order, mtime first
int sys_utimensat_xnu(int dirfd, const char *path, const struct timespec ts[2],
                      int flags) {
  if (!path)
    return sys_utimensat_old(dirfd, path, ts, flags);
  struct timespec now, in[2], buf[2];
  struct attrlist_xnu al = {ATTR_BIT_MAP_COUNT};
  int n = 0;
  if (ts) {
    in[0] = ts[0];
    in[1] = ts[1];
  } else {
    in[0].tv_nsec = UTIME_NOW;
    in[1].tv_nsec = UTIME_NOW;
  }
  if (in[0].tv_nsec == UTIME_NOW || in[1].tv_nsec == UTIME_NOW)
    clock_gettime(CLOCK_REALTIME, &now);
  for (int i = 0; i < 2; ++i) {
    if (in[i].tv_nsec == UTIME_NOW)
      in[i] = now;
    else if (in[i].tv_nsec != UTIME_OMIT &&
             (in[i].tv_nsec < 0 || in[i].tv_nsec >= 1000000000))
      return einval();
  }
  if (in[1].tv_nsec != UTIME_OMIT) {
    al.commonattr |= ATTR_CMN_MODTIME;
    buf[n++] = in[1];
  }
  if (in[0].tv_nsec != UTIME_OMIT) {
    al.commonattr |= ATTR_CMN_ACCTIME;
    buf[n++] = in[0];
  }
  if (!n)
    return 0;
  int e = errno;
  int rc = sys_setattrlistat(__dirfd2host(dirfd), path, &al, buf,
                             n * sizeof(struct timespec),
                             (flags & AT_SYMLINK_NOFOLLOW) ? FSOPT_NOFOLLOW : 0);
  if (rc == -1 && errno == ENOSYS) {
    errno = e;
    rc = sys_utimensat_old(dirfd, path, ts, flags);
  }
  return rc;
}

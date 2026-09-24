#include "libc/calls/struct/timespec.h"
#include "libc/dce.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/utime.h"

__HOSTCONST(int, UTIME_NOW);
__HOSTCONST(int, UTIME_OMIT);

/**
 * Turns the `tv_nsec` markers of a utimensat() pair into the host's.
 *
 * Returns `ts` itself when nothing needs changing, else `buf` holding
 * the converted pair.
 */
const struct timespec *__utime2host(const struct timespec ts[2],
                                    struct timespec buf[2]) {
  if (!ts || IsLinux())
    return ts;
  for (int i = 0; i < 2; ++i) {
    buf[i] = ts[i];
    if (ts[i].tv_nsec == UTIME_NOW) {
      buf[i].tv_nsec = __host_UTIME_NOW;
    } else if (ts[i].tv_nsec == UTIME_OMIT) {
      buf[i].tv_nsec = __host_UTIME_OMIT;
    }
  }
  return buf;
}

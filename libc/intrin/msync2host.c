#include "libc/dce.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/msync.h"

__HOSTCONST(int, MS_ASYNC);
__HOSTCONST(int, MS_INVALIDATE);
__HOSTCONST(int, MS_SYNC);

/**
 * Turns msync() flags into what the host kernel expects.
 *
 * FreeBSD spells `MS_SYNC` as zero, which comes out right here.
 */
int __msync2host(int flags) {
  if (IsLinux() || IsWindows())
    return flags;
  int res = 0;
  if (flags & MS_ASYNC)
    res |= __host_MS_ASYNC;
  if (flags & MS_INVALIDATE)
    res |= __host_MS_INVALIDATE;
  if (flags & MS_SYNC)
    res |= __host_MS_SYNC;
  return res;
}

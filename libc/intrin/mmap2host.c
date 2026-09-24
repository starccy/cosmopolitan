#include "libc/dce.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/map.h"

__HOSTCONST(int, MAP_ANONYMOUS);
__HOSTCONST(int, MAP_32BIT);
__HOSTCONST(int, MAP_LOCKED);
__HOSTCONST(int, MAP_NORESERVE);
__HOSTCONST(int, MAP_POPULATE);
__HOSTCONST(int, MAP_NONBLOCK);
__HOSTCONST(int, MAP_SYNC);
__HOSTCONST(int, MAP_INHERIT);
__HOSTCONST(int, MAP_NOSYNC);
__HOSTCONST(int, MAP_NOCACHE);
__HOSTCONST(int, MAP_JIT);
__HOSTCONST(int, MAP_CONCEAL);
__HOSTCONST(int, MAP_NOEXTEND);
__HOSTCONST(int, MAP_HASSEMAPHORE);

#define COSMO_ONLY                                                     \
  (MAP_INHERIT | MAP_NOSYNC | MAP_NOCACHE | MAP_JIT | MAP_CONCEAL | \
   MAP_NOEXTEND | MAP_HASSEMAPHORE)

/**
 * Turns mmap() flags into what the host kernel expects.
 *
 * `MAP_FIXED_NOREPLACE` isn't handled here, since mmap() polyfills it.
 * A flag the host doesn't have is dropped, which is what Linux does
 * with bits it doesn't know. `MAP_DENYWRITE` and `MAP_EXECUTABLE` are
 * ignored by Linux itself and go the same way.
 */
int __mmap2host(int flags) {
  if (IsLinux())
    return flags & ~COSMO_ONLY;
  if (IsWindows())
    return flags;
  int res = flags & (MAP_TYPE | MAP_FIXED);
  if ((res & MAP_TYPE) == MAP_SHARED_VALIDATE)
    res = (res & ~MAP_TYPE) | MAP_SHARED;
  if ((flags & MAP_ANONYMOUS) && __host_MAP_ANONYMOUS > 0)
    res |= __host_MAP_ANONYMOUS;
  if ((flags & MAP_32BIT) && __host_MAP_32BIT > 0)
    res |= __host_MAP_32BIT;
  if ((flags & MAP_LOCKED) && __host_MAP_LOCKED > 0)
    res |= __host_MAP_LOCKED;
  if ((flags & MAP_NORESERVE) && __host_MAP_NORESERVE > 0)
    res |= __host_MAP_NORESERVE;
  if ((flags & MAP_POPULATE) && __host_MAP_POPULATE > 0)
    res |= __host_MAP_POPULATE;
  if ((flags & MAP_NONBLOCK) && __host_MAP_NONBLOCK > 0)
    res |= __host_MAP_NONBLOCK;
  if ((flags & MAP_SYNC) && __host_MAP_SYNC > 0)
    res |= __host_MAP_SYNC;
  if ((flags & MAP_INHERIT) && __host_MAP_INHERIT > 0)
    res |= __host_MAP_INHERIT;
  if ((flags & MAP_NOSYNC) && __host_MAP_NOSYNC > 0)
    res |= __host_MAP_NOSYNC;
  if ((flags & MAP_NOCACHE) && __host_MAP_NOCACHE > 0)
    res |= __host_MAP_NOCACHE;
  if ((flags & MAP_JIT) && __host_MAP_JIT > 0)
    res |= __host_MAP_JIT;
  if ((flags & MAP_CONCEAL) && __host_MAP_CONCEAL > 0)
    res |= __host_MAP_CONCEAL;
  if ((flags & MAP_NOEXTEND) && __host_MAP_NOEXTEND > 0)
    res |= __host_MAP_NOEXTEND;
  if ((flags & MAP_HASSEMAPHORE) && __host_MAP_HASSEMAPHORE > 0)
    res |= __host_MAP_HASSEMAPHORE;
  return res;
}

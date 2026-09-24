#include "libc/dce.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/sig.h"

__HOSTCONST(int, SIG_BLOCK);
__HOSTCONST(int, SIG_UNBLOCK);
__HOSTCONST(int, SIG_SETMASK);

/**
 * Turns a sigprocmask() `how` into what the host kernel expects.
 *
 * Returns -1 if it isn't one of the three.
 */
int __sighow2host(int how) {
  switch (how) {
    case SIG_BLOCK:
      return __host_SIG_BLOCK;
    case SIG_UNBLOCK:
      return __host_SIG_UNBLOCK;
    case SIG_SETMASK:
      return __host_SIG_SETMASK;
    default:
      return -1;
  }
}

#include "libc/dce.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/w.h"

__HOSTCONST(int, WCONTINUED);

/**
 * Turns wait4() options into what the host kernel expects.
 *
 * Returns -1 for an option bit the host doesn't take there.
 */
int __wait2host(int options) {
  if (IsLinux() || IsWindows())
    return options;
  if (options & ~(WNOHANG | WUNTRACED | WCONTINUED))
    return -1;
  int res = options & (WNOHANG | WUNTRACED);
  if (options & WCONTINUED)
    res |= __host_WCONTINUED;
  return res;
}

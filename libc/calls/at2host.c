#include "libc/dce.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/host.internal.h"

#define AT_EMPTY_PATH_freebsd 0x4000

__HOSTCONST(int, AT_FDCWD);
__HOSTCONST(int, AT_SYMLINK_NOFOLLOW);
__HOSTCONST(int, AT_REMOVEDIR);
__HOSTCONST(int, AT_EACCESS);
__HOSTCONST(int, AT_SYMLINK_FOLLOW);

/**
 * Turns a directory descriptor argument into what the host expects.
 */
int __dirfd2host(int dirfd) {
  return dirfd == AT_FDCWD ? __host_AT_FDCWD : dirfd;
}

/**
 * Turns AT_xxx flags into what the host kernel expects.
 */
int __at2host(int flags) {
  if (IsLinux() || IsWindows())
    return flags;
  int res = 0;
  if (flags & AT_SYMLINK_NOFOLLOW)
    res |= __host_AT_SYMLINK_NOFOLLOW;
  if (flags & AT_REMOVEDIR)
    res |= __host_AT_REMOVEDIR;
  if (flags & AT_SYMLINK_FOLLOW)
    res |= __host_AT_SYMLINK_FOLLOW;
  if ((flags & AT_EMPTY_PATH) && IsFreebsd())
    res |= AT_EMPTY_PATH_freebsd;
  if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_REMOVEDIR | AT_SYMLINK_FOLLOW |
                AT_EMPTY_PATH | AT_NO_AUTOMOUNT))
    return -1;
  return res;
}

/**
 * Turns faccessat() flags into what the host kernel expects.
 */
int __faccessat2host(int flags) {
  if (IsLinux() || IsWindows())
    return flags;
  int res = 0;
  if (flags & AT_SYMLINK_NOFOLLOW)
    res |= __host_AT_SYMLINK_NOFOLLOW;
  if (flags & AT_EACCESS)
    res |= __host_AT_EACCESS;
  if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EACCESS))
    return -1;
  return res;
}

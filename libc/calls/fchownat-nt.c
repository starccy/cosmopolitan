#include "libc/calls/calls.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/syscall-nt.internal.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/errfuns.h"

// windows files have owners but no unix ids to give them: a change to
// what the caller already is succeeds, anything else is EPERM, and the
// file has to be there

textwindows static int sys_chown_check_nt(uint32_t uid, uint32_t gid) {
  if ((uid != -1u && uid != getuid()) || (gid != -1u && gid != getgid()))
    return eperm();
  return 0;
}

textwindows int sys_fchownat_nt(int dirfd, const char *path, uint32_t uid,
                                uint32_t gid, int flags) {
  struct stat st;
  if (fstatat(dirfd, path, &st, flags & AT_SYMLINK_NOFOLLOW) == -1)
    return -1;
  return sys_chown_check_nt(uid, gid);
}

textwindows int sys_fchown_nt(int fd, uint32_t uid, uint32_t gid) {
  struct stat st;
  if (fstat(fd, &st) == -1)
    return -1;
  return sys_chown_check_nt(uid, gid);
}

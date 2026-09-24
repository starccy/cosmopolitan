#include "libc/calls/calls.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/fmt/itoa.h"
#include "libc/intrin/strace.h"
#include "libc/limits.h"
#include "libc/runtime/runtime.h"
#include "libc/stdio/rand.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/mfd.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/errfuns.h"


/**
 * Creates an anonymous file that lives in memory.
 *
 * Linux has this as a system call. Elsewhere it's a file in the temp
 * directory that is unlinked as soon as it's open, which keeps every
 * property a memfd user relies on (read, write, ftruncate, mmap, pass
 * it to a child) apart from sealing: `MFD_ALLOW_SEALING` is accepted
 * and F_ADD_SEALS fails with EINVAL.
 *
 * @param name shows up in /proc/self/fd on Linux and in the temp file's
 *     name elsewhere
 * @param flags can have MFD_CLOEXEC, MFD_ALLOW_SEALING, MFD_HUGETLB
 * @return file descriptor, or -1 w/ errno
 */
int memfd_create(const char *name, unsigned flags) {
  int fd;
  if (!name || (flags & ~(MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB))) {
    fd = einval();
  } else if (IsLinux()) {
    fd = sys_memfd_create(name, flags);
  } else if (IsMetal()) {
    fd = enosys();
  } else {
    char path[PATH_MAX], *p;
    const char *dir = __get_tmpdir();
    size_t dirlen = strlen(dir);
    if (dirlen + 64 + strlen(name) > sizeof(path)) {
      fd = enametoolong();
    } else {
      p = mempcpy(path, dir, dirlen);
      if (p > path && p[-1] != '/')
        *p++ = '/';
      p = stpcpy(p, ".memfd-");
      for (; *name; ++name)
        *p++ = *name == '/' ? '_' : *name;
      *p++ = '-';
      p = FormatUint64(p, getpid());
      *p++ = '-';
      p = FormatUint64(p, _rand64());
      *p = 0;
      fd = open(path, O_RDWR | O_CREAT | O_EXCL |
                          ((flags & MFD_CLOEXEC) ? O_CLOEXEC : 0),
                0600);
      if (fd != -1)
        unlink(path);
    }
  }
  STRACE("memfd_create(%#s, %#x) → %d% m", name, flags, fd);
  return fd;
}

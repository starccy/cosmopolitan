#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/dce.h"
#include "libc/dlopen/dlfcn.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/strace.h"
#include "libc/nt/console.h"
#include "libc/nt/dll.h"
#include "libc/nt/enum/filetype.h"
#include "libc/nt/files.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/winsock.h"
#include "libc/sysv/consts/f.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

#define kNtSolSocket       0xffff
#define kNtSoProtocolInfoW 0x2005

// the socket's family, type and protocol, if `h` is a socket. a host
// library that made one has loaded ws2_32.dll, so there's no need to
// load it here when it isn't
static bool dlfd_socket(int64_t h, struct NtWsaProtocolInfo *info) {
  int64_t ws2;
  int __msabi (*get)(uint64_t, int, int, void *, int *);
  if (!(ws2 = GetModuleHandleW(u"ws2_32.dll")))
    return false;
  if (!(get = GetProcAddress(ws2, "getsockopt")))
    return false;
  int n = sizeof(*info);
  return !get(h, kNtSolSocket, kNtSoProtocolInfoW, info, &n);
}

static int dlfd_nt(int64_t h, int flags) {
  int fd, kind, family = 0, type = 0, protocol = 0;
  unsigned mode;
  uint32_t cm;
  struct NtWsaProtocolInfo info;
  SetLastError(0);
  switch (GetFileType(h)) {
    case kNtFileTypeDisk:
      kind = kFdFile;
      mode = 0100644;
      break;
    case kNtFileTypeChar:
      kind = GetConsoleMode(h, &cm) ? kFdConsole : kFdFile;
      mode = 0020666;
      break;
    case kNtFileTypePipe:
      if (dlfd_socket(h, &info)) {
        kind = kFdSocket;
        mode = 0140666;
        // windows numbers AF_INET6 23
        family = info.iAddressFamily == 23 ? AF_INET6 : info.iAddressFamily;
        type = info.iSocketType;
        protocol = info.iProtocol;
      } else {
        kind = kFdFile;
        mode = 0010666;
      }
      break;
    default:
      // GetFileType() answers unknown for a handle that isn't one
      if (GetLastError())
        return ebadf();
      kind = kFdFile;
      mode = 0;
      break;
  }
  if ((fd = __reservefd(-1)) == -1)
    return -1;
  struct Fd *f = __get_pib()->fds.p + fd;
  f->handle = h;
  f->flags = flags;
  f->mode = mode;
  f->family = family;
  f->type = type;
  f->protocol = protocol;
  if (mode == 0100644 &&
      (!(flags & O_APPEND) || (flags & O_ACCMODE) != O_WRONLY)) {
    __fds_lock();
    f->cursor = __cursor_new();
    __fds_unlock();
  }
  f->kind = kind;
  return fd;
}

/**
 * Makes a file descriptor of something a host library handed over.
 *
 * This is the reverse of cosmo_dlhandle(). On Windows `handle` is a
 * Win32 HANDLE, which may be a file, a pipe, a console or a socket.
 * The new descriptor owns it, so close() closes the handle. `flags` is
 * the access mode it was opened with, `O_RDONLY`, `O_WRONLY` or
 * `O_RDWR`, and may add `O_APPEND`, `O_CLOEXEC` and `O_NONBLOCK`.
 *
 * Anywhere else the host's descriptors are ours, so `handle` is
 * returned as it is, once it's known to be open, and `flags` is only
 * checked.
 *
 * @return file descriptor, or -1 w/ errno
 * @raise EBADF if `handle` isn't open
 * @raise EINVAL if `flags` has anything else in it
 */
int cosmo_dlfd(intptr_t handle, int flags) {
  int rc;
  if (flags & ~(O_ACCMODE | O_APPEND | O_CLOEXEC | O_NONBLOCK)) {
    rc = einval();
  } else if (IsWindows()) {
    if (!handle || handle == -1)
      rc = ebadf();
    else
      rc = dlfd_nt(handle, flags);
  } else if (handle < 0 || handle > 0x7fffffff) {
    rc = ebadf();
  } else if (fcntl(handle, F_GETFD) == -1) {
    rc = -1;
  } else {
    rc = handle;
  }
  STRACE("cosmo_dlfd(%ld, %#o) → %d% m", handle, flags, rc);
  return rc;
}

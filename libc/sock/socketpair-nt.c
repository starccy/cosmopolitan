/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2020 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/kprintf.h"
#include "libc/nt/createfile.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/ipc.h"
#include "libc/nt/runtime.h"
#include "libc/sock/internal.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/stdio/rand.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#if SupportsWindows()

textwindows static bool ExchangeAll(int fd, void *buf, size_t n,
                                    bool writing) {
  char *p = buf;
  while (n) {
    ssize_t r = writing ? send(fd, p, n, 0) : recv(fd, p, n, 0);
    if (r <= 0)
      return false;
    p += r;
    n -= r;
  }
  return true;
}

// A stream pair is two real sockets joined through a listener, since
// poll() can't tell when a named pipe is writable. The listener sits at
// a random name under the temp directory for the length of one connect,
// and a nonce sent by our client tells it apart from a local process
// that raced us to the path.
textwindows static int SocketPairStream(int oflags, int sv[2]) {
  int err, srv = -1, cli = -1, acc = -1;
  int cloexec = (oflags & O_CLOEXEC) ? SOCK_CLOEXEC : 0;
  uint64_t nonce[2] = {_rand64(), _rand64()};
  struct sockaddr_un sa = {.sun_family = AF_UNIX};
  ksnprintf(sa.sun_path, sizeof(sa.sun_path), "/tmp/.cosmo-sp-%d-%lx.sock",
            getpid(), nonce[0]);
  if ((srv = socket(AF_UNIX, SOCK_STREAM | cloexec, 0)) == -1)
    goto Fail;
  if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    goto Fail;
  if (listen(srv, 4) == -1)
    goto Fail;
  if ((cli = socket(AF_UNIX, SOCK_STREAM | cloexec, 0)) == -1)
    goto Fail;
  if (connect(cli, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    goto Fail;
  if (!ExchangeAll(cli, nonce, sizeof(nonce), true))
    goto Fail;
  for (int tries = 0; tries < 8 && acc == -1; ++tries) {
    uint64_t got[2];
    int fd = accept4(srv, 0, 0, cloexec);
    if (fd == -1)
      goto Fail;
    if (ExchangeAll(fd, got, sizeof(got), false) &&
        !memcmp(got, nonce, sizeof(got))) {
      acc = fd;
    } else {
      close(fd);
    }
  }
  if (acc == -1) {
    errno = ECONNABORTED;
    goto Fail;
  }
  close(srv);
  unlink(sa.sun_path);
  if (oflags & O_NONBLOCK) {
    __fds_lock();
    __get_pib()->fds.p[cli].flags |= O_NONBLOCK;
    __get_pib()->fds.p[acc].flags |= O_NONBLOCK;
    __fds_unlock();
  }
  sv[0] = cli;
  sv[1] = acc;
  return 0;
Fail:
  err = errno;
  if (srv != -1)
    close(srv);
  if (cli != -1)
    close(cli);
  if (acc != -1)
    close(acc);
  unlink(sa.sun_path);
  errno = err;
  return -1;
}

textwindows static int sys_socketpair_nt_impl(int family, int type, int proto,
                                              int sv[2]) {
  uint32_t mode;
  int64_t hpipe, h1;
  char16_t pipename[64];
  int rc, reader, writer, oflags;

  // Supports only AF_UNIX
  if (family != AF_UNIX) {
    return eafnosupport();
  }

  oflags = 0;
  if (type & SOCK_CLOEXEC)
    oflags |= O_CLOEXEC;
  if (type & SOCK_NONBLOCK)
    oflags |= O_NONBLOCK;
  type &= ~(SOCK_CLOEXEC | SOCK_NONBLOCK);

  if (type == SOCK_STREAM) {
    return SocketPairStream(oflags, sv);
  } else if ((type == SOCK_DGRAM) || (type == SOCK_SEQPACKET)) {
    mode = kNtPipeTypeMessage | kNtPipeReadmodeMessage;
  } else {
    return eopnotsupp();
  }

  __create_pipe_name(pipename);
  __fds_lock();
  reader = __reservefd_unlocked(-1);
  writer = __reservefd_unlocked(-1);
  __fds_unlock();
  if (reader == -1 || writer == -1) {
    if (reader != -1)
      __releasefd(reader);
    if (writer != -1)
      __releasefd(writer);
    return -1;
  }
  if ((hpipe = CreateNamedPipe(
           pipename, kNtPipeAccessDuplex | kNtFileFlagOverlapped, mode, 1,
           65536, 65536, 0, &kNtIsInheritable)) == -1) {
    __releasefd(writer);
    __releasefd(reader);
    return -1;
  }

  h1 = CreateFile(pipename, kNtGenericWrite | kNtGenericRead,
                  kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete,
                  &kNtIsInheritable, kNtOpenExisting, kNtFileFlagOverlapped, 0);

  __fds_lock();

  if (h1 != -1) {

    __get_pib()->fds.p[reader].kind = kFdFile;
    __get_pib()->fds.p[reader].flags = O_RDWR | oflags;
    __get_pib()->fds.p[reader].mode = 0140444;
    __get_pib()->fds.p[reader].handle = hpipe;
    __get_pib()->fds.p[reader].was_created_during_vfork = __vforked;

    __get_pib()->fds.p[writer].kind = kFdFile;
    __get_pib()->fds.p[writer].flags = O_RDWR | oflags;
    __get_pib()->fds.p[writer].mode = 0140222;
    __get_pib()->fds.p[writer].handle = h1;
    __get_pib()->fds.p[writer].was_created_during_vfork = __vforked;

    sv[0] = reader;
    sv[1] = writer;

    rc = 0;
  } else {
    __winerr();
    CloseHandle(hpipe);
    __releasefd(writer);
    __releasefd(reader);
    rc = -1;
  }

  __fds_unlock();

  return rc;
}

textwindows int sys_socketpair_nt(int family, int type, int proto, int sv[2]) {
  int rc;
  BLOCK_SIGNALS;
  rc = sys_socketpair_nt_impl(family, type, proto, sv);
  ALLOW_SIGNALS;
  return rc;
}

#endif /* __x86_64__ */

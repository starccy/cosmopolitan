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
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/sock/struct/sockaddr.internal.h"
#include "libc/sysv/consts/af.h"

// the bsds drop the peer of a datagram socket before they refuse the
// family, so linux's AF_UNSPEC disconnect is a connect() that fails
// and leaves no peer behind
static int sys_connect_unspec_bsd(int fd) {
  union sockaddr_storage_bsd peer;
  uint32_t len = sizeof(peer);
  unsigned char un[16] = {sizeof(un), AF_UNSPEC};
  int e = errno;
  if (!__sys_connect(fd, un, sizeof(un)))
    return 0;
  int ce = errno;
  if (__sys_getpeername(fd, &peer, &len) == -1 && errno == ENOTCONN) {
    errno = e;
    return 0;
  }
  errno = ce;
  return -1;
}

int sys_connect(int fd, const void *addr, uint32_t addrsize) {
  union sockaddr_storage_bsd bsd;
  if (!IsBsd()) {
    return __sys_connect(fd, addr, addrsize);
  } else if (addr && addrsize >= sizeof(uint16_t) &&
             ((const struct sockaddr *)addr)->sa_family == AF_UNSPEC) {
    return sys_connect_unspec_bsd(fd);
  } else if (!sockaddr2bsd(addr, addrsize, &bsd, &addrsize)) {
    return __sys_connect(fd, &bsd.sa, addrsize);
  } else {
    return -1;
  }
}

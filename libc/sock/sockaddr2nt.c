#include "libc/dce.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/host.internal.h"
#if SupportsWindows()

/**
 * Gives a socket address the family number WinSock knows.
 *
 * Only the family field differs from what Linux takes. Addresses whose
 * family is the same on both are returned as they are; the others are
 * copied into `buf` and fixed up there.
 */
textwindows const void *__sockaddr2nt(const void *addr, uint32_t addrsize,
                                      struct sockaddr_storage *buf) {
  if (addrsize < sizeof(uint16_t))
    return addr;
  uint16_t family = *(const uint16_t *)addr;
  int host = __af2host(family);
  if (host == family)
    return addr;
  if (addrsize > sizeof(*buf))
    addrsize = sizeof(*buf);
  memcpy(buf, addr, addrsize);
  buf->ss_family = host;
  return buf;
}

#endif /* __x86_64__ */

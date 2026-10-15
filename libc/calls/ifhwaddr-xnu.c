#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/intrin/weaken.h"
#include "libc/macros.h"
#include "libc/mem/mem.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/arp.h"
#include "libc/sysv/errfuns.h"

// the sockaddr_dl after the if_msghdr: sdl_type at byte 4, the name
// length at 5, the address length at 6, name then address from byte 8
int __xnu_ifhwaddr(const char *name, unsigned short *type,
                   unsigned char *addr, int *alen) {
  int mib[6] = {4 /* CTL_NET */, 17 /* PF_ROUTE */, 0, 0,
                3 /* NET_RT_IFLIST */, 0};
  size_t len = 0, namelen = strlen(name);
  char *buf;
  int rc = -1;
  if (sysctl(mib, 6, 0, &len, 0, 0) == -1 || !_weaken(malloc) || !(buf = _weaken(malloc)(len)))
    return -1;
  if (sysctl(mib, 6, buf, &len, 0, 0) == -1) {
    _weaken(free)(buf);
    return -1;
  }
  for (size_t i = 0; i + 4 <= len;) {
    uint16_t msglen;
    int addrs;
    memcpy(&msglen, buf + i, 2);
    if (!msglen || msglen > len - i)
      break;
    memcpy(&addrs, buf + i + 4, 4);
    const unsigned char *sdl = (const unsigned char *)buf + i + 112;
    if (buf[i + 3] == 0xe /* RTM_IFINFO */ && (addrs & 0x10 /* RTA_IFP */) &&
        msglen >= 112 + 8 && sdl[1] == 18 /* AF_LINK */ &&
        sdl[5] == namelen && 8 + sdl[5] + sdl[6] <= msglen - 112 &&
        !memcmp(sdl + 8, name, namelen)) {
      switch (sdl[4]) {
        case 0x6:   // IFT_ETHER
        case 0x87:  // IFT_L2VLAN
        case 0xd1:  // IFT_BRIDGE
          *type = ARPHRD_ETHER;
          break;
        case 0x18:  // IFT_LOOP
          *type = ARPHRD_LOOPBACK;
          break;
        case 0x17:  // IFT_PPP
          *type = ARPHRD_PPP;
          break;
        default:
          *type = ARPHRD_NONE;
      }
      *alen = MIN(sdl[6], 14);
      memset(addr, 0, 14);
      memcpy(addr, sdl + 8 + sdl[5], *alen);
      rc = 0;
      break;
    }
    i += msglen;
  }
  _weaken(free)(buf);
  if (rc == -1)
    enodev();
  return rc;
}


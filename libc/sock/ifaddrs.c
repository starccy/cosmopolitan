/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2023 Justine Alexandra Roberts Tunney                              │
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
#include "libc/sock/ifaddrs.h"
#include "libc/calls/calls.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/limits.h"
#include "libc/mem/mem.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/ifconf.h"
#include "libc/sock/struct/ifreq.h"
#include "libc/sock/struct/sockaddr6.h"
#include "libc/sock/ifname.h"
#include "libc/sock/struct/sockaddr_ll.h"
#include "libc/stdio/stdio.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/iff.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/sio.h"
#include "libc/sysv/consts/sock.h"

struct IfAddr {
  struct ifaddrs ifaddrs;
  char name[IFNAMSIZ];
  struct sockaddr_in addr;
  struct sockaddr_in netmask;
  struct sockaddr_in bstaddr;
  char pad[sizeof(struct sockaddr_storage)];
};

// linux's AF_PACKET entry for an interface, holding its link layer
// address; ifa_data (linux's rtnl_link_stats) is left null
struct IfAddrLL {
  struct ifaddrs ifaddrs;
  char name[IFNAMSIZ];
  struct sockaddr_ll addr;
};

struct IfAddr6Info {
  int addr_scope;
  int addr_flags;
};

struct IfAddr6 {
  struct ifaddrs ifaddrs;
  char name[IFNAMSIZ];
  struct sockaddr_in6 addr;
  struct sockaddr_in6 netmask;
  struct sockaddr_in6 bstaddr;  // unused
  struct IfAddr6Info info;
  char pad[sizeof(struct sockaddr_storage)];
};

/**
 * Frees network interface address list.
 */
void freeifaddrs(struct ifaddrs *ifp) {
  struct ifaddrs *next;
  while (ifp) {
    next = ifp->ifa_next;
    free(ifp);
    ifp = next;
  }
}

// hex repr to network order int
static uint128_t hex2no(const char *str) {
  uint128_t res = 0;
  const int max_quads = sizeof(uint128_t) * 2;
  int i = 0;
  while ((i < max_quads) && str[i]) {
    uint8_t acc = (((str[i] & 0xF) + (str[i] >> 6)) | ((str[i] >> 3) & 0x8));
    acc = acc << 4;
    i += 1;
    if (str[i]) {
      acc = acc | (((str[i] & 0xF) + (str[i] >> 6)) | ((str[i] >> 3) & 0x8));
      i += 1;
    }
    res = (res >> 8) | (((uint128_t)acc) << ((sizeof(uint128_t) - 1) * 8));
  }
  res = res >> ((max_quads - i) * 4);
  return res;
}

/**
 * Gets network interface IPv6 address list on linux.
 *
 * @return 0 on success, or -1 w/ errno
 */
static int getifaddrs_linux_ip6(struct ifconf *conf) {
  int fd;
  int n = 0;
  struct ifreq *ifreq = conf->ifc_req;
  const int bufsz = 44 + IFNAMSIZ + 1;
  char buf[bufsz + 1];  // one line max size
  if ((fd = sys_openat(0, "/proc/net/if_inet6", O_RDONLY, 0)) == -1) {
    return -1;
  }

  while ((n = sys_read(fd, &buf[n], bufsz - n)) &&
         ((char *)ifreq < (conf->ifc_buf + conf->ifc_len))) {
    // flags linux include/uapi/linux/if_addr.h:44
    // scope linux include/net/ipv6.h:L99

    //           *addr,   *index,   *plen,    *scope,   *flags,   *ifname
    char *s[] = {&buf[0], &buf[33], &buf[36], &buf[39], &buf[42], &buf[45]};
    int ifnamelen = 0;
    while (*s[5] == ' ') {
      ++s[5];
    }
    while (s[5][ifnamelen] > '\n') {
      ++ifnamelen;
    }
    buf[32] = buf[35] = buf[38] = buf[41] = buf[44] = s[5][ifnamelen] = '\0';
    bzero(ifreq, sizeof(*ifreq));
    ifreq->ifr_addr.sa_family = AF_INET6;
    memcpy(&ifreq->ifr_name, s[5], ifnamelen);
    *((uint128_t *)&ifreq->ifr6_addr) = hex2no(s[0]);
    ifreq->ifr6_ifindex = hex2no(s[1]);
    ifreq->ifr6_prefixlen = hex2no(s[2]);
    ifreq->ifr6_scope = hex2no(s[3]);
    ifreq->ifr6_flags = hex2no(s[4]);
    ++ifreq;
    int tlen = &s[5][ifnamelen] - &buf[0] + 1;
    n = bufsz - tlen;
    memcpy(&buf, &buf[tlen], n);
  }

  conf->ifc_len = (char *)ifreq - conf->ifc_buf;
  return sys_close(fd);
}

/**
 * Gets network interface address list.
 *
 * @return 0 on success, or -1 w/ errno
 * @see tool/viz/getifaddrs.c for example code
 */
int getifaddrs(struct ifaddrs **out_ifpp) {
  // printf("%d\n", sizeof(struct ifreq));
  int rc = -1;
  int fd;
  if ((fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) != -1) {
    char *data;
    size_t size;
    if ((data = malloc((size = 16384)))) {
      struct ifconf conf;
      conf.ifc_buf = data;
      conf.ifc_len = size;
      if (!ioctl(fd, SIOCGIFCONF, &conf)) {
        if (IsLinux()) {
          struct ifconf confl6;
          confl6.ifc_buf = data + conf.ifc_len;
          confl6.ifc_len = size - conf.ifc_len;
          if ((rc = getifaddrs_linux_ip6(&confl6)))
            return rc;
          conf.ifc_len += confl6.ifc_len;
        }

        struct ifaddrs *res = 0;
        for (struct ifreq *ifr = (struct ifreq *)data;
             (char *)ifr < data + conf.ifc_len; ++ifr) {
          uint16_t family = ifr->ifr_addr.sa_family;
          if (family == AF_INET) {
            struct IfAddr *addr;
            if ((addr = calloc(1, sizeof(struct IfAddr)))) {
              memcpy(addr->name, ifr->ifr_name, IFNAMSIZ);
              addr->ifaddrs.ifa_name = addr->name;
              memcpy(&addr->addr, &ifr->ifr_addr, sizeof(struct sockaddr_in));
              addr->ifaddrs.ifa_addr = (struct sockaddr *)&addr->addr;
              addr->ifaddrs.ifa_netmask = (struct sockaddr *)&addr->netmask;
              if (!ioctl(fd, SIOCGIFFLAGS, ifr)) {
                addr->ifaddrs.ifa_flags = ifr->ifr_flags;
              }
              if (!ioctl(fd, SIOCGIFNETMASK, ifr)) {
                memcpy(&addr->netmask, &ifr->ifr_addr,
                       sizeof(struct sockaddr_in));
              }
              unsigned long op;
              if (addr->ifaddrs.ifa_flags & IFF_BROADCAST) {
                op = SIOCGIFBRDADDR;
              } else if (addr->ifaddrs.ifa_flags & IFF_POINTOPOINT) {
                op = SIOCGIFDSTADDR;
              } else {
                op = 0;
              }
              if (op && !ioctl(fd, op, ifr)) {
                memcpy(&addr->bstaddr, &ifr->ifr_addr,
                       sizeof(struct sockaddr_in));
                addr->ifaddrs.ifa_broadaddr =  // is union'd w/ ifu_dstaddr
                    (struct sockaddr *)&addr->bstaddr;
              }
              addr->ifaddrs.ifa_next = res;
              res = (struct ifaddrs *)addr;
            }
          } else if (family == AF_INET6) {
            struct IfAddr6 *addr6;
            if ((addr6 = calloc(1, sizeof(struct IfAddr6)))) {
              addr6->ifaddrs.ifa_name = addr6->name;
              addr6->ifaddrs.ifa_addr = (struct sockaddr *)&addr6->addr;
              addr6->ifaddrs.ifa_netmask = (struct sockaddr *)&addr6->netmask;
              addr6->ifaddrs.ifa_broadaddr = (struct sockaddr *)&addr6->bstaddr;
              addr6->ifaddrs.ifa_data = (void *)&addr6->info;

              memcpy(&addr6->name, &ifr->ifr_name, IFNAMSIZ);
              addr6->info.addr_flags = ifr->ifr6_flags;
              addr6->info.addr_scope = ifr->ifr6_scope;

              addr6->addr.sin6_family = AF_INET6;
              addr6->addr.sin6_port = 0;
              addr6->addr.sin6_flowinfo = 0;
              addr6->addr.sin6_scope_id = ifr->ifr6_ifindex;
              memcpy(&addr6->addr.sin6_addr, &ifr->ifr6_addr,
                     sizeof(struct in6_addr));

              addr6->netmask.sin6_family = AF_INET6;
              addr6->netmask.sin6_port = 0;
              addr6->netmask.sin6_flowinfo = 0;
              addr6->addr.sin6_scope_id = ifr->ifr6_ifindex;
              memcpy(&addr6->netmask.sin6_addr, &ifr->ifr6_addr,
                     sizeof(struct in6_addr));
              *((uint128_t *)&(addr6->netmask.sin6_addr)) &=
                  (UINT128_MAX >> ifr->ifr6_prefixlen);

              if (!ioctl(fd, SIOCGIFFLAGS, ifr)) {
                addr6->ifaddrs.ifa_flags = ifr->ifr_flags;
              }

              bzero(&addr6->bstaddr, sizeof(struct sockaddr_in6));
              addr6->ifaddrs.ifa_next = res;
              res = (struct ifaddrs *)addr6;
            }
          }
        }
        // one AF_PACKET entry per interface, in front like linux
        char names[64][IFNAMSIZ];
        int nnames = 0;
        for (struct ifreq *ifr = (struct ifreq *)data;
             (char *)ifr < data + conf.ifc_len && nnames < 64; ++ifr) {
          char base[IFNAMSIZ];
          size_t len = strcspn(ifr->ifr_name, ":");
          int dup = 0;
          if (!len || len >= IFNAMSIZ)
            continue;
          memcpy(base, ifr->ifr_name, len);
          base[len] = 0;
          for (int i = 0; i < nnames; ++i)
            if (!strcmp(names[i], base))
              dup = 1;
          if (dup)
            continue;
          strcpy(names[nnames++], base);
          struct ifreq hw = {0};
          strcpy(hw.ifr_name, base);
          if (ioctl(fd, SIOCGIFHWADDR, &hw))
            continue;
          struct IfAddrLL *ll;
          if (!(ll = calloc(1, sizeof(*ll))))
            continue;
          strcpy(ll->name, base);
          ll->ifaddrs.ifa_name = ll->name;
          ll->ifaddrs.ifa_addr = (struct sockaddr *)&ll->addr;
          ll->addr.sll_family = AF_PACKET;
          ll->addr.sll_ifindex = if_nametoindex(base);
          ll->addr.sll_hatype = hw.ifr_hwaddr.sa_family;
          ll->addr.sll_halen = 6;
          memcpy(ll->addr.sll_addr, hw.ifr_hwaddr.sa_data, 6);
          struct ifreq fl = {0};
          strcpy(fl.ifr_name, base);
          if (!ioctl(fd, SIOCGIFFLAGS, &fl))
            ll->ifaddrs.ifa_flags = (unsigned short)fl.ifr_flags;
          ll->ifaddrs.ifa_next = res;
          res = (struct ifaddrs *)ll;
        }
        *out_ifpp = res;
        rc = 0;
      }
      free(data);
    }
    close(fd);
  }
  return rc;
}

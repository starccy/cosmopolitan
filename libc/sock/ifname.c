#include "libc/calls/calls.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/mem/mem.h"
#include "libc/sock/ifname.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/ifconf.h"
#include "libc/sock/struct/ifreq.h"
#include "libc/calls/struct/dirent.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/sio.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/errfuns.h"

// An interface has both a name and a small integer index, which is what
// an IPv6 scope id or a multicast socket option carries. Linux and
// Windows answer SIOCGIFINDEX and SIOCGIFNAME, and FreeBSD the former.
// XNU lists both in the NET_RT_IFLIST sysctl. Elsewhere the interfaces
// are numbered in the order the host lists them, which round-trips
// between these three calls, but isn't the kernel's.

#define MAX_IFS 128

typedef char ifname_t[IFNAMSIZ];

static int IfSocket(void) {
  return socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
}

// "<name>:<n>" names one address of an interface. SIOCGIFCONF repeats an
// interface once per address, so the part in front is listed once.
static int AddName(ifname_t *out, int n, int max, const char *name) {
  ifname_t base;
  size_t len = strcspn(name, ":");
  if (n >= max || !len || len >= IFNAMSIZ)
    return n;
  memcpy(base, name, len);
  base[len] = 0;
  for (int i = 0; i < n; ++i)
    if (!strcmp(out[i], base))
      return n;
  strcpy(out[n], base);
  return n + 1;
}

// SIOCGIFCONF is an IPv4 address list, so on Linux the interfaces come
// from sysfs, when it's mounted
static int ListFromSysfs(ifname_t *out, int max) {
  int n = 0;
  DIR *d;
  struct dirent *e;
  if (!(d = opendir("/sys/class/net")))
    return -1;
  while ((e = readdir(d)))
    if (e->d_name[0] != '.')
      n = AddName(out, n, max, e->d_name);
  closedir(d);
  return n ? n : -1;
}

static int ListFromIoctl(ifname_t *out, int max) {
  int fd, n = -1;
  struct ifconf ifc;
  size_t bytes = MAX_IFS * sizeof(struct ifreq);
  if ((fd = IfSocket()) == -1)
    return -1;
  if (!(ifc.ifc_buf = malloc(bytes))) {
    close(fd);
    return -1;
  }
  ifc.ifc_len = bytes;
  if (ioctl(fd, SIOCGIFCONF, &ifc) != -1) {
    int count = ifc.ifc_len / sizeof(struct ifreq);
    n = 0;
    for (int i = 0; i < count; ++i) {
      ifname_t name;
      memcpy(name, ifc.ifc_req[i].ifr_name, IFNAMSIZ - 1);
      name[IFNAMSIZ - 1] = 0;
      n = AddName(out, n, max, name);
    }
  }
  free(ifc.ifc_buf);
  close(fd);
  return n;
}

// one RTM_IFINFO message per interface: a struct if_msghdr, whose
// ifm_index sits at byte 12 and which is 112 bytes long, followed by a
// struct sockaddr_dl holding the name
static int ListFromXnu(ifname_t *out, unsigned *idx, int max) {
  int mib[6] = {4 /* CTL_NET */, 17 /* PF_ROUTE */, 0, 0,
                3 /* NET_RT_IFLIST */, 0};
  size_t len = 0;
  char *buf;
  int n = 0;
  if (sysctl(mib, 6, 0, &len, 0, 0) == -1 || !(buf = malloc(len)))
    return -1;
  if (sysctl(mib, 6, buf, &len, 0, 0) == -1) {
    free(buf);
    return -1;
  }
  for (size_t i = 0; i + 4 <= len && n < max;) {
    uint16_t msglen, index;
    int addrs;
    memcpy(&msglen, buf + i, 2);
    if (!msglen || msglen > len - i)
      break;
    memcpy(&addrs, buf + i + 4, 4);
    memcpy(&index, buf + i + 12, 2);
    const unsigned char *sdl = (const unsigned char *)buf + i + 112;
    if (buf[i + 3] == 0xe /* RTM_IFINFO */ && (addrs & 0x10 /* RTA_IFP */) &&
        msglen >= 112 + 8 && sdl[1] == 18 /* AF_LINK */ && sdl[5] &&
        sdl[5] < IFNAMSIZ && 8 + sdl[5] <= msglen - 112) {
      memcpy(out[n], sdl + 8, sdl[5]);
      out[n][sdl[5]] = 0;
      idx[n++] = index;
    }
    i += msglen;
  }
  free(buf);
  return n;
}

static unsigned XnuIndex(const char *name) {
  ifname_t names[MAX_IFS];
  unsigned idx[MAX_IFS];
  int n = ListFromXnu(names, idx, MAX_IFS);
  for (int i = 0; i < n; ++i)
    if (!strcmp(names[i], name))
      return idx[i];
  return 0;
}

static int ListNames(ifname_t *out, int max) {
  if (IsXnu()) {
    unsigned idx[MAX_IFS];
    int n = ListFromXnu(out, idx, max < MAX_IFS ? max : MAX_IFS);
    if (n > 0)
      return n;
  }
  if (IsLinux()) {
    int n = ListFromSysfs(out, max);
    if (n > 0)
      return n;
  }
  return ListFromIoctl(out, max);
}

static unsigned SynthIndex(const char *name) {
  ifname_t names[MAX_IFS];
  int n = ListNames(names, MAX_IFS);
  for (int i = 0; i < n; ++i)
    if (!strcmp(names[i], name))
      return i + 1;
  return 0;
}

/**
 * Returns index of network interface.
 *
 * @return index, or 0 w/ errno
 * @raise ENODEV if no interface has that name
 */
unsigned if_nametoindex(const char *name) {
  int fd;
  unsigned idx = 0;
  if (!name || !name[0] || strlen(name) >= IFNAMSIZ) {
    enodev();
    return 0;
  }
  if (IsXnu()) {
    idx = XnuIndex(name);
  } else if ((fd = IfSocket()) != -1) {
    struct ifreq r = {0};
    strcpy(r.ifr_name, name);
    if (ioctl(fd, SIOCGIFINDEX, &r) != -1 && r.ifr_ifindex > 0)
      idx = r.ifr_ifindex;
    close(fd);
  }
  if (!idx)
    idx = SynthIndex(name);
  if (!idx)
    enodev();
  return idx;
}

/**
 * Returns name of network interface.
 *
 * @param name receives up to IFNAMSIZ bytes
 * @return name, or NULL w/ errno
 * @raise ENXIO if no interface has that index
 */
char *if_indextoname(unsigned index, char *name) {
  int fd;
  ifname_t names[MAX_IFS];
  if (!index || !name) {
    enxio();
    return 0;
  }
  if (!IsXnu() && (fd = IfSocket()) != -1) {
    struct ifreq r = {0};
    r.ifr_ifindex = index;
    bool ok = ioctl(fd, SIOCGIFNAME, &r) != -1 && r.ifr_name[0];
    close(fd);
    if (ok) {
      memcpy(name, r.ifr_name, IFNAMSIZ - 1);
      name[IFNAMSIZ - 1] = 0;
      return name;
    }
  }
  int n = ListNames(names, MAX_IFS);
  for (int i = 0; i < n; ++i)
    if (if_nametoindex(names[i]) == index)
      return strcpy(name, names[i]);
  enxio();
  return 0;
}

/**
 * Lists network interfaces.
 *
 * @return zero-terminated array, which if_freenameindex() frees, or
 *     NULL w/ errno
 */
struct if_nameindex *if_nameindex(void) {
  ifname_t names[MAX_IFS];
  int n = ListNames(names, MAX_IFS);
  if (n < 0) {
    enobufs();
    return 0;
  }
  // one allocation holds the table, its terminator and the strings
  struct if_nameindex *t =
      calloc(1, (n + 1) * sizeof(struct if_nameindex) + n * IFNAMSIZ);
  if (!t) {
    enobufs();
    return 0;
  }
  char *strings = (char *)(t + n + 1);
  for (int i = 0; i < n; ++i) {
    t[i].if_index = if_nametoindex(names[i]);
    t[i].if_name = strings + i * IFNAMSIZ;
    strcpy(t[i].if_name, names[i]);
  }
  // in index order, the way the kernel lists them to glibc
  for (int i = 1; i < n; ++i)
    for (int j = i; j > 0 && t[j - 1].if_index > t[j].if_index; --j) {
      struct if_nameindex x = t[j];
      t[j] = t[j - 1];
      t[j - 1] = x;
    }
  return t;
}

void if_freenameindex(struct if_nameindex *p) {
  free(p);
}

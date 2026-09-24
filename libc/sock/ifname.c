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
// Elsewhere the interfaces are numbered in the order the host lists them,
// which round-trips between these three calls, but isn't the kernel's.

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

static int ListNames(ifname_t *out, int max) {
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
  if ((fd = IfSocket()) != -1) {
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
  if ((fd = IfSocket()) != -1) {
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
  return t;
}

void if_freenameindex(struct if_nameindex *p) {
  free(p);
}

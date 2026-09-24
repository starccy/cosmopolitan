#include "libc/dce.h"
#include "libc/sock/struct/cmsghdr.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/sol.h"

/*
 * The BSDs lay out struct cmsghdr as {u32 len; i32 level; i32 type}
 * with entries aligned to 4 on XNU and 8 elsewhere. Linux, and cosmo,
 * use a 16 byte header aligned to 8.
 */

__HOSTCONST(int, SOL_SOCKET);

#define BSD_HDR 12

static size_t align_bsd(size_t n) {
  size_t a = IsXnu() ? 4 : 8;
  return (n + a - 1) & ~(a - 1);
}

static void level2host(int32_t *level, int32_t *type) {
  if (*level == SOL_SOCKET) {
    *level = __host_SOL_SOCKET;
  } else if (*level == SOL_IP || *level == SOL_IPV6) {
    *type = __sockopt2host(*level, *type);
  }
}

static void level2linux(int32_t *level, int32_t *type) {
  if (*level == __host_SOL_SOCKET) {
    *level = SOL_SOCKET;
  } else if (*level == SOL_IP || *level == SOL_IPV6) {
    *type = __sockopt2linux(*level, *type);
  }
}

/**
 * Converts a Linux control buffer into the host BSD's layout.
 *
 * `dst` never needs more room than `srclen`.
 *
 * @return byte length written to `dst`, or -1 if it didn't fit
 */
ssize_t __cmsg2bsd(const void *src, size_t srclen, void *dst, size_t dstcap) {
  const unsigned char *s = src;
  unsigned char *d = dst;
  size_t si = 0, di = 0;
  while (si + sizeof(struct cmsghdr) <= srclen) {
    struct cmsghdr h;
    memcpy(&h, s + si, sizeof(h));
    if (h.cmsg_len < sizeof(h) || h.cmsg_len > srclen - si)
      break;
    size_t payload = h.cmsg_len - sizeof(h);
    size_t blen = BSD_HDR + payload;
    if (align_bsd(blen) > dstcap - di)
      return -1;
    level2host(&h.cmsg_level, &h.cmsg_type);
    uint32_t len32 = blen;
    memcpy(d + di, &len32, 4);
    memcpy(d + di + 4, &h.cmsg_level, 4);
    memcpy(d + di + 8, &h.cmsg_type, 4);
    memcpy(d + di + BSD_HDR, s + si + sizeof(h), payload);
    di += align_bsd(blen);
    si += CMSG_ALIGN(h.cmsg_len);
  }
  return di;
}

/**
 * Converts a host BSD control buffer into Linux's layout.
 *
 * The Linux form is larger per entry, so a result that outgrows
 * `dstcap` is cut at an entry boundary, the way MSG_CTRUNC does it.
 *
 * @return byte length written to `dst`
 */
size_t __cmsg2linux(const void *src, size_t srclen, void *dst, size_t dstcap) {
  const unsigned char *s = src;
  unsigned char *d = dst;
  size_t si = 0, di = 0;
  while (si + BSD_HDR <= srclen) {
    uint32_t blen;
    struct cmsghdr h = {0};
    memcpy(&blen, s + si, 4);
    if (blen < BSD_HDR || blen > srclen - si)
      break;
    size_t payload = blen - BSD_HDR;
    h.cmsg_len = sizeof(h) + payload;
    if (CMSG_ALIGN(h.cmsg_len) > dstcap - di)
      break;
    memcpy(&h.cmsg_level, s + si + 4, 4);
    memcpy(&h.cmsg_type, s + si + 8, 4);
    level2linux(&h.cmsg_level, &h.cmsg_type);
    memcpy(d + di, &h, sizeof(h));
    memcpy(d + di + sizeof(h), s + si + BSD_HDR, payload);
    di += CMSG_ALIGN(h.cmsg_len);
    si += align_bsd(blen);
  }
  return di;
}

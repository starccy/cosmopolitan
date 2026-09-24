#include "libc/dce.h"
#include "libc/sysv/consts/fio.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/modem.h"
#include "libc/sysv/consts/pty.h"
#include "libc/sysv/consts/sio.h"
#include "libc/sysv/consts/termios.h"

#define REQUESTS(X)                                                        \
  X(FIONREAD) X(FIONBIO) X(FIOASYNC) X(FIOCLEX) X(FIONCLEX)                \
  X(TCGETS) X(TCSETS) X(TIOCGWINSZ) X(TIOCSWINSZ) X(TIOCOUTQ) X(TIOCSPGRP) \
  X(TIOCCONS) X(TIOCGETD) X(TIOCNOTTY) X(TIOCNXCL) X(TIOCSCTTY) X(TIOCSETD) \
  X(TIOCSIG) X(TIOCSTI) X(TIOCPKT) X(TIOCMGET) X(TIOCMSET) X(TIOCMBIC)     \
  X(TIOCMBIS) X(SIOCGIFCONF) X(SIOCADDMULTI) X(SIOCDELMULTI)               \
  X(SIOCDIFADDR) X(SIOCGIFADDR) X(SIOCGIFBRDADDR) X(SIOCGIFDSTADDR)        \
  X(SIOCGIFFLAGS) X(SIOCGIFMETRIC) X(SIOCGIFNETMASK) X(SIOCGPGRP)          \
  X(SIOCSIFADDR) X(SIOCSIFBRDADDR) X(SIOCSIFDSTADDR) X(SIOCSIFFLAGS)       \
  X(SIOCSIFMETRIC) X(SIOCSIFNETMASK) X(SIOCSPGRP) X(SIOCGIFMTU)            \
  X(SIOCSIFMTU) X(SIOCGIFINDEX) X(SIOCSIFNAME) X(SIOCADDDLCI) X(SIOCADDRT) \
  X(SIOCDARP) X(SIOCDELDLCI) X(SIOCDELRT) X(SIOCDEVPRIVATE) X(SIOCDRARP)   \
  X(SIOCGARP) X(SIOCGIFBR) X(SIOCGIFCOUNT) X(SIOCGIFENCAP) X(SIOCGIFHWADDR) \
  X(SIOCGIFMAP) X(SIOCGIFMEM) X(SIOCGIFNAME) X(SIOCGIFPFLAGS)              \
  X(SIOCGIFSLAVE) X(SIOCGIFTXQLEN) X(SIOCGRARP) X(SIOCGSTAMP)              \
  X(SIOCGSTAMPNS) X(SIOCPROTOPRIVATE) X(SIOCRTMSG) X(SIOCSARP) X(SIOCSIFBR) \
  X(SIOCSIFENCAP) X(SIOCSIFHWADDR) X(SIOCSIFHWBROADCAST) X(SIOCSIFLINK)    \
  X(SIOCSIFMAP) X(SIOCSIFMEM) X(SIOCSIFPFLAGS) X(SIOCSIFSLAVE)             \
  X(SIOCSIFTXQLEN) X(SIOCSRARP)

#define DECL(NAME) extern const unsigned long __host_##NAME __asm__(#NAME);
REQUESTS(DECL)

#define ENTRY(NAME) {NAME, &__host_##NAME},
static const struct {
  unsigned long linux;
  const unsigned long *host;
} kRequests[] = {REQUESTS(ENTRY)};

/**
 * Turns an ioctl request into the host's number for it.
 *
 * On Windows this yields what ioctlsocket() takes. TCSETSW and TCSETSF
 * follow TCSETS on every host, so they're derived. Requests cosmo has no
 * name for pass through as they are.
 *
 * @return host request, or 0 if the host has no such request
 */
unsigned long __ioctl2host(unsigned long request) {
  if (IsLinux())
    return request;
  if (request == TCSETSW || request == TCSETSF)
    return __host_TCSETS ? __host_TCSETS + (request - TCSETS) : 0;
  for (int i = 0; i < sizeof(kRequests) / sizeof(*kRequests); ++i)
    if (request == kRequests[i].linux)
      return *kRequests[i].host;
  return request;
}

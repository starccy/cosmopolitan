#include "libc/dce.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/iff.h"

#define IFF_NAMES(X)    \
  X(IFF_UP)             \
  X(IFF_BROADCAST)      \
  X(IFF_DEBUG)          \
  X(IFF_LOOPBACK)       \
  X(IFF_POINTOPOINT)    \
  X(IFF_NOTRAILERS)     \
  X(IFF_RUNNING)        \
  X(IFF_NOARP)          \
  X(IFF_PROMISC)        \
  X(IFF_ALLMULTI)       \
  X(IFF_MASTER)         \
  X(IFF_SLAVE)          \
  X(IFF_MULTICAST)      \
  X(IFF_PORTSEL)        \
  X(IFF_AUTOMEDIA)      \
  X(IFF_DYNAMIC)

#define DECL(NAME) extern const int __host_##NAME __asm__(#NAME);
IFF_NAMES(DECL)

#define ENTRY(NAME) {NAME, &__host_##NAME},
static const struct {
  int linux;
  const int *host;
} kIff[] = {IFF_NAMES(ENTRY)};

/**
 * Turns the host's interface flags into Linux bits.
 *
 * Windows never gets here: its flags are made up from Linux names.
 */
int __iff2linux(int flags) {
  if (IsLinux() || IsWindows())
    return flags;
  int linux = 0;
  for (int i = 0; i < sizeof(kIff) / sizeof(*kIff); ++i)
    if (*kIff[i].host && (flags & *kIff[i].host))
      linux |= kIff[i].linux;
  return linux;
}

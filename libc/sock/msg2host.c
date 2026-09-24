#include "libc/dce.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/msg.h"

__HOSTCONST(int, MSG_DONTWAIT);
__HOSTCONST(int, MSG_WAITALL);
__HOSTCONST(int, MSG_NOSIGNAL);
__HOSTCONST(int, MSG_TRUNC);
__HOSTCONST(int, MSG_CTRUNC);
__HOSTCONST(int, MSG_FASTOPEN);

static const struct {
  int linux;
  const int *host;
} kMsg[] = {
    {MSG_DONTWAIT, &__host_MSG_DONTWAIT},  //
    {MSG_WAITALL, &__host_MSG_WAITALL},    //
    {MSG_NOSIGNAL, &__host_MSG_NOSIGNAL},  //
    {MSG_TRUNC, &__host_MSG_TRUNC},        //
    {MSG_CTRUNC, &__host_MSG_CTRUNC},      //
    {MSG_FASTOPEN, &__host_MSG_FASTOPEN},  //
};

#define MSG_SAME (MSG_OOB | MSG_PEEK | MSG_DONTROUTE)

/**
 * Turns send/recv flags into the host's bits.
 *
 * On Windows the result is consts.sh's Windows column, which the NT
 * code strips its own inventions from before calling WinSock.
 *
 * @return host flags, or -1 if a flag isn't a name or the host lacks it
 */
int __msg2host(int flags) {
  if (IsLinux())
    return flags;
  int host = flags & MSG_SAME;
  flags &= ~MSG_SAME;
  for (int i = 0; i < sizeof(kMsg) / sizeof(*kMsg); ++i) {
    if (flags & kMsg[i].linux) {
      if (*kMsg[i].host <= 0)
        return -1;
      host |= *kMsg[i].host;
      flags &= ~kMsg[i].linux;
    }
  }
  return flags ? -1 : host;
}

/**
 * Turns the host's msg_flags back into Linux bits.
 */
int __msg2linux(int flags) {
  if (IsLinux())
    return flags;
  int linux = flags & MSG_SAME;
  for (int i = 0; i < sizeof(kMsg) / sizeof(*kMsg); ++i)
    if (*kMsg[i].host > 0 && (flags & *kMsg[i].host))
      linux |= kMsg[i].linux;
  return linux;
}

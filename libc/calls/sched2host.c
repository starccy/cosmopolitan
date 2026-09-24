#include "libc/dce.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/sched.h"

__HOSTCONST(int, SCHED_OTHER);
__HOSTCONST(int, SCHED_FIFO);
__HOSTCONST(int, SCHED_RR);
__HOSTCONST(int, SCHED_BATCH);
__HOSTCONST(int, SCHED_IDLE);
__HOSTCONST(int, SCHED_DEADLINE);

static const struct {
  int linux;
  const int *host;
} kSched[] = {
    {SCHED_OTHER, &__host_SCHED_OTHER},        //
    {SCHED_FIFO, &__host_SCHED_FIFO},          //
    {SCHED_RR, &__host_SCHED_RR},              //
    {SCHED_BATCH, &__host_SCHED_BATCH},        //
    {SCHED_IDLE, &__host_SCHED_IDLE},          //
    {SCHED_DEADLINE, &__host_SCHED_DEADLINE},  //
};

/**
 * Turns scheduling policy into the host's number for it.
 *
 * `SCHED_RESET_ON_FORK` only exists on Linux and is dropped elsewhere.
 *
 * @return host policy, or 127 if the host has no such policy
 */
int __sched2host(int policy) {
  if (IsLinux())
    return policy;
  policy &= ~SCHED_RESET_ON_FORK;
  for (int i = 0; i < sizeof(kSched) / sizeof(*kSched); ++i)
    if (policy == kSched[i].linux)
      return *kSched[i].host;
  return 127;
}

/**
 * Turns the host's scheduling policy number back into a Linux one.
 *
 * Several Linux policies can share one host number, in which case the
 * first of other, fifo and rr wins.
 */
int __sched2linux(int policy) {
  if (IsLinux() || policy < 0)
    return policy;
  for (int i = 0; i < sizeof(kSched) / sizeof(*kSched); ++i)
    if (*kSched[i].host != 127 && policy == *kSched[i].host)
      return kSched[i].linux;
  return policy;
}

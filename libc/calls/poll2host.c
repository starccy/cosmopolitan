#include "libc/dce.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/poll.h"

__HOSTCONST(int16_t, POLLIN);
__HOSTCONST(int16_t, POLLPRI);
__HOSTCONST(int16_t, POLLOUT);
__HOSTCONST(int16_t, POLLERR);
__HOSTCONST(int16_t, POLLHUP);
__HOSTCONST(int16_t, POLLNVAL);
__HOSTCONST(int16_t, POLLRDNORM);
__HOSTCONST(int16_t, POLLRDBAND);
__HOSTCONST(int16_t, POLLWRNORM);
__HOSTCONST(int16_t, POLLWRBAND);
__HOSTCONST(int16_t, POLLRDHUP);

static const struct {
  int16_t linux;
  const int16_t *host;
} kPoll[] = {
    {POLLIN, &__host_POLLIN},          //
    {POLLPRI, &__host_POLLPRI},        //
    {POLLOUT, &__host_POLLOUT},        //
    {POLLERR, &__host_POLLERR},        //
    {POLLHUP, &__host_POLLHUP},        //
    {POLLNVAL, &__host_POLLNVAL},      //
    {POLLRDNORM, &__host_POLLRDNORM},  //
    {POLLRDBAND, &__host_POLLRDBAND},  //
    {POLLWRNORM, &__host_POLLWRNORM},  //
    {POLLWRBAND, &__host_POLLWRBAND},  //
    {POLLRDHUP, &__host_POLLRDHUP},    //
};

/**
 * Turns pollfd events into the bits the host kernel wants.
 *
 * On Windows the result is what WSAPoll() takes. Bits that aren't any
 * POLL* name are dropped.
 */
int __poll2host(int events) {
  if (IsLinux())
    return events;
  int host = 0;
  for (int i = 0; i < sizeof(kPoll) / sizeof(*kPoll); ++i)
    if (events & kPoll[i].linux)
      host |= *kPoll[i].host;
  return host;
}

/**
 * Turns the host's revents back into Linux bits.
 *
 * A host bit that stands for several names lights all of them, e.g.
 * POLLHUP on the BSDs is also their POLLRDHUP. Callers mask the result
 * with what was asked for, the way Linux does.
 */
int __poll2linux(int revents) {
  if (IsLinux())
    return revents;
  int linux = 0;
  for (int i = 0; i < sizeof(kPoll) / sizeof(*kPoll); ++i)
    if (*kPoll[i].host && (revents & *kPoll[i].host))
      linux |= kPoll[i].linux;
  return linux;
}

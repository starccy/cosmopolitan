#ifndef COSMOPOLITAN_LIBC_CALLS_STRUCT_ITIMERSPEC_H_
#define COSMOPOLITAN_LIBC_CALLS_STRUCT_ITIMERSPEC_H_
#include "libc/calls/struct/timespec.h"
COSMOPOLITAN_C_START_

struct itimerspec {
  struct timespec it_interval;
  struct timespec it_value;
};

int timerfd_settime(int, int, const struct itimerspec *, struct itimerspec *)
    libcesque;
int timerfd_gettime(int, struct itimerspec *) libcesque;
int timer_settime(void *, int, const struct itimerspec *, struct itimerspec *)
    libcesque;
int timer_gettime(void *, struct itimerspec *) libcesque;

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_STRUCT_ITIMERSPEC_H_ */

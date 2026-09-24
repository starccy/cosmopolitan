#ifndef COSMOPOLITAN_LIBC_ISYSTEM_SYS_TIMERFD_H_
#define COSMOPOLITAN_LIBC_ISYSTEM_SYS_TIMERFD_H_
#include "libc/calls/calls.h"
#include "libc/calls/struct/itimerspec.h"

#define TFD_CLOEXEC             0x80000
#define TFD_NONBLOCK            0x800
#define TFD_TIMER_ABSTIME       1
#define TFD_TIMER_CANCEL_ON_SET 2

#endif /* COSMOPOLITAN_LIBC_ISYSTEM_SYS_TIMERFD_H_ */

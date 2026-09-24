#ifndef COSMOPOLITAN_LIBC_CALLS_STRUCT_SIGEVENT_H_
#define COSMOPOLITAN_LIBC_CALLS_STRUCT_SIGEVENT_H_
#include "libc/calls/struct/sigval.h"
#include "libc/calls/weirdtypes.h"
#include "libc/thread/thread.h"
COSMOPOLITAN_C_START_

#define SIGEV_SIGNAL    0
#define SIGEV_NONE      1
#define SIGEV_THREAD    2
#define SIGEV_THREAD_ID 4

struct sigevent {
  union sigval sigev_value;
  int sigev_signo;
  int sigev_notify;
  union {
    int _tid;
    struct {
      void (*_function)(union sigval);
      pthread_attr_t *_attribute;
    } _thread;
    char _pad[48];
  } _sigev_un;
};

#define sigev_notify_function   _sigev_un._thread._function
#define sigev_notify_attributes _sigev_un._thread._attribute
#define sigev_notify_thread_id  _sigev_un._tid

int timer_create(int, struct sigevent *, timer_t *) libcesque;
int timer_delete(timer_t) libcesque;
int timer_getoverrun(timer_t) libcesque;

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_STRUCT_SIGEVENT_H_ */

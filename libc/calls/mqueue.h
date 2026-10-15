#ifndef COSMOPOLITAN_LIBC_CALLS_MQUEUE_H_
#define COSMOPOLITAN_LIBC_CALLS_MQUEUE_H_
#include "libc/calls/struct/sigevent.h"
#include "libc/calls/struct/timespec.h"
COSMOPOLITAN_C_START_

typedef int mqd_t;

struct mq_attr {
  long mq_flags;
  long mq_maxmsg;
  long mq_msgsize;
  long mq_curmsgs;
  long __unused[4];
};

mqd_t mq_open(const char *, int, ...);
int mq_close(mqd_t);
int mq_unlink(const char *);
int mq_send(mqd_t, const char *, size_t, unsigned);
int mq_timedsend(mqd_t, const char *, size_t, unsigned,
                 const struct timespec *);
ssize_t mq_receive(mqd_t, char *, size_t, unsigned *);
ssize_t mq_timedreceive(mqd_t, char *, size_t, unsigned *,
                        const struct timespec *);
int mq_getattr(mqd_t, struct mq_attr *);
int mq_setattr(mqd_t, const struct mq_attr *, struct mq_attr *);
int mq_notify(mqd_t, const struct sigevent *);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_MQUEUE_H_ */

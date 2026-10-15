#include "libc/calls/calls.h"
#include "libc/calls/mqueue.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/calls/struct/timespec.internal.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/errfuns.h"

// POSIX message queues. Linux has them in the kernel and that is the
// only host with them: everything here says ENOSYS elsewhere. Queue
// names begin with a slash which the kernel does not want to see.

static const char *mq_name(const char *name) {
  if (!name || name[0] != '/')
    return 0;
  return name + 1;
}

/**
 * Opens message queue.
 *
 * @param name begins with a slash
 * @param oflag has `O_RDONLY`, `O_WRONLY` or `O_RDWR`, and may have
 *     `O_CREAT`, `O_EXCL` and `O_NONBLOCK`; with `O_CREAT` a mode and a
 *     `struct mq_attr *` (which may be NULL) follow
 * @return queue descriptor on success, or -1 w/ errno
 * @raise ENOSYS if not Linux
 */
mqd_t mq_open(const char *name, int oflag, ...) {
  int rc;
  unsigned mode = 0;
  struct mq_attr *attr = 0;
  const char *kname;
  if (oflag & O_CREAT) {
    va_list va;
    va_start(va, oflag);
    mode = va_arg(va, unsigned);
    attr = va_arg(va, struct mq_attr *);
    va_end(va);
  }
  if (!IsLinux()) {
    rc = enosys();
  } else if (!(kname = mq_name(name))) {
    rc = einval();
  } else {
    rc = sys_mq_open(kname, oflag, mode, attr);
  }
  STRACE("mq_open(%#s, %#x, %#o, %p) → %d% m", name, oflag, mode, attr, rc);
  return rc;
}

int mq_close(mqd_t mqd) {
  return close(mqd);
}

int mq_unlink(const char *name) {
  int rc;
  const char *kname;
  if (!IsLinux()) {
    rc = enosys();
  } else if (!(kname = mq_name(name))) {
    rc = einval();
  } else {
    rc = sys_mq_unlink(kname);
  }
  STRACE("mq_unlink(%#s) → %d% m", name, rc);
  return rc;
}

int mq_timedsend(mqd_t mqd, const char *msg, size_t len, unsigned prio,
                 const struct timespec *abstime) {
  int rc;
  if (!IsLinux()) {
    rc = enosys();
  } else {
    rc = sys_mq_timedsend(mqd, msg, len, prio, abstime);
  }
  STRACE("mq_timedsend(%d, %p, %'zu, %u, %s) → %d% m", mqd, msg, len, prio,
         DescribeTimespec(0, abstime), rc);
  return rc;
}

int mq_send(mqd_t mqd, const char *msg, size_t len, unsigned prio) {
  return mq_timedsend(mqd, msg, len, prio, 0);
}

ssize_t mq_timedreceive(mqd_t mqd, char *buf, size_t len, unsigned *prio,
                        const struct timespec *abstime) {
  ssize_t rc;
  if (!IsLinux()) {
    rc = enosys();
  } else {
    rc = sys_mq_timedreceive(mqd, buf, len, prio, abstime);
  }
  STRACE("mq_timedreceive(%d, %p, %'zu, %p, %s) → %ld% m", mqd, buf, len,
         prio, DescribeTimespec(0, abstime), rc);
  return rc;
}

ssize_t mq_receive(mqd_t mqd, char *buf, size_t len, unsigned *prio) {
  return mq_timedreceive(mqd, buf, len, prio, 0);
}

int mq_getattr(mqd_t mqd, struct mq_attr *attr) {
  int rc;
  if (!IsLinux()) {
    rc = enosys();
  } else {
    rc = sys_mq_getsetattr(mqd, 0, attr);
  }
  STRACE("mq_getattr(%d, %p) → %d% m", mqd, attr, rc);
  return rc;
}

/**
 * Sets message queue attributes.
 *
 * Only `mq_flags` is changeable, and only its `O_NONBLOCK` bit.
 */
int mq_setattr(mqd_t mqd, const struct mq_attr *attr, struct mq_attr *old) {
  int rc;
  if (!IsLinux()) {
    rc = enosys();
  } else {
    rc = sys_mq_getsetattr(mqd, attr, old);
  }
  STRACE("mq_setattr(%d, %p, %p) → %d% m", mqd, attr, old, rc);
  return rc;
}

/**
 * Asks to be told when a message arrives on an empty queue.
 *
 * `SIGEV_SIGNAL` and `SIGEV_NONE` go to the kernel. `SIGEV_THREAD`
 * needs the netlink helper thread glibc runs, which doesn't exist
 * here, so it's refused.
 *
 * @param sev may be NULL to remove the registration
 * @return 0 on success, or -1 w/ errno
 * @raise ENOTSUP for `SIGEV_THREAD`
 * @raise ENOSYS if not Linux
 */
int mq_notify(mqd_t mqd, const struct sigevent *sev) {
  int rc;
  if (!IsLinux()) {
    rc = enosys();
  } else if (sev && sev->sigev_notify == SIGEV_THREAD) {
    rc = enotsup();
  } else {
    rc = sys_mq_notify(mqd, sev);
  }
  STRACE("mq_notify(%d, %p) → %d% m", mqd, sev, rc);
  return rc;
}

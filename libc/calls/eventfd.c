#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/iovec.h"
#include "libc/nt/events.h"
#include "libc/sock/struct/pollfd.h"
#include "libc/sysv/consts/poll.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/strace.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/efd.h"
#include "libc/sysv/consts/f.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

/**
 * @fileoverview eventfd for every host.
 *
 * Linux has it. Elsewhere the counter lives in the fd table entry and
 * only the wakeup needs the kernel: on Windows that's an event object
 * (eventfd-nt.c), which poll() waits on directly; on XNU and the BSDs
 * it's a unix socket pair, one end handed out and the other kept, with
 * a byte in flight whenever the counter is nonzero, so the kernel's
 * own poll() and read() do the waiting and the end the caller holds
 * polls writable like an eventfd does. Every write puts a byte on the
 * wire, so a kqueue watching the caller's end in edge mode sees each
 * one the way epoll does on Linux; the queue is emptied once the
 * counter reads back to zero. What differs from Linux there: a dup()
 * shares the wakeup but not the counter.
 */

#define EFD_MAX 0xfffffffffffffffeull

// what a read takes: the whole counter, or 1 in semaphore mode; 0 when
// there's nothing
uint64_t __eventfd_take(struct Fd *f) {
  uint64_t old = __atomic_load_n(&f->evcount, __ATOMIC_RELAXED);
  for (;;) {
    if (!old)
      return 0;
    uint64_t take = (f->evflags & EFD_SEMAPHORE) ? 1 : old;
    if (__atomic_compare_exchange_n(&f->evcount, &old, old - take, true,
                                    __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
      return take;
  }
}

// adds to the counter; false when that would overflow it
bool __eventfd_add(struct Fd *f, uint64_t v, bool *was_zero) {
  uint64_t old = __atomic_load_n(&f->evcount, __ATOMIC_RELAXED);
  for (;;) {
    if (v > EFD_MAX - old)
      return false;
    if (__atomic_compare_exchange_n(&f->evcount, &old, old + v, true,
                                    __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
      *was_zero = !old;
      return true;
    }
  }
}

// AF_UNIX and SOCK_STREAM are 1 on every host, so the raw call will do
static int sys_eventfd_pipe(unsigned initval, int flags) {
  int p[2];
  if (__sys_socketpair(1, 1, 0, p) == -1)
    return -1;
  fcntl(p[1], F_SETFD, FD_CLOEXEC);
  fcntl(p[1], F_SETFL, O_NONBLOCK);
  if (flags & EFD_CLOEXEC)
    fcntl(p[0], F_SETFD, FD_CLOEXEC);
  if (flags & EFD_NONBLOCK)
    fcntl(p[0], F_SETFL, O_NONBLOCK);
  __fds_lock();
  if (__ensurefds_unlocked(p[0]) == -1) {
    __fds_unlock();
    sys_close(p[0]);
    sys_close(p[1]);
    return -1;
  }
  struct Fd *f = __get_pib()->fds.p + p[0];
  f->handle = -1;
  f->flags = O_RDWR;
  if (flags & EFD_CLOEXEC)
    f->flags |= O_CLOEXEC;
  if (flags & EFD_NONBLOCK)
    f->flags |= O_NONBLOCK;
  f->evcount = initval;
  f->evflags = flags;
  f->evpeer = p[1];
  f->kind = kFdEvent;
  __fds_unlock();
  if (initval)
    sys_write(p[1], "", 1);
  return p[0];
}

// what's queued on the caller's end, once the counter is zero
static void eventfd_drain_bytes(int fd) {
  char buf[64];
  struct pollfd p = {fd, POLLIN, 0};
  while (poll(&p, 1, 0) == 1 && (p.revents & POLLIN))
    if (sys_read(fd, buf, sizeof(buf)) <= 0)
      break;
}

// a full socket means thousands of unread wakeups; emptying it and
// queueing one fresh byte keeps the next edge from being lost
static void eventfd_kick(int fd, struct Fd *f) {
  if (sys_write(f->evpeer, "", 1) == -1 && errno == EAGAIN) {
    eventfd_drain_bytes(fd);
    sys_write(f->evpeer, "", 1);
  }
}

// a byte is in flight while the counter is nonzero, so reading one is
// the wait, and the kernel honors O_NONBLOCK and signals on it
static ssize_t eventfd_read_pipe(int fd, struct Fd *f, void *buf) {
  for (;;) {
    char c;
    ssize_t r = sys_read(fd, &c, 1);
    if (r == -1)
      return -1;
    if (!r)
      return eio();
    uint64_t v = __eventfd_take(f);
    if (!v)
      continue;
    if (__atomic_load_n(&f->evcount, __ATOMIC_RELAXED)) {
      // semaphore mode with count left: keep a byte on the wire
      sys_write(f->evpeer, &c, 1);
    } else {
      eventfd_drain_bytes(fd);
      // a write that landed between the take and the drain
      if (__atomic_load_n(&f->evcount, __ATOMIC_RELAXED))
        sys_write(f->evpeer, &c, 1);
    }
    memcpy(buf, &v, sizeof(v));
    return sizeof(v);
  }
}

static ssize_t eventfd_write_pipe(int fd, struct Fd *f, uint64_t v) {
  bool was_zero;
  while (!__eventfd_add(f, v, &was_zero)) {
    // full: a reader has to make room first
    if (fcntl(fd, F_GETFL) & O_NONBLOCK)
      return eagain();
    usleep(1000);
  }
  eventfd_kick(fd, f);
  return sizeof(v);
}

ssize_t __eventfd_read(int fd, void *buf, size_t size) {
  if (size < 8)
    return einval();
  struct Fd *f = __get_pib()->fds.p + fd;
  if (IsWindows())
    return sys_read_eventfd_nt(f, buf);
  return eventfd_read_pipe(fd, f, buf);
}

// adds to the counter and wakes the waiters; what write() does, minus
// the checks, for the code that feeds a timerfd
int __eventfd_post(int fd, uint64_t v) {
  if (!__isfdkind(fd, kFdEvent))
    return ebadf();
  struct Fd *f = __get_pib()->fds.p + fd;
  if (IsWindows())
    return sys_write_eventfd_nt(f, v) == -1 ? -1 : 0;
  return eventfd_write_pipe(fd, f, v) == -1 ? -1 : 0;
}

// forgets whatever hasn't been read yet
int __eventfd_drain(int fd) {
  if (!__isfdkind(fd, kFdEvent))
    return ebadf();
  struct Fd *f = __get_pib()->fds.p + fd;
  while (__eventfd_take(f)) {
  }
  if (IsWindows()) {
    ResetEvent(f->handle);
    if (__atomic_load_n(&f->evcount, __ATOMIC_RELAXED))
      SetEvent(f->handle);
  } else {
    eventfd_drain_bytes(fd);
    if (__atomic_load_n(&f->evcount, __ATOMIC_RELAXED))
      sys_write(f->evpeer, "", 1);
  }
  return 0;
}

ssize_t __eventfd_write(int fd, const void *buf, size_t size) {
  uint64_t v;
  if (size < 8)
    return einval();
  memcpy(&v, buf, sizeof(v));
  if (v == 0xffffffffffffffffull)
    return einval();
  struct Fd *f = __get_pib()->fds.p + fd;
  if (f->evflags & __EFD_TIMERFD)
    return einval();
  if (IsWindows())
    return sys_write_eventfd_nt(f, v);
  return eventfd_write_pipe(fd, f, v);
}

/**
 * Creates file descriptor for event notification.
 *
 * @param flags can have EFD_{CLOEXEC,NONBLOCK,SEMAPHORE}
 * @return file descriptor, or -1 w/ errno
 */
int eventfd(unsigned initval, int flags) {
  int rc;
  if (flags & ~(EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE)) {
    rc = einval();
  } else if (IsLinux()) {
    rc = sys_eventfd2(initval, flags);
  } else if (IsWindows()) {
    rc = sys_eventfd_nt(initval, flags);
  } else {
    rc = sys_eventfd_pipe(initval, flags);
  }
  STRACE("eventfd(%u, %#x) → %d% m", initval, flags, rc);
  return rc;
}

int eventfd_read(int fd, uint64_t *value) {
  return read(fd, value, sizeof(*value)) == sizeof(*value) ? 0 : -1;
}

int eventfd_write(int fd, uint64_t value) {
  return write(fd, &value, sizeof(value)) == sizeof(value) ? 0 : -1;
}

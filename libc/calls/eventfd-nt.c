#include "libc/calls/internal.h"
#include "libc/calls/sig.internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/weaken.h"
#include "libc/nt/enum/wait.h"
#include "libc/nt/events.h"
#include "libc/nt/runtime.h"
#include "libc/nt/synchronization.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/efd.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/sicode.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/thread/posixthread.internal.h"

// an eventfd on windows: the counter sits in the fd table entry, and a
// manual-reset event object is signaled exactly while it's nonzero, so
// poll() can wait on the handle like any other

textwindows int sys_eventfd_nt(unsigned initval, int flags) {
  int fd = __reservefd(-1);
  if (fd == -1)
    return -1;
  int64_t h = CreateEvent(&kNtIsInheritable, true, initval > 0, 0);
  if (!h) {
    __releasefd(fd);
    return __winerr();
  }
  struct Fd *f = __get_pib()->fds.p + fd;
  f->handle = h;
  f->flags = O_RDWR;
  if (flags & EFD_CLOEXEC)
    f->flags |= O_CLOEXEC;
  if (flags & EFD_NONBLOCK)
    f->flags |= O_NONBLOCK;
  f->mode = 0600;
  f->evcount = initval;
  f->evflags = flags;
  f->evpeer = -1;
  f->was_created_during_vfork = __vforked;
  f->kind = kFdEvent;
  return fd;
}

// blocks until the event is signaled, a signal handler ran without
// SA_RESTART, or the thread is canceled. 0 to look again, -1 w/ errno
textwindows static int WaitForEventFd(int64_t h, sigset_t waitmask) {
  intptr_t sev;
  if (!(sev = __interruptible_start(waitmask)))
    return __winerr();
  int sig = 0;
  uint32_t wi = 1;
  if (!_is_canceled() &&
      !(_weaken(__sig_get) && (sig = _weaken(__sig_get)(waitmask)))) {
    intptr_t hands[2] = {h, sev};
    wi = WaitForMultipleObjects(2, hands, 0, -1u);
  }
  __interruptible_end();
  if (wi == -1u)
    return __winerr();
  if (wi == 1) {
    int handler_was_called = 0;
    if (sig)
      handler_was_called = _weaken(__sig_relay)(sig, SI_KERNEL, waitmask);
    if (_check_cancel() == -1)
      return -1;
    if (handler_was_called & SIG_HANDLED_NO_RESTART)
      return eintr();
  }
  return 0;
}

textwindows ssize_t sys_read_eventfd_nt(struct Fd *f, void *buf) {
  ssize_t rc;
  sigset_t m = __sig_block();
  for (;;) {
    uint64_t v = __eventfd_take(f);
    if (v) {
      if (!__atomic_load_n(&f->evcount, __ATOMIC_RELAXED)) {
        ResetEvent(f->handle);
        // a write that landed between the take and the reset
        if (__atomic_load_n(&f->evcount, __ATOMIC_RELAXED))
          SetEvent(f->handle);
      }
      memcpy(buf, &v, sizeof(v));
      rc = sizeof(v);
      break;
    }
    if (f->flags & O_NONBLOCK) {
      rc = eagain();
      break;
    }
    if (WaitForEventFd(f->handle, m) == -1) {
      rc = -1;
      break;
    }
  }
  __sig_unblock(m);
  return rc;
}

textwindows ssize_t sys_write_eventfd_nt(struct Fd *f, uint64_t v) {
  bool was_zero;
  while (!__eventfd_add(f, v, &was_zero)) {
    // full: a reader has to make room first
    if (f->flags & O_NONBLOCK)
      return eagain();
    SleepEx(1, true);
  }
  SetEvent(f->handle);
  if (_weaken(__epoll_rearm_in))
    _weaken(__epoll_rearm_in)(f - __get_pib()->fds.p);
  return sizeof(v);
}

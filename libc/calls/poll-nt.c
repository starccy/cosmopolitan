/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2020 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include "libc/assert.h"
#include "libc/calls/internal.h"
#include "libc/calls/sig.internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/sigset.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/struct/timespec.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/sysv/consts/af.h"
#include "libc/errno.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/getenv.h"
#include "libc/intrin/nomultics.h"
#include "libc/intrin/weaken.h"
#include "libc/macros.h"
#include "libc/intrin/strace.h"
#include "libc/limits.h"
#include "libc/nt/console.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/afd.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/enum/filetype.h"
#include "libc/nt/enum/ioctl.h"
#include "libc/nt/enum/sio.h"
#include "libc/nt/enum/status.h"
#include "libc/nt/enum/wait.h"
#include "libc/nt/errors.h"
#include "libc/nt/events.h"
#include "libc/nt/files.h"
#include "libc/nt/ipc.h"
#include "libc/nt/memory.h"
#include "libc/nt/nt/file.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/afd.h"
#include "libc/nt/struct/iostatusblock.h"
#include "libc/nt/struct/objectattributes.h"
#include "libc/nt/struct/pollfd.h"
#include "libc/nt/struct/unicodestring.h"
#include "libc/nt/synchronization.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/time.h"
#include "libc/nt/winsock.h"
#include "libc/runtime/runtime.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/pollfd.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/sicode.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/thread/posixthread.internal.h"
#if SupportsWindows()

// <sync libc/sysv/consts.sh>
#define POLLERR_    0x0001  // implied in events
#define POLLHUP_    0x0002  // implied in events
#define POLLNVAL_   0x0004  // implied in events
#define POLLIN_     0x0300
#define POLLRDNORM_ 0x0100
#define POLLRDBAND_ 0x0200
#define POLLOUT_    0x0010
#define POLLWRNORM_ 0x0010
#define POLLWRBAND_ 0x0020  // MSDN undocumented
#define POLLPRI_    0x0400  // MSDN unsupported

#define POLL_PIPE_MS 10
// </sync libc/sysv/consts.sh>

#define kNtObjInherit 0x00000002u
#define kNtFileOpen   1

// Pipes signal nothing, so the wait between looks at them decides how
// soon a byte written by another thread shows up. It's 1ms for the first
// POLL_BUDGET_MS of a call, which covers a round trip between threads,
// and POLL_PIPE_MS once the call has been quiet for longer than that.
// COSMOPOLITAN_POLL_MS moves the boundary; 0 turns the fast phase off.
// A set with sockets in it gets an afd poll request per socket, whose
// event then waits next to the signal event and the console and eventfd
// handles in one call; see sys_poll_nt_arm(). A set too big for that
// (64 handles) sleeps in WSAPoll(), which no signal can wake, so that
// sleep is cut into POLL_INTERVAL_MS pieces and any handles next to
// the sockets are looked at on the pipe schedule.
#define POLL_BUDGET_MS 250

textwindows static int sys_poll_nt_budget(void) {
  static int budget = -1;
  if (budget == -1) {
    int ms = POLL_BUDGET_MS;
    const char *s = __getenv(environ, "COSMOPOLITAN_POLL_MS").s;
    if (s) {
      ms = 0;
      for (; '0' <= *s && *s <= '9' && ms < 60000; ++s)
        ms = ms * 10 + (*s - '0');
    }
    budget = ms;
  }
  return budget;
}

textwindows static uint32_t sys_poll_nt_pipems(struct timespec started) {
  int budget = sys_poll_nt_budget();
  if (budget > 0) {
    struct timespec now = sys_clock_gettime_monotonic_nt();
    if (timespec_tomillis(timespec_subz(now, started)) < budget)
      return 1;
  }
  return POLL_PIPE_MS;
}

__msabi extern typeof(WaitForMultipleObjects)
    *const __imp_WaitForMultipleObjects;

// a wait in WSAPoll() can't be woken by a signal, so it's cut into
// POLL_INTERVAL_MS pieces. one that has the signal event in its set
// doesn't need that.
textwindows static uint32_t sys_poll_nt_waitms(struct timespec deadline,
                                               bool sliced) {
  struct timespec now = sys_clock_gettime_monotonic_nt();
  if (timespec_cmp(now, deadline) < 0) {
    struct timespec remain = timespec_sub(deadline, now);
    int64_t millis = timespec_tomillis(remain);
    uint32_t waitfor = MIN(millis, 0xfffffffeu);
    return sliced ? MIN(waitfor, POLL_INTERVAL_MS) : waitfor;
  } else {
    return 0;  // we timed out
  }
}

// a socket's readiness as a handle: an afd poll request completes
// when the socket is in a state it asked about, and the event it's
// issued with then waits in WaitForMultipleObjects() next to consoles
// and eventfds. the request is cancelled once the wait returns, and
// WSAPoll() does the reporting as before.
struct PollArm {
  int64_t event;
  struct NtIoStatusBlock iosb;
  struct NtAfdPollInfo info;
};

textwindows static int64_t sys_poll_nt_afd(void) {
  static _Atomic(int64_t) afd;
  int64_t h = atomic_load_explicit(&afd, memory_order_acquire);
  if (h)
    return h;
  static const char16_t name[] = u"\\Device\\Afd\\Cosmo";
  struct NtUnicodeString us = {sizeof(name) - sizeof(name[0]), sizeof(name),
                               (char16_t *)name};
  struct NtObjectAttributes oa = {sizeof(oa), 0, &us, kNtObjInherit, 0, 0};
  struct NtIoStatusBlock iosb;
  NtStatus st = NtCreateFile(&h, kNtSynchronize, &oa, &iosb, 0, 0,
                             kNtFileShareRead | kNtFileShareWrite, kNtFileOpen,
                             0, 0, 0);
  if (!NtSuccess(st)) {
    STRACE("open \\Device\\Afd failed %#x", st);
    h = -1;
  }
  int64_t old = 0;
  if (!atomic_compare_exchange_strong_explicit(
          &afd, &old, h, memory_order_release, memory_order_acquire)) {
    if (h != -1)
      CloseHandle(h);
    h = old;
  }
  return h;
}

textwindows static uint32_t sys_poll_nt_afdmask(short ev) {
  uint32_t a = kNtAfdPollLocalClose | kNtAfdPollAbort | kNtAfdPollConnectFail |
               kNtAfdPollDisconnect;
  if (ev & POLLRDNORM_)
    a |= kNtAfdPollReceive | kNtAfdPollAccept;
  if (ev & POLLRDBAND_)
    a |= kNtAfdPollReceiveExpedited;
  if (ev & POLLWRNORM_)
    a |= kNtAfdPollSend;
  return a;
}

textwindows static void sys_poll_nt_disarm(struct PollArm *arms, int n) {
  int64_t afd = sys_poll_nt_afd();
  for (int i = 0; i < n; ++i) {
    struct NtIoStatusBlock iosb;
    NtCancelIoFileEx(afd, &arms[i].iosb, &iosb);
    // the request writes into arms[] when it completes, so it has to
    // be over before this frame goes away. the event is manual reset
    // so a completion the wait already consumed is still visible here
    WaitForSingleObject(arms[i].event, -1u);
    CloseHandle(arms[i].event);
  }
}

// returns false with nothing left in flight if a socket can't be armed
textwindows static bool sys_poll_nt_arm(struct sys_pollfd_nt *sockfds, int sn,
                                        struct PollArm *arms, int64_t *hands) {
  int i;
  int64_t afd = sys_poll_nt_afd();
  if (afd == -1)
    return false;
  for (i = 0; i < sn; ++i) {
    struct PollArm *a = arms + i;
    int64_t base;
    uint32_t bytes;
    if (WSAIoctl(sockfds[i].handle, kNtSioBaseHandle, 0, 0, &base,
                 sizeof(base), &bytes, 0, 0) == -1)
      base = sockfds[i].handle;
    if (!(a->event = CreateEvent(0, true, false, 0)))
      break;
    a->info.Timeout = INT64_MAX;
    a->info.NumberOfHandles = 1;
    a->info.Exclusive = 0;
    a->info.Handles[0].Handle = base;
    a->info.Handles[0].Events = sys_poll_nt_afdmask(sockfds[i].events);
    a->info.Handles[0].Status = 0;
    a->iosb.Status = kNtStatusPending;
    NtStatus st = NtDeviceIoControlFile(afd, a->event, 0, 0, &a->iosb,
                                        kNtIoctlAfdPoll, &a->info,
                                        sizeof(a->info), &a->info,
                                        sizeof(a->info));
    if (st == kNtStatusSuccess) {
      SetEvent(a->event);
    } else if (st != kNtStatusPending) {
      STRACE("afd poll on socket %ld failed %#x", sockfds[i].handle, st);
      CloseHandle(a->event);
      break;
    }
    hands[i] = a->event;
  }
  if (i < sn) {
    sys_poll_nt_disarm(arms, i);
    return false;
  }
  return true;
}

// a descriptor another thread closed while the call was in flight:
// linux reports POLLNVAL for it, and the rest of the array goes on.
// returns how many entries were marked, 0 if the handles are all
// still the ones the fd table has.
textwindows static int sys_poll_nt_stale(struct pollfd *fds, int *indices,
                                         int64_t *handles, size_t stride,
                                         int n) {
  int found = 0;
  __fds_lock();
  for (int i = 0; i < n; ++i) {
    int fi = indices[i];
    int64_t h = *(int64_t *)((char *)handles + i * stride);
    if (fds[fi].revents)
      continue;
    if (!__isfdopen(fds[fi].fd) ||
        __get_pib()->fds.p[fds[fi].fd].handle != h) {
      fds[fi].revents = POLLNVAL_;
      ++found;
    }
  }
  __fds_unlock();
  return found;
}

// Polls on the New Technology.
//
// This function is used to implement poll() and select(). You may poll
// on sockets, files and the console at the same time. We also poll for
// both signals and posix thread cancelation, while the poll is polling
textwindows static int sys_poll_nt_actual_impl(
    struct pollfd *fds, uint64_t nfds, struct timespec deadline,
    struct timespec started, sigset_t waitmask, struct sys_pollfd_nt *sockfds,
    int *sockindices, size_t sockcap, struct PollArm *arms, int armcap) {
  int fileindices[64];
  int64_t filehands[64];
  int i, rc, ev, kind, gotsocks, armed;
  bool gotpipe = false;
  bool gotevent = false;
  bool gotconsole = false;
  bool canarm;
  bool sockwoke = false;
  bool fast;
  // a wait with a deadline gets the 1ms scheduler tick, like nanosleep()
  bool timed = timespec_cmp(deadline, timespec_max) < 0;
  uint32_t cm, fi, sn, pn, nh, avail, waitfor, pipems, already_slept;

  // ensure revents is cleared
  for (i = 0; i < nfds; ++i)
    fds[i].revents = 0;

  // divide files from sockets
  // check for invalid file descriptors
  __fds_lock();
  for (rc = sn = pn = i = 0; i < nfds; ++i) {
    if (fds[i].fd < 0)
      continue;
    if (__isfdopen(fds[i].fd)) {
      kind = __get_pib()->fds.p[fds[i].fd].kind;
      if (kind == kFdSocket) {
        // we can use WSAPoll() for these fds
        // WSAPoll whines if we pass POLLNVAL, POLLHUP, or POLLERR.
        sockindices[sn] = i;
        sockfds[sn].handle = __get_pib()->fds.p[fds[i].fd].handle;
        sockfds[sn].events =
            fds[i].events & (POLLRDNORM_ | POLLRDBAND_ | POLLWRNORM_);
        sockfds[sn].revents = 0;
        ++sn;
        // a packet socket's ipv6 capture is watched along with it, when
        // the array has room left for the fds still to come
        struct Fd *f = __get_pib()->fds.p + fds[i].fd;
        if (f->family == AF_PACKET && f->pkthandle6 &&
            sn + (nfds - i - 1) < sockcap) {
          sockindices[sn] = i;
          sockfds[sn].handle = f->pkthandle6;
          sockfds[sn].events = sockfds[sn - 1].events;
          sockfds[sn].revents = 0;
          ++sn;
        }
      } else if (kind == kFdFile || kind == kFdConsole || kind == kFdEvent ||
                 kind == kFdEpoll) {
        // we can use WaitForMultipleObjects() for these fds
        gotconsole |= kind == kFdConsole;
        gotevent |= kind == kFdEvent || kind == kFdEpoll;
        if (pn == ARRAYLEN(fileindices) - 1) {  // last slot for signal event
          rc = einval();
          break;
        }
        fileindices[pn] = i;
        filehands[pn] = __get_pib()->fds.p[fds[i].fd].handle;
        ++pn;
      } else if (kind == kFdDevNull || kind == kFdDevRandom || kind == kFdZip ||
                 kind == kFdProc) {
        // we can't wait on these kinds via win32
        if (fds[i].events & (POLLRDNORM_ | POLLWRNORM_)) {
          // the linux kernel does this irrespective of oflags
          fds[i].revents = fds[i].events & (POLLRDNORM_ | POLLWRNORM_);
        }
      } else {
        // unsupported file type
        fds[i].revents = POLLNVAL_;
      }
    } else {
      // file not open
      fds[i].revents = POLLNVAL_;
    }
    rc += !!fds[i].revents;
  }
  __fds_unlock();
  if (rc == -1)
    return rc;

  // another process on this console may have changed the mouse bit
  if (gotconsole && (__ttyconf.magic & kTtyUncanon))
    sys_console_sync_nt();

  // the socket events go after the signal event in filehands[]
  canarm = sn && sn <= armcap && pn + 1 + sn <= ARRAYLEN(filehands);

  // perform poll operation
  for (;;) {

    // check input status of pipes / consoles without blocking
    // this ensures any socket fds won't starve them of events
    // we can't poll file handles, so we just mark those ready
    for (i = 0; i < pn; ++i) {
      fi = fileindices[i];
      ev = fds[fi].events;
      ev &= POLLRDNORM_ | POLLWRNORM_;
      if ((__get_pib()->fds.p[fds[fi].fd].flags & O_ACCMODE) == O_RDONLY)
        ev &= ~POLLWRNORM_;
      if ((__get_pib()->fds.p[fds[fi].fd].flags & O_ACCMODE) == O_WRONLY)
        ev &= ~POLLRDNORM_;
      kind = __get_pib()->fds.p[fds[fi].fd].kind;
      if (kind == kFdEvent || kind == kFdEpoll) {
        // an eventfd is readable while its counter is nonzero and
        // always writable; an epoll fd is readable while its port
        // holds a completion, and never writable
        fds[fi].revents =
            kind == kFdEvent ? fds[fi].events & POLLWRNORM_ : 0;
        if ((fds[fi].events & POLLRDNORM_) &&
            !WaitForSingleObject(filehands[i], 0))
          fds[fi].revents |= POLLRDNORM_;
      } else if ((ev & POLLWRNORM_) && !(ev & POLLRDNORM_)) {
        fds[fi].revents = fds[fi].events & (POLLRDNORM_ | POLLWRNORM_);
      } else if (GetFileType(filehands[i]) == kNtFileTypePipe) {
        gotpipe = true;
        if (PeekNamedPipe(filehands[i], 0, 0, 0, &avail, 0)) {
          if (avail)
            fds[fi].revents = POLLRDNORM_;
        } else if (GetLastError() == kNtErrorHandleEof ||
                   GetLastError() == kNtErrorBrokenPipe) {
          fds[fi].revents = POLLHUP_;
        } else {
          fds[fi].revents = POLLERR_;
        }
      } else if (GetConsoleMode(filehands[i], &cm)) {
        switch (CountConsoleInputBytes()) {
          case 0:
            fds[fi].revents = fds[fi].events & POLLWRNORM_;
            break;
          case -1:
            fds[fi].revents = POLLHUP_;
            break;
          default:
            fds[fi].revents = fds[fi].events & (POLLRDNORM_ | POLLWRNORM_);
            break;
        }
      } else {
        fds[fi].revents = fds[fi].events & (POLLRDNORM_ | POLLWRNORM_);
      }
      rc += !!fds[fi].revents;
    }

    // determine how long to wait. a set that can't be armed sleeps in
    // WSAPoll(), which sees nothing else, so a console next to the
    // sockets is then looked at in slices too, the way a pipe is
    waitfor = sys_poll_nt_waitms(deadline, !canarm);
    pipems = 0;
    if (gotpipe || ((gotevent || gotconsole) && sn && !canarm)) {
      pipems = sys_poll_nt_pipems(started);
      if (waitfor > pipems)
        waitfor = pipems;
    }
    fast = timed || pipems == 1;

    // check for events and/or readiness on sockets
    // we always do this due to issues with POLLOUT
    if (sn) {
      // if we need to wait, then we prefer to wait inside WSAPoll()
      // this ensures network events are received in ~10µs not ~10ms
      if (!rc && waitfor && !canarm) {
        if (__sigcheck(waitmask, false))
          return -1;
        already_slept = waitfor;
      } else {
        already_slept = 0;
      }
      if (fast && already_slept)
        __nt_fast_tick(true);
      gotsocks = WSAPoll(sockfds, sn, already_slept);
      if (fast && already_slept)
        __nt_fast_tick(false);
      if (gotsocks == -1) {
        if (WSAGetLastError() == WSAENOTSOCK &&
            (gotsocks = sys_poll_nt_stale(fds, sockindices, &sockfds[0].handle,
                                          sizeof(*sockfds), sn))) {
          rc += gotsocks;
          break;
        }
        return __winsockerr();
      }
      // a wakeup the driver gave that winsock won't report would come
      // straight back, so the call sleeps in slices from here on
      if (sockwoke) {
        sockwoke = false;
        if (!gotsocks)
          canarm = false;
      }
      if (gotsocks) {
        for (i = 0; i < sn; ++i)
          if (sockfds[i].revents) {
            if (!fds[sockindices[i]].revents)
              ++rc;
            fds[sockindices[i]].revents |= sockfds[i].revents;
          }
      } else if (already_slept) {
        if (__sigcheck(waitmask, false))
          return -1;
      }
    } else {
      already_slept = 0;
    }

    // return if we observed events
    if (rc || !waitfor)
      break;

    // if nothing has happened and we haven't already waited in poll()
    // then we can wait on consoles, pipes, and signals simultaneously
    // this ensures low latency for apps like emacs which with no sock
    // here we shall actually report that something can be written too
    if (!already_slept) {
      nh = pn + 1;
      armed = 0;
      if (canarm) {
        if (sys_poll_nt_arm(sockfds, sn, arms, filehands + nh)) {
          armed = sn;
          nh += sn;
        } else {
          canarm = false;
          continue;
        }
      }
      if (!(filehands[pn] = __interruptible_start(waitmask))) {
        sys_poll_nt_disarm(arms, armed);
        return __winerr();
      }
      //!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!//
      int sig = 0;
      uint32_t wi = pn;
      if (!_is_canceled() &&
          !(_weaken(__sig_get) && (sig = _weaken(__sig_get)(waitmask)))) {
        if (fast)
          __nt_fast_tick(true);
        wi = __imp_WaitForMultipleObjects(nh, filehands, 0, waitfor);
        if (fast)
          __nt_fast_tick(false);
      }
      //!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!/!//
      __interruptible_end();
      sys_poll_nt_disarm(arms, armed);
      if (wi > pn && wi < nh) {
        // a socket woke us; the next pass reports it through WSAPoll()
        sockwoke = true;
        continue;
      }
      if (wi == -1u) {
        // win32 wait failure
        if (GetLastError() == kNtErrorInvalidHandle &&
            (rc = sys_poll_nt_stale(fds, fileindices, filehands,
                                    sizeof(*filehands), pn))) {
          break;
        }
        return __winerr();
      }
      if (wi == pn) {
        // our signal event was signalled
        int handler_was_called = 0;
        if (sig)
          handler_was_called = _weaken(__sig_relay)(sig, SI_KERNEL, waitmask);
        if (_check_cancel() == -1)
          return -1;
        if (handler_was_called)
          return eintr();
      } else if ((wi ^ kNtWaitAbandoned) < pn) {
        // this is possibly because a process or thread was killed
        fds[fileindices[wi ^ kNtWaitAbandoned]].revents = POLLERR_;
        ++rc;
      } else if (wi < pn) {
        fi = fileindices[wi];
        // one of the handles we polled is ready for fi/o
        if (GetConsoleMode(filehands[wi], &cm)) {
          switch (CountConsoleInputBytes()) {
            case 0:
              // it's possible there was input and it was handled by the
              // ICANON reader, and therefore should not be reported yet
              if (fds[fi].events & POLLWRNORM_)
                fds[fi].revents = POLLWRNORM_;
              break;
            case -1:
              fds[fi].revents = POLLHUP_;
              break;
            default:
              fds[fi].revents = fds[fi].events & (POLLRDNORM_ | POLLWRNORM_);
              break;
          }
        } else if (GetFileType(filehands[wi]) == kNtFileTypePipe) {
          if ((fds[fi].events & POLLRDNORM_) &&
              (__get_pib()->fds.p[fds[fi].fd].flags & O_ACCMODE) != O_WRONLY) {
            if (PeekNamedPipe(filehands[wi], 0, 0, 0, &avail, 0)) {
              fds[fi].revents = fds[fi].events & (POLLRDNORM_ | POLLWRNORM_);
            } else if (GetLastError() == kNtErrorHandleEof ||
                       GetLastError() == kNtErrorBrokenPipe) {
              fds[fi].revents = POLLHUP_;
            } else {
              fds[fi].revents = POLLERR_;
            }
          } else {
            fds[fi].revents = fds[fi].events & (POLLRDNORM_ | POLLWRNORM_);
          }
        } else {
          fds[fi].revents = fds[fi].events & (POLLRDNORM_ | POLLWRNORM_);
        }
        rc += !!fds[fi].revents;
      } else {
        // should only be possible on kNtWaitTimeout or semaphore abandoned
        // keep looping for events and we'll catch timeout when appropriate
      }
    }

    // once again, return if we observed events
    if (rc)
      break;
  }

  return rc;
}

// the arms for sets that don't fit the small array come from the heap;
// without them the sockets sleep in WSAPoll()
textwindows static int sys_poll_nt_actual(struct pollfd *fds, uint64_t nfds,
                                          struct timespec deadline,
                                          struct timespec started,
                                          sigset_t waitmask,
                                          struct sys_pollfd_nt *sockfds,
                                          int *sockindices, size_t sockcap) {
  int rc;
  struct PollArm small[8];
  struct PollArm *arms = small;
  int armcap = MIN(nfds, 63);
  if (armcap > ARRAYLEN(small)) {
    if (!(arms = HeapAlloc(GetProcessHeap(), 0, armcap * sizeof(*arms)))) {
      arms = small;
      armcap = ARRAYLEN(small);
    }
  }
  rc = sys_poll_nt_actual_impl(fds, nfds, deadline, started, waitmask, sockfds,
                               sockindices, sockcap, arms, armcap);
  if (arms != small)
    HeapFree(GetProcessHeap(), 0, arms);
  return rc;
}

textwindows static int sys_poll_nt_impl(struct pollfd *fds, uint64_t nfds,
                                        struct timespec deadline,
                                        struct timespec started,
                                        const sigset_t waitmask) {
  int sockindices[64];
  int i, n, rc, files, got = 0;
  struct sys_pollfd_nt sockfds[64];
  struct timespec now, next, target, wall;

  // we normally don't check for signals until we decide to wait, since
  // it's nice to have functions like write() be unlikely to EINTR, but
  // ppoll is a function where users are surely thinking about signals,
  // since ppoll actually allows them to block signals everywhere else.
  if (__sigcheck(waitmask, false))
    return -1;

  // fast path
  if (nfds <= 63)
    return sys_poll_nt_actual(fds, nfds, deadline, started, waitmask, sockfds,
                              sockindices, 64);

  __fds_lock();
  for (files = i = 0; i < nfds; ++i) {
    if (fds[i].fd >= 0 && __isfdopen(fds[i].fd)) {
      int kind = __get_pib()->fds.p[fds[i].fd].kind;
      files += kind == kFdFile || kind == kFdConsole;
    }
  }
  __fds_unlock();
  if (files <= 63) {
    void *mem;
    size_t cap = nfds + 8;
    size_t each = sizeof(struct sys_pollfd_nt) + sizeof(int);
    if ((mem = HeapAlloc(GetProcessHeap(), 0, cap * each))) {
      rc = sys_poll_nt_actual(
          fds, nfds, deadline, started, waitmask, mem,
          (int *)((char *)mem + cap * sizeof(struct sys_pollfd_nt)), cap);
      HeapFree(GetProcessHeap(), 0, mem);
      // a descriptor can turn into a file between the count and the call
      if (rc != -1 || errno != EINVAL)
        return rc;
    }
  }

  // clumsy path
  for (;;) {
    for (i = 0; i < nfds; i += 63) {
      n = nfds - i;
      n = n > 63 ? 63 : n;
      rc = sys_poll_nt_actual(fds + i, n, timespec_zero, started, waitmask,
                              sockfds, sockindices, 64);
      if (rc == -1)
        return -1;
      got += rc;
    }
    if (got)
      return got;
    now = sys_clock_gettime_monotonic_nt();
    if (timespec_cmp(now, deadline) >= 0)
      return 0;
    // what's here is mostly pipes, or it would have fit in one call
    uint32_t pipems = sys_poll_nt_pipems(started);
    next = timespec_add(now, timespec_frommillis(pipems));
    if (timespec_cmp(next, deadline) >= 0) {
      target = deadline;
    } else {
      target = next;
    }
    // _park_norestart() wants its deadline on the wall clock
    sys_clock_gettime_nt(0, &wall);
    wall = timespec_add(wall, timespec_sub(target, now));
    bool fast = pipems == 1 || timespec_cmp(deadline, timespec_max) < 0;
    if (fast)
      __nt_fast_tick(true);
    rc = _park_norestart(wall, waitmask);
    if (fast)
      __nt_fast_tick(false);
    if (rc == -1)
      return -1;
  }
}

textwindows int sys_poll_nt(struct pollfd *fds, uint64_t nfds,
                            const struct timespec *relative,
                            const sigset_t *sigmask) {
  int rc;
  struct timespec now, timeout, deadline;
  BLOCK_SIGNALS;
  now = sys_clock_gettime_monotonic_nt();
  timeout = relative ? *relative : timespec_max;
  deadline = relative ? timespec_add(now, timeout) : timespec_max;
  rc = sys_poll_nt_impl(fds, nfds, deadline, now,
                        sigmask ? *sigmask : _SigMask);
  ALLOW_SIGNALS;
  return rc;
}

#endif /* __x86_64__ */

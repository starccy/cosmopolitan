#include "libc/atomic.h"
#include "libc/calls/calls.h"
#include "libc/calls/cp.internal.h"
#include "libc/calls/internal.h"
#include "libc/calls/sig.internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/sigset.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/dll.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/strace.h"
#include "libc/intrin/weaken.h"
#include "libc/limits.h"
#include "libc/macros.h"
#include "libc/mem/mem.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/afd.h"
#include "libc/nt/enum/fileinformationclass.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/enum/filetype.h"
#include "libc/nt/enum/ioctl.h"
#include "libc/nt/enum/sio.h"
#include "libc/nt/enum/status.h"
#include "libc/nt/enum/wait.h"
#include "libc/nt/errors.h"
#include "libc/nt/events.h"
#include "libc/nt/files.h"
#include "libc/nt/iocp.h"
#include "libc/nt/ipc.h"
#include "libc/nt/nt/file.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/afd.h"
#include "libc/nt/struct/iostatusblock.h"
#include "libc/nt/struct/objectattributes.h"
#include "libc/nt/struct/overlapped.h"
#include "libc/nt/struct/overlappedentry.h"
#include "libc/nt/struct/pollfd.h"
#include "libc/nt/struct/unicodestring.h"
#include "libc/nt/thread.h"
#include "libc/nt/winsock.h"
#include "libc/sock/epoll.h"
#include "libc/sock/struct/pollfd.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/epoll.h"
#include "libc/sysv/consts/f.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/poll.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/consts/sicode.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/thread/posixthread.internal.h"
#include "libc/thread/thread.h"

/**
 * @fileoverview epoll, three ways.
 *
 * Linux gets the system calls. XNU and the BSDs get a kqueue, which is
 * what the epoll fd is there: EPOLLET is EV_CLEAR, EPOLLONESHOT is
 * EV_DISPATCH, and the kernel tracks edges itself. The one visible
 * difference is that kqueue keeps a read filter and a write filter per
 * fd, so a socket that's ready both ways may come back as two events
 * rather than one, and an EPOLLONESHOT registration may fire once per
 * direction. Windows keeps the interest list in userspace and waits
 * on an i/o completion port fed by the AFD driver for sockets and by
 * zero byte reads for pipes: an edge-triggered registration is armed
 * per direction, reported once, and armed again when the read or
 * write paths see EAGAIN, data, or a short write, or when epoll_ctl()
 * modifies it.
 */

////////////////////////////////////////////////////////////////////////////////
// xnu and bsd

// <sync with the host headers>
#define EV_ADD     0x0001
#define EV_DELETE  0x0002
#define EV_ENABLE  0x0004
#define EV_ONESHOT 0x0010
#define EV_CLEAR   0x0020
#define EV_RECEIPT 0x0040
#define EV_DISABLE  0x0008
#define EV_DISPATCH 0x0080
#define EV_ERROR   0x4000
#define EV_EOF     0x8000
// </sync with the host headers>

struct KeventXnu {  // also openbsd
  uint64_t ident;
  int16_t filter;
  uint16_t flags;
  uint32_t fflags;
  int64_t data;
  uint64_t udata;
};

struct KeventFreebsd {
  uint64_t ident;
  int16_t filter;
  uint16_t flags;
  uint32_t fflags;
  int64_t data;
  uint64_t udata;
  uint64_t ext[4];
};

struct KeventNetbsd {
  uint64_t ident;
  uint32_t filter;
  uint32_t flags;
  uint32_t fflags;
  int64_t data;
  uint64_t udata;
};

#define KEVENT_MAX_SIZE sizeof(struct KeventFreebsd)

static size_t KeventSize(void) {
  if (IsFreebsd())
    return sizeof(struct KeventFreebsd);
  if (IsNetbsd())
    return sizeof(struct KeventNetbsd);
  return sizeof(struct KeventXnu);
}

static int KqRead(void) {
  return IsNetbsd() ? 0 : -1;
}

static int KqWrite(void) {
  return IsNetbsd() ? 1 : -2;
}

dontinline static void KeventSet(void *buf, int i, uint64_t ident, int filter,
                      uint32_t flags, uint64_t udata) {
  if (IsFreebsd()) {
    struct KeventFreebsd *k = (struct KeventFreebsd *)buf + i;
    bzero(k, sizeof(*k));
    k->ident = ident;
    k->filter = filter;
    k->flags = flags;
    k->udata = udata;
  } else if (IsNetbsd()) {
    struct KeventNetbsd *k = (struct KeventNetbsd *)buf + i;
    bzero(k, sizeof(*k));
    k->ident = ident;
    k->filter = filter;
    k->flags = flags;
    k->udata = udata;
  } else {
    struct KeventXnu *k = (struct KeventXnu *)buf + i;
    bzero(k, sizeof(*k));
    k->ident = ident;
    k->filter = filter;
    k->flags = flags;
    k->udata = udata;
  }
}

dontinline static void KeventGet(const void *buf, int i, uint64_t *ident,
                      int *filter, uint32_t *flags, uint32_t *fflags,
                      int64_t *data, uint64_t *udata) {
  if (IsFreebsd()) {
    const struct KeventFreebsd *k = (const struct KeventFreebsd *)buf + i;
    *ident = k->ident;
    *filter = k->filter;
    *flags = k->flags;
    *fflags = k->fflags;
    *data = k->data;
    *udata = k->udata;
  } else if (IsNetbsd()) {
    const struct KeventNetbsd *k = (const struct KeventNetbsd *)buf + i;
    *ident = k->ident;
    *filter = (int32_t)k->filter;
    *flags = k->flags;
    *fflags = k->fflags;
    *data = k->data;
    *udata = k->udata;
  } else {
    const struct KeventXnu *k = (const struct KeventXnu *)buf + i;
    *ident = k->ident;
    *filter = k->filter;
    *flags = k->flags;
    *fflags = k->fflags;
    *data = k->data;
    *udata = k->udata;
  }
}

static int sys_epoll_create_kq(int flags) {
  int fd = sys_kqueue();
  if (fd != -1 && (flags & EPOLL_CLOEXEC))
    __sys_fcntl(fd, F_SETFD, FD_CLOEXEC);
  return fd;
}

// a wanted filter is deleted and added back rather than re-added in
// place: xnu keeps the EV_CLEAR and EV_DISPATCH bits a knote was
// created with, so that's the only way a MOD can change them. each
// change carries a receipt, so a delete of a filter that was never
// added is told apart from a real failure.
static int sys_epoll_ctl_kq(int kq, int op, int fd, struct epoll_event *ev) {
  uint32_t events = op == EPOLL_CTL_DEL ? 0 : ev->events;
  uint64_t data = op == EPOLL_CTL_DEL ? 0 : ev->data.u64;
  uint32_t add = EV_ADD | EV_ENABLE | EV_RECEIPT;
  if (events & EPOLLET)
    add |= EV_CLEAR;
  if (events & EPOLLONESHOT)
    add |= EV_DISPATCH;
  bool want[2] = {!!(events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP)),
                  !!(events & EPOLLOUT)};
  int filter[2] = {KqRead(), KqWrite()};
  char changes[4 * KEVENT_MAX_SIZE];
  char receipts[4 * KEVENT_MAX_SIZE];
  bool isdel[4];
  int n = 0;
  for (int i = 0; i < 2; ++i) {
    isdel[n] = true;
    KeventSet(changes, n++, fd, filter[i], EV_DELETE | EV_RECEIPT, 0);
    if (want[i]) {
      isdel[n] = false;
      KeventSet(changes, n++, fd, filter[i], add, data);
    }
  }
  if (sys_kevent(kq, changes, n, receipts, n, 0) == -1)
    return -1;
  int missing = 0;
  for (int i = 0; i < n; ++i) {
    int f;
    uint32_t flags, fflags;
    int64_t err;
    uint64_t ident, udata;
    KeventGet(receipts, i, &ident, &f, &flags, &fflags, &err, &udata);
    if (!(flags & EV_ERROR) || !err)
      continue;
    if (isdel[i] && err == ENOENT) {
      ++missing;
      continue;
    }
    errno = err;
    return -1;
  }
  if (op == EPOLL_CTL_DEL && missing == 2)
    return enoent();
  return 0;
}

// the caller's array doubles as the kevent array: a kevent is bigger
// than an epoll_event, so translating entry i in place never touches
// an entry that hasn't been read yet
static int sys_epoll_wait_kq(int kq, struct epoll_event *out, int maxevents,
                             int timeout, const sigset_t *sigmask) {
  size_t ksz = KeventSize();
  int n = (size_t)maxevents * sizeof(*out) / ksz;
  char one[KEVENT_MAX_SIZE];
  void *buf = out;
  if (n < 1) {
    n = 1;
    buf = one;
  }
  struct timespec ts, *tsp = 0;
  if (timeout >= 0) {
    ts = timespec_frommillis(timeout);
    tsp = &ts;
  }
  sigset_t oldmask, hostmask;
  if (sigmask) {
    hostmask = __linux2mask(*sigmask);
    sys_sigprocmask(SIG_SETMASK, &hostmask, &oldmask);
  }
  int rc = sys_kevent(kq, 0, 0, buf, n, tsp);
  if (sigmask) {
    int e = errno;
    sys_sigprocmask(SIG_SETMASK, &oldmask, 0);
    errno = e;
  }
  // kqueue keeps a read and a write filter per fd, so one fd that's
  // ready both ways comes back twice; the two are handed out as one
  // event, the way epoll reports them. entry k is written after kevent
  // i has been read, and k <= i, so the translation stays in place
  uint64_t few[64];
  uint64_t *ids = rc <= 64 ? few : rc > 0 ? malloc(rc * sizeof(*ids)) : 0;
  char offs[32 * KEVENT_MAX_SIZE];
  char *off = offs;
  int noff = 0;
  int k = 0;
  for (int i = 0; i < rc; ++i) {
    int filter;
    uint32_t flags, fflags, events;
    int64_t data;
    uint64_t ident, udata;
    KeventGet(buf, i, &ident, &filter, &flags, &fflags, &data, &udata);
    if (flags & EV_ERROR) {
      events = EPOLLERR;
    } else if (filter == KqWrite()) {
      events = EPOLLOUT;
      if (flags & EV_EOF)
        events |= EPOLLHUP | (fflags ? EPOLLERR : 0);
    } else {
      events = EPOLLIN;
      if (flags & EV_EOF) {
        // a socket's peer that stopped writing is a read hangup, but a
        // pipe with no writers left is a hangup, as on linux
        struct stat st;
        events |= EPOLLRDHUP | (fflags ? EPOLLERR : 0);
        if (!fstat(ident, &st) && S_ISFIFO(st.st_mode))
          events |= EPOLLHUP;
      }
    }
    // EPOLLONESHOT is EV_DISPATCH on each filter, so the direction that
    // didn't fire is disabled too, until epoll_ctl() arms the fd again
    if ((flags & EV_DISPATCH) && !(flags & EV_ERROR) && noff < 32)
      KeventSet(off, noff++, ident, filter == KqWrite() ? KqRead() : KqWrite(),
                EV_DISABLE | EV_RECEIPT, 0);
    int j = 0;
    if (ids)
      for (j = 0; j < k; ++j)
        if (ids[j] == ident && out[j].data.u64 == udata)
          break;
    if (ids && j < k) {
      out[j].events |= events;
    } else {
      if (ids)
        ids[k] = ident;
      out[k].events = events;
      out[k].data.u64 = udata;
      ++k;
    }
  }
  if (noff) {
    char receipts[32 * KEVENT_MAX_SIZE];
    int e = errno;
    sys_kevent(kq, off, noff, receipts, noff, 0);
    errno = e;
  }
  if (ids != few)
    free(ids);
  return rc > 0 ? k : rc;
}

////////////////////////////////////////////////////////////////////////////////
// windows
//
// The interest list lives in userspace and readiness arrives through an
// i/o completion port. A socket gets an AFD poll request, which the
// driver completes once the socket is in a state the request asked
// about. A pipe that cosmo made gets a zero byte overlapped read of its
// own, which completes when a byte or a hangup arrives; the read signals
// an event of the entry's, and a wait completion packet ties that event
// to the port, so the pipe itself is never bound to a port and can sit
// in any number of sets. An eventfd is looked at on every pass, and its
// writes post a wakeup. Whatever's left goes through poll() on every
// pass. For a console that's what swallows the records that aren't
// keystrokes, and a wait packet on the console input handle wakes the
// port when more arrive. Inherited pipes, disk files and other epoll
// fds have nothing to wait on, so they make the port wait in 10ms
// slices. A signal for a parked waiter is posted to the port by
// __sig_wake().
//
// Edge triggering is per direction: a registration is armed for input
// and output, a report disarms what it reported, and the read and write
// paths arm a direction again when they see EAGAIN, data, or a short
// write. A socket's AFD request only asks about armed directions. Data
// arriving on a socket that wasn't drained is an edge on Linux, and
// the request that a read puts back in flight is how it's seen here,
// at the price of a report for what was already there.
//
// Requests are put back in flight lazily: an entry that needs one goes
// on the set's update list, which is flushed right before a waiter
// parks, or at once when another thread is parked already. A level
// triggered request that goes out after the caller has read what was
// reported then only completes for what's really there, so what it
// brings back within the same epoll_wait() is handed out as is.

#define EPOLL_ARM_IN  1u
#define EPOLL_ARM_OUT 2u
#define EPOLL_ARM_HUP 4u

#define EPOLL_KEY_WAKE    1  // set changed, or a signal wants the waiter
#define EPOLL_KEY_AFD     2  // overlapped is the entry
#define EPOLL_KEY_PIPE    3  // overlapped is the entry
#define EPOLL_KEY_CONSOLE 4  // console input arrived

#define EPOLL_GROUP_SIZE 32
#define EPOLL_POLL_MS    10

#define EPOLL_IN_BITS \
  (EPOLLIN | EPOLLRDNORM | EPOLLPRI | EPOLLRDBAND | EPOLLRDHUP)
#define EPOLL_OUT_BITS (EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND)

// <sync libc/sysv/consts.sh>
#define POLLERR_    0x0001
#define POLLHUP_    0x0002
#define POLLRDNORM_ 0x0100
#define POLLRDBAND_ 0x0200
#define POLLWRNORM_ 0x0010
// </sync libc/sysv/consts.sh>

#define kNtObjInherit             0x00000002u
#define kNtFileOpen               1
#define kNtFileSynchronousIo      0x00000030u
#define kNtStatusEndOfFile        0xC0000011u
#define kNtStatusBufferOverflow   0x80000005u
#define kNtStatusPipeDisconnected 0xC00000B0u
#define kNtStatusPipeClosing      0xC00000B1u
#define kNtStatusPipeBroken       0xC000014Bu

enum EpollKind {
  kEpollSock,
  kEpollPipe,
  kEpollEvent,
  kEpollPoll,
};

struct EpollGroup {
  struct EpollGroup *next;
  int64_t afd;
  int n;
};

struct EpollEntry {
  struct Dll elem;            // the set's socks, misc, or dead list
  struct Dll ready;           // the set's ready list, while got is set
  struct Dll upd;             // the set's update list, while queued is set
  struct EpollEntry *fdnext;  // same fd, another set
  struct EpollSet *set;
  struct EpollGroup *group;
  int fd;
  int kind;
  bool pending;    // an afd poll or zero byte read is in flight
  bool cancelled;  // and it's been told to stop
  bool dead;       // out of the set; freed once nothing's in flight
  bool queued;     // waiting for the update list to be flushed
  bool console;    // poll entry for a console
  int64_t handle;
  int64_t evt;   // pipe: signaled by the zero byte read
  int64_t pkt;   // pipe: posts to the port when evt is
  int64_t base;  // socket: what the afd driver knows it as
  uint32_t events;
  uint32_t armed;
  uint32_t polled;  // afd mask of the request in flight
  uint32_t got;     // events waiting to be handed out
  uint32_t epoch;   // bumped by epoll_ctl(), so an older completion is
  uint32_t issued;  // checked against the fd rather than trusted
  uint32_t pass;    // the epoll_wait() that flushed the request
  uint64_t data;
  struct NtIoStatusBlock iosb;
  struct NtAfdPollInfo info;
  struct NtOverlapped ov;
};

struct EpollSet {
  struct EpollSet *next;
  int refs;     // fd table names plus waiters, under g_epoll_lock
  int names;    // the fd table names alone
  bool closed;  // no fd names it anymore
  int pid;
  int64_t port;
  struct EpollGroup *groups;
  struct Dll *socks;
  struct Dll *misc;
  struct Dll *dead;
  struct Dll *ready;
  struct Dll *updates;
  int npoll;   // misc entries that go through poll()
  int nslice;  // of those, the ones with nothing to wait on
  uint32_t pass;     // counts the epoll_wait() calls
  int64_t cin;       // console input handle, once a console is added
  int64_t conpkt;    // posts to the port when cin is signaled
  bool conarmed;     // conpkt is associated
  atomic_int waiters;  // threads parked on the port, or about to be
  pthread_mutex_t lock;
};

static struct EpollSet *g_epoll_sets;
static atomic_int g_epoll_count;
static struct EpollEntry **g_epoll_byfd;
static int g_epoll_byfd_n;
static char g_epoll_dummy;
static pthread_mutex_t g_epoll_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t EpollDirs(const struct EpollEntry *e) {
  if (!(e->events & (EPOLLET | EPOLLONESHOT)))
    return EPOLL_ARM_IN | EPOLL_ARM_OUT | EPOLL_ARM_HUP;
  return e->armed;
}

// a peer that went away is an input event on linux, whichever
// directions were still armed
static uint32_t EpollWithHup(uint32_t ev) {
  if (ev & EPOLLRDHUP)
    ev |= EPOLLIN | EPOLLRDNORM;
  return ev;
}

// the events the registration may report right now
static uint32_t EpollMask(const struct EpollEntry *e) {
  uint32_t dirs = EpollDirs(e);
  if (!dirs)
    return 0;
  uint32_t m = EPOLLERR | EPOLLHUP;
  if (dirs & EPOLL_ARM_IN)
    m |= EPOLL_IN_BITS;
  if (dirs & EPOLL_ARM_OUT)
    m |= EPOLL_OUT_BITS;
  if (dirs & EPOLL_ARM_HUP)
    m |= EPOLLRDHUP;
  return (e->events | EPOLLERR | EPOLLHUP) & m;
}

static uint32_t EpollToAfd(uint32_t m) {
  uint32_t a = kNtAfdPollLocalClose;
  if (m & (EPOLLIN | EPOLLRDNORM))
    a |= kNtAfdPollReceive | kNtAfdPollAccept | kNtAfdPollDisconnect;
  if (m & (EPOLLPRI | EPOLLRDBAND))
    a |= kNtAfdPollReceiveExpedited;
  if (m & EPOLL_OUT_BITS)
    a |= kNtAfdPollSend;
  if (m & EPOLLRDHUP)
    a |= kNtAfdPollDisconnect;
  if (m & EPOLLHUP)
    a |= kNtAfdPollAbort;
  if (m & EPOLLERR)
    a |= kNtAfdPollConnectFail;
  return a;
}

static uint32_t EpollFromAfd(uint32_t a) {
  uint32_t e = 0;
  if (a & (kNtAfdPollReceive | kNtAfdPollAccept))
    e |= EPOLLIN | EPOLLRDNORM;
  if (a & kNtAfdPollReceiveExpedited)
    e |= EPOLLPRI | EPOLLRDBAND;
  if (a & kNtAfdPollSend)
    e |= EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND;
  if (a & kNtAfdPollDisconnect)
    e |= EPOLLIN | EPOLLRDNORM | EPOLLRDHUP;
  if (a & kNtAfdPollAbort)
    e |= EPOLLHUP;
  if (a & (kNtAfdPollConnectFail | kNtAfdPollLocalClose))
    e |= EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDNORM | EPOLLWRNORM |
         EPOLLRDHUP;
  return e;
}

static short EpollToPoll(uint32_t m) {
  short p = 0;
  if (m & (EPOLLIN | EPOLLRDNORM))
    p |= POLLIN;
  if (m & EPOLLPRI)
    p |= POLLPRI;
  if (m & EPOLLRDHUP)
    p |= POLLRDHUP;
  if (m & EPOLL_OUT_BITS)
    p |= POLLOUT;
  return p;
}

static uint32_t PollToEpoll(short revents) {
  uint32_t e = 0;
  if (revents & POLLIN)
    e |= EPOLLIN | EPOLLRDNORM;
  if (revents & POLLOUT)
    e |= EPOLLOUT | EPOLLWRNORM;
  if (revents & POLLPRI)
    e |= EPOLLPRI;
  if (revents & POLLERR)
    e |= EPOLLERR;
  if (revents & POLLHUP)
    e |= EPOLLHUP;
  if (revents & POLLRDHUP)
    e |= EPOLLRDHUP;
  return e;
}

static void EpollDisarm(struct EpollEntry *e, uint32_t ev) {
  if (e->events & EPOLLONESHOT) {
    e->armed = 0;
  } else if (e->events & EPOLLET) {
    if (ev & (EPOLLERR | EPOLLHUP)) {
      e->armed = 0;
    } else {
      if (ev & EPOLL_IN_BITS)
        e->armed &= ~EPOLL_ARM_IN;
      if (ev & EPOLL_OUT_BITS)
        e->armed &= ~EPOLL_ARM_OUT;
      if (ev & EPOLLRDHUP)
        e->armed &= ~EPOLL_ARM_HUP;
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
// the fd index, under g_epoll_lock

static struct EpollEntry *EpollFind(struct EpollSet *s, int fd) {
  if (fd < g_epoll_byfd_n)
    for (struct EpollEntry *e = g_epoll_byfd[fd]; e; e = e->fdnext)
      if (e->set == s)
        return e;
  return 0;
}

static int EpollIndex(struct EpollEntry *e) {
  if (e->fd >= g_epoll_byfd_n) {
    int n = MAX(64, g_epoll_byfd_n);
    while (n <= e->fd)
      n *= 2;
    struct EpollEntry **p = realloc(g_epoll_byfd, n * sizeof(*p));
    if (!p)
      return enomem();
    bzero(p + g_epoll_byfd_n, (n - g_epoll_byfd_n) * sizeof(*p));
    g_epoll_byfd = p;
    g_epoll_byfd_n = n;
  }
  e->fdnext = g_epoll_byfd[e->fd];
  g_epoll_byfd[e->fd] = e;
  return 0;
}

static void EpollUnindex(struct EpollEntry *e) {
  for (struct EpollEntry **pp = &g_epoll_byfd[e->fd]; *pp; pp = &(*pp)->fdnext) {
    if (*pp == e) {
      *pp = e->fdnext;
      break;
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
// the requests, under the set's lock

// a change that a parked waiter has to look at. a waiter counts
// itself in before it lets go of the lock, so a change it didn't see
// finds the count set and posts; one nobody is waiting for is picked
// up by the next epoll_wait() on its own.
textwindows static void EpollWake(struct EpollSet *s) {
  if (atomic_load_explicit(&s->waiters, memory_order_relaxed) > 0)
    PostQueuedCompletionStatus(s->port, 0, EPOLL_KEY_WAKE, 0);
}

textwindows static void EpollGot(struct EpollSet *s, struct EpollEntry *e,
                                 uint32_t ev) {
  if (!e->got)
    dll_make_last(&s->ready, &e->ready);
  e->got |= ev;
}

textwindows static struct EpollGroup *EpollGroupAcquire(struct EpollSet *s) {
  struct EpollGroup *g;
  for (g = s->groups; g; g = g->next)
    if (g->n < EPOLL_GROUP_SIZE)
      break;
  if (!g) {
    static const char16_t name[] = u"\\Device\\Afd\\Cosmo";
    struct NtUnicodeString us = {sizeof(name) - sizeof(name[0]), sizeof(name),
                                 (char16_t *)name};
    struct NtObjectAttributes oa = {sizeof(oa), 0, &us, kNtObjInherit, 0, 0};
    struct NtIoStatusBlock iosb;
    int64_t afd;
    NtStatus st = NtCreateFile(&afd, kNtSynchronize, &oa, &iosb, 0, 0,
                               kNtFileShareRead | kNtFileShareWrite,
                               kNtFileOpen, 0, 0, 0);
    if (!NtSuccess(st)) {
      SetLastError(RtlNtStatusToDosError(st));
      __winerr();
      return 0;
    }
    if (!CreateIoCompletionPort(afd, s->port, EPOLL_KEY_AFD, 0)) {
      __winerr();
      CloseHandle(afd);
      return 0;
    }
    SetFileCompletionNotificationModes(afd, kNtFileSkipSetEventOnHandle);
    if (!(g = calloc(1, sizeof(*g)))) {
      CloseHandle(afd);
      enomem();
      return 0;
    }
    g->afd = afd;
    g->next = s->groups;
    s->groups = g;
  }
  ++g->n;
  return g;
}

// a failure that got as far as the driver leaves nothing in flight
// and posts nothing, so it's reported from here
textwindows static void EpollIssueSock(struct EpollEntry *e, uint32_t mask) {
  e->info.Timeout = INT64_MAX;
  e->info.NumberOfHandles = 1;
  e->info.Exclusive = 0;
  e->info.Handles[0].Handle = e->base;
  e->info.Handles[0].Events = mask;
  e->info.Handles[0].Status = 0;
  e->iosb.Status = kNtStatusPending;
  NtStatus st = NtDeviceIoControlFile(e->group->afd, 0, 0, e, &e->iosb,
                                      kNtIoctlAfdPoll, &e->info,
                                      sizeof(e->info), &e->info,
                                      sizeof(e->info));
  STRACE("afd poll fd %d mask %#x → %#x", e->fd, mask, st);
  if (st == kNtStatusSuccess || st == kNtStatusPending) {
    e->pending = true;
    e->polled = mask;
    e->issued = e->epoch;
    e->pass = e->set->pass;
  } else {
    STRACE("afd poll on fd %d failed %#x", e->fd, st);
    EpollGot(e->set, e, EPOLLERR);
  }
}

textwindows static void EpollIssuePipe(struct EpollEntry *e) {
  bzero(&e->ov, sizeof(e->ov));
  e->ov.hEvent = e->evt | 1;  // signal evt, post nothing to a port
  if (ReadFile(e->handle, &g_epoll_dummy, 0, 0, &e->ov) ||
      GetLastError() == kNtErrorIoPending) {
    if (NtSuccess(NtAssociateWaitCompletionPacket(
            e->pkt, e->set->port, e->evt, (void *)EPOLL_KEY_PIPE, e, 0, 0,
            0))) {
      e->pending = true;
      e->issued = e->epoch;
      e->pass = e->set->pass;
      return;
    }
    uint32_t got;
    CancelIoEx(e->handle, &e->ov);
    GetOverlappedResult(e->handle, &e->ov, &got, true);
    EpollGot(e->set, e, EPOLLERR);
    return;
  }
  uint32_t err = GetLastError();
  if (err == kNtErrorMoreData) {
    // a message mode pipe answers a zero byte read this way when a
    // message is waiting
    EpollGot(e->set, e, EPOLLIN | EPOLLRDNORM);
    return;
  }
  if (err == kNtErrorBrokenPipe || err == kNtErrorHandleEof ||
      err == kNtErrorPipeNotConnected || err == kNtErrorNoData) {
    EpollGot(e->set, e, EPOLLHUP);
  } else {
    EpollGot(e->set, e, EPOLLERR);
  }
}

textwindows static void EpollCancel(struct EpollEntry *e) {
  if (!e->pending || e->cancelled)
    return;
  STRACE("epoll cancel fd %d", e->fd);
  e->cancelled = true;
  if (e->kind == kEpollSock) {
    struct NtIoStatusBlock iosb;
    NtCancelIoFileEx(e->group->afd, &e->iosb, &iosb);
  } else {
    CancelIoEx(e->handle, &e->ov);
  }
}

// brings what's in flight in line with what the registration wants.
// a request that asks about less than it should is cancelled, and
// its cancellation completion is what issues the replacement.
textwindows static void EpollSubmit(struct EpollEntry *e) {
  uint32_t m = EpollMask(e);
  if (e->kind == kEpollSock) {
    uint32_t want = m ? EpollToAfd(m) : 0;
    if (e->pending) {
      if (want & ~e->polled)
        EpollCancel(e);
    } else if (want) {
      EpollIssueSock(e, want);
    }
  } else if (e->kind == kEpollPipe) {
    if (e->evt && !e->pending && !e->got && (m & EPOLL_IN_BITS))
      EpollIssuePipe(e);
  }
}

textwindows static void EpollFlush(struct EpollSet *s) {
  struct Dll *d;
  while ((d = dll_first(s->updates))) {
    struct EpollEntry *e = DLL_CONTAINER(struct EpollEntry, upd, d);
    dll_remove(&s->updates, d);
    e->queued = false;
    EpollSubmit(e);
  }
}

// an entry whose request may have to change. it goes out before the
// next waiter parks, or now if one is parked already.
textwindows static void EpollUpdate(struct EpollEntry *e) {
  struct EpollSet *s = e->set;
  if (e->kind != kEpollSock && e->kind != kEpollPipe)
    return;
  if (!e->queued) {
    e->queued = true;
    dll_make_last(&s->updates, &e->upd);
  }
  if (atomic_load_explicit(&s->waiters, memory_order_relaxed) > 0)
    EpollFlush(s);
}

textwindows static void EpollFree(struct EpollEntry *e) {
  if (e->pkt)
    CloseHandle(e->pkt);
  if (e->evt)
    CloseHandle(e->evt);
  free(e);
}

// the completion of a socket's afd poll or a pipe's zero byte read
textwindows static void EpollComplete(struct EpollSet *s,
                                      struct EpollEntry *e) {
  e->pending = false;
  e->cancelled = false;
  if (e->dead) {
    dll_remove(&s->dead, &e->elem);
    EpollFree(e);
    return;
  }
  uint32_t ev = 0;
  if (e->kind == kEpollSock) {
    NtStatus st = e->iosb.Status;
    if (st == kNtStatusCancelled) {
    } else if (!NtSuccess(st)) {
      ev = EPOLLERR;
    } else if (e->info.NumberOfHandles) {
      ev = EpollFromAfd(e->info.Handles[0].Events);
    }
  } else {
    NtStatus st = e->ov.Internal;
    if (st == kNtStatusCancelled) {
    } else if (NtSuccess(st) || st == kNtStatusBufferOverflow) {
      ev = EPOLLIN | EPOLLRDNORM;
    } else if (st == kNtStatusPipeBroken || st == kNtStatusEndOfFile ||
               st == kNtStatusPipeDisconnected || st == kNtStatusPipeClosing) {
      ev = EPOLLHUP;
    } else {
      ev = EPOLLERR;
    }
  }
  ev &= EpollMask(e);
  ev = EpollWithHup(ev);
  STRACE("epoll completion fd %d status %#x afd %#x → %#x", e->fd,
         e->kind == kEpollSock ? e->iosb.Status : e->ov.Internal,
         e->kind == kEpollSock && e->info.NumberOfHandles
             ? e->info.Handles[0].Events
             : 0,
         ev);
  if (ev) {
    EpollGot(s, e, ev);
  } else {
    EpollUpdate(e);
  }
}

textwindows static void EpollTake(struct EpollSet *s,
                                  struct NtOverlappedEntry *ents, uint32_t n) {
  for (uint32_t i = 0; i < n; ++i) {
    switch (ents[i].lpCompletionKey) {
      case EPOLL_KEY_AFD:
      case EPOLL_KEY_PIPE:
        EpollComplete(s, (struct EpollEntry *)ents[i].lpOverlapped);
        break;
      case EPOLL_KEY_CONSOLE:
        s->conarmed = false;
        break;
      default:
        break;
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
// the registrations, under both locks

// a layered service provider may answer SIO_BASE_HANDLE with its own
// handle or refuse it. SIO_BSP_HANDLE_POLL then names the handle one
// layer down, which is asked again.
textwindows static int64_t EpollBaseSocket(int64_t h) {
  for (int i = 0; i < 8; ++i) {
    int64_t base;
    uint32_t bytes;
    if (WSAIoctl(h, kNtSioBaseHandle, 0, 0, &base, sizeof(base), &bytes, 0,
                 0) != -1)
      return base;
    if (WSAGetLastError() == WSAENOTSOCK)
      break;
    if (WSAIoctl(h, kNtSioBspHandlePoll, 0, 0, &base, sizeof(base), &bytes, 0,
                 0) == -1 ||
        base == h)
      break;
    h = base;
  }
  return h;
}

textwindows static bool EpollPipeWatch(struct EpollEntry *e) {
  struct NtObjectAttributes oa = {sizeof(oa), 0, 0, kNtObjInherit, 0, 0};
  struct NtSecurityAttributes sa = {sizeof(sa), 0, true};
  if (!(e->evt = CreateEvent(&sa, true, false, 0)))
    return false;
  if (!NtSuccess(NtCreateWaitCompletionPacket(&e->pkt, kNtGenericAll, &oa))) {
    e->pkt = 0;
    CloseHandle(e->evt);
    e->evt = 0;
    return false;
  }
  return true;
}

textwindows static bool EpollConsoleWatch(struct EpollSet *s) {
  if (s->conpkt)
    return true;
  struct NtObjectAttributes oa = {sizeof(oa), 0, 0, kNtObjInherit, 0, 0};
  if (!_weaken(GetConsoleInputHandle))
    return false;
  int64_t cin = _weaken(GetConsoleInputHandle)();
  if (!cin || cin == -1)
    return false;
  if (!NtSuccess(NtCreateWaitCompletionPacket(&s->conpkt, kNtGenericAll, &oa))) {
    s->conpkt = 0;
    return false;
  }
  s->cin = cin;
  return true;
}

textwindows static bool EpollPipeIsAsync(int64_t h) {
  struct NtIoStatusBlock iosb;
  uint32_t mode = 0;
  if (!NtSuccess(NtQueryInformationFile(h, &iosb, &mode, sizeof(mode),
                                        kNtFileModeInformation)))
    return false;
  return !(mode & kNtFileSynchronousIo);
}

textwindows static int EpollAdd(struct EpollSet *s, int fd,
                                const struct epoll_event *ev) {
  struct Fd *f = __get_pib()->fds.p + fd;
  struct EpollEntry *e;
  if (!(e = calloc(1, sizeof(*e))))
    return enomem();
  e->set = s;
  e->fd = fd;
  e->handle = f->handle;
  e->events = ev->events;
  e->data = ev->data.u64;
  e->armed = EPOLL_ARM_IN | EPOLL_ARM_OUT | EPOLL_ARM_HUP;
  e->kind = kEpollPoll;
  dll_init(&e->elem);
  dll_init(&e->ready);
  dll_init(&e->upd);
  if (f->kind == kFdSocket && f->family != AF_PACKET) {
    if (!(e->group = EpollGroupAcquire(s))) {
      free(e);
      return -1;
    }
    e->kind = kEpollSock;
    e->base = EpollBaseSocket(f->handle);
  } else if (f->kind == kFdFile && GetFileType(f->handle) == kNtFileTypePipe) {
    if ((f->flags & O_ACCMODE) == O_WRONLY) {
      e->kind = kEpollPipe;
    } else if (EpollPipeIsAsync(f->handle) && EpollPipeWatch(e)) {
      e->kind = kEpollPipe;
    }
  } else if (f->kind == kFdEvent) {
    e->kind = kEpollEvent;
  } else if (f->kind == kFdConsole) {
    e->console = EpollConsoleWatch(s);
  }
  if (EpollIndex(e) == -1) {
    if (e->group)
      --e->group->n;
    EpollFree(e);
    return -1;
  }
  if (e->kind == kEpollSock) {
    dll_make_last(&s->socks, &e->elem);
  } else {
    dll_make_last(&s->misc, &e->elem);
    s->npoll += e->kind == kEpollPoll;
    s->nslice += e->kind == kEpollPoll && !e->console;
  }
  EpollUpdate(e);
  return 0;
}

// takes a registration out of the set. a request in flight is told to
// stop, and the entry waits on the dead list until that's been seen.
textwindows static void EpollDrop(struct EpollSet *s, struct EpollEntry *e) {
  EpollUnindex(e);
  if (e->got) {
    dll_remove(&s->ready, &e->ready);
    e->got = 0;
  }
  if (e->queued) {
    dll_remove(&s->updates, &e->upd);
    e->queued = false;
  }
  if (e->kind == kEpollSock) {
    dll_remove(&s->socks, &e->elem);
    --e->group->n;
  } else {
    dll_remove(&s->misc, &e->elem);
    s->npoll -= e->kind == kEpollPoll;
    s->nslice -= e->kind == kEpollPoll && !e->console;
  }
  e->dead = true;
  if (e->pending) {
    if (s->pid == getpid())
      EpollCancel(e);
    dll_make_last(&s->dead, &e->elem);
  } else {
    EpollFree(e);
  }
}

////////////////////////////////////////////////////////////////////////////////
// the sets

textwindows static struct EpollSet *EpollSetOf(int epfd) {
  if (!__isfdkind(epfd, kFdEpoll))
    return 0;
  return __get_pib()->fds.p[epfd].epset;
}

textwindows static void EpollFreeList(struct Dll **list, int *left) {
  struct Dll *d;
  while ((d = dll_first(*list))) {
    struct EpollEntry *e = DLL_CONTAINER(struct EpollEntry, elem, d);
    dll_remove(list, d);
    if (e->pending) {
      ++*left;
    } else {
      EpollFree(e);
    }
  }
}

// the last name is gone. in the process that made the set, whatever's
// in flight is stopped and its completions are collected, since the
// kernel writes into the entries when they land. a set inherited by a
// child shares its port with the parent, whose completions mustn't be
// taken, so the child only closes its handles and drops the memory.
textwindows static void EpollDestroy(struct EpollSet *s) {
  bool mine = s->pid == getpid();
  struct NtOverlappedEntry ents[64];
  if (mine) {
    for (struct Dll *d = dll_first(s->socks); d; d = dll_next(s->socks, d))
      EpollCancel(DLL_CONTAINER(struct EpollEntry, elem, d));
    for (struct Dll *d = dll_first(s->misc); d; d = dll_next(s->misc, d))
      EpollCancel(DLL_CONTAINER(struct EpollEntry, elem, d));
    for (int tries = 0; tries < 100; ++tries) {
      uint32_t n = 0;
      bool busy = false;
      if (!GetQueuedCompletionStatusEx(s->port, ents, ARRAYLEN(ents), &n,
                                       tries ? 1 : 0, false))
        n = 0;
      for (uint32_t i = 0; i < n; ++i)
        if (ents[i].lpCompletionKey == EPOLL_KEY_AFD ||
            ents[i].lpCompletionKey == EPOLL_KEY_PIPE)
          ((struct EpollEntry *)ents[i].lpOverlapped)->pending = false;
      for (struct Dll *d = dll_first(s->socks); d; d = dll_next(s->socks, d))
        busy |= DLL_CONTAINER(struct EpollEntry, elem, d)->pending;
      for (struct Dll *d = dll_first(s->misc); d; d = dll_next(s->misc, d))
        busy |= DLL_CONTAINER(struct EpollEntry, elem, d)->pending;
      for (struct Dll *d = dll_first(s->dead); d; d = dll_next(s->dead, d))
        busy |= DLL_CONTAINER(struct EpollEntry, elem, d)->pending;
      if (!busy)
        break;
    }
  } else {
    for (struct Dll *d = dll_first(s->socks); d; d = dll_next(s->socks, d))
      DLL_CONTAINER(struct EpollEntry, elem, d)->pending = false;
    for (struct Dll *d = dll_first(s->misc); d; d = dll_next(s->misc, d))
      DLL_CONTAINER(struct EpollEntry, elem, d)->pending = false;
    for (struct Dll *d = dll_first(s->dead); d; d = dll_next(s->dead, d))
      DLL_CONTAINER(struct EpollEntry, elem, d)->pending = false;
  }
  int left = 0;
  EpollFreeList(&s->socks, &left);
  EpollFreeList(&s->misc, &left);
  EpollFreeList(&s->dead, &left);
  if (left)
    STRACE("epoll set closed with %d requests still in flight", left);
  while (s->groups) {
    struct EpollGroup *g = s->groups;
    s->groups = g->next;
    CloseHandle(g->afd);
    free(g);
  }
  if (s->conpkt) {
    if (mine)
      NtCancelWaitCompletionPacket(s->conpkt, true);
    CloseHandle(s->conpkt);
  }
  CloseHandle(s->port);
  free(s);
}

// drops a name or a waiter, and unlinks the set once it has neither
textwindows static void EpollRelease(struct EpollSet *s) {
  bool last;
  pthread_mutex_lock(&g_epoll_lock);
  last = --s->refs == 0;
  if (last) {
    for (struct EpollSet **pp = &g_epoll_sets; *pp; pp = &(*pp)->next) {
      if (*pp == s) {
        *pp = s->next;
        break;
      }
    }
    for (struct Dll *d = dll_first(s->socks); d; d = dll_next(s->socks, d))
      EpollUnindex(DLL_CONTAINER(struct EpollEntry, elem, d));
    for (struct Dll *d = dll_first(s->misc); d; d = dll_next(s->misc, d))
      EpollUnindex(DLL_CONTAINER(struct EpollEntry, elem, d));
    atomic_fetch_sub(&g_epoll_count, 1);
  }
  pthread_mutex_unlock(&g_epoll_lock);
  if (last)
    EpollDestroy(s);
}

textwindows static int sys_epoll_create_nt(int flags) {
  int fd;
  int64_t port, h;
  struct EpollSet *s;
  if ((fd = __reservefd(-1)) == -1)
    return -1;
  if (!(s = calloc(1, sizeof(*s)))) {
    __releasefd(fd);
    return -1;
  }
  // the concurrency limit of a port holds back a dequeue while that
  // many threads that took a packet earlier are still running, so with
  // more busy epoll_wait() callers than cores nothing comes out at all
  if (!(port = CreateIoCompletionPort(-1, 0, 0, INT32_MAX))) {
    free(s);
    __releasefd(fd);
    return __winerr();
  }
  SetHandleInformation(port, kNtHandleFlagInherit, kNtHandleFlagInherit);
  if (!DuplicateHandle(GetCurrentProcess(), port, GetCurrentProcess(), &h, 0,
                       true, kNtDuplicateSameAccess)) {
    CloseHandle(port);
    free(s);
    __releasefd(fd);
    return __winerr();
  }
  s->refs = 1;
  s->names = 1;
  s->pid = getpid();
  s->port = port;
  pthread_mutex_init(&s->lock, 0);
  pthread_mutex_lock(&g_epoll_lock);
  s->next = g_epoll_sets;
  g_epoll_sets = s;
  atomic_fetch_add(&g_epoll_count, 1);
  pthread_mutex_unlock(&g_epoll_lock);
  struct Fd *f = __get_pib()->fds.p + fd;
  f->handle = h;
  f->flags = O_RDWR;
  if (flags & EPOLL_CLOEXEC)
    f->flags |= O_CLOEXEC;
  f->mode = 0600;
  f->epset = s;
  f->was_created_during_vfork = __vforked;
  f->kind = kFdEpoll;
  return fd;
}

// a duplicate of the fd names the same set
void __epoll_ref(struct Fd *f) {
  struct EpollSet *s = f->epset;
  if (s) {
    pthread_mutex_lock(&g_epoll_lock);
    ++s->refs;
    ++s->names;
    pthread_mutex_unlock(&g_epoll_lock);
  }
}

// closes an epoll fd. the set goes when its last name and waiter do,
// and a waiter parked on it is told to leave.
int __epoll_close(struct Fd *f) {
  int rc = 0;
  if (!CloseHandle(f->handle))
    rc = __winerr();
  struct EpollSet *s = f->epset;
  if (s) {
    pthread_mutex_lock(&g_epoll_lock);
    if (!--s->names) {
      s->closed = true;
      if (s->refs > 1)
        PostQueuedCompletionStatus(s->port, 0, EPOLL_KEY_WAKE, 0);
    }
    pthread_mutex_unlock(&g_epoll_lock);
    EpollRelease(s);
  }
  return rc;
}

// a closed fd leaves every set it was registered with, like on linux
void __epoll_forget(int fd) {
  if (!atomic_load_explicit(&g_epoll_count, memory_order_relaxed))
    return;
  sigset_t m = __sig_block();
  pthread_mutex_lock(&g_epoll_lock);
  struct EpollEntry *e, *next;
  for (e = fd < g_epoll_byfd_n ? g_epoll_byfd[fd] : 0; e; e = next) {
    next = e->fdnext;
    struct EpollSet *s = e->set;
    pthread_mutex_lock(&s->lock);
    EpollDrop(s, e);
    pthread_mutex_unlock(&s->lock);
  }
  pthread_mutex_unlock(&g_epoll_lock);
  __sig_unblock(m);
}

// the i/o paths report that a direction of fd wants watching again.
// EPOLLONESHOT registrations only come back through epoll_ctl(). a
// waiter is woken for anything the pass looks at rather than gets a
// completion for, so a level triggered eventfd is seen right away.
static void EpollRearm(int fd, uint32_t bits) {
  if (!atomic_load_explicit(&g_epoll_count, memory_order_relaxed))
    return;
  sigset_t m = __sig_block();
  pthread_mutex_lock(&g_epoll_lock);
  for (struct EpollEntry *e = fd < g_epoll_byfd_n ? g_epoll_byfd[fd] : 0; e;
       e = e->fdnext) {
    struct EpollSet *s = e->set;
    pthread_mutex_lock(&s->lock);
    if ((e->events & EPOLLET) && !(e->events & EPOLLONESHOT) &&
        (e->armed | bits) != e->armed) {
      e->armed |= bits;
      EpollUpdate(e);
    }
    if (e->kind != kEpollSock)
      EpollWake(s);
    pthread_mutex_unlock(&s->lock);
  }
  pthread_mutex_unlock(&g_epoll_lock);
  __sig_unblock(m);
}

void __epoll_rearm_in(int fd) {
  EpollRearm(fd, EPOLL_ARM_IN);
}

void __epoll_rearm_out(int fd) {
  EpollRearm(fd, EPOLL_ARM_OUT);
}

textwindows static int sys_epoll_ctl_nt(int epfd, int op, int fd,
                                       struct epoll_event *ev) {
  struct EpollSet *s;
  if (!__isfdopen(epfd))
    return ebadf();
  if (!__isfdopen(fd))
    return ebadf();
  if (fd == epfd)
    return einval();
  int rc = 0;
  sigset_t m = __sig_block();
  pthread_mutex_lock(&g_epoll_lock);
  if (!(s = EpollSetOf(epfd))) {
    pthread_mutex_unlock(&g_epoll_lock);
    __sig_unblock(m);
    return einval();
  }
  pthread_mutex_lock(&s->lock);
  struct EpollEntry *e = EpollFind(s, fd);
  switch (op) {
    case EPOLL_CTL_ADD:
      if (e) {
        rc = eexist();
      } else {
        rc = EpollAdd(s, fd, ev);
      }
      break;
    case EPOLL_CTL_MOD:
      if (!e) {
        rc = enoent();
      } else {
        e->events = ev->events;
        e->data = ev->data.u64;
        e->armed = EPOLL_ARM_IN | EPOLL_ARM_OUT | EPOLL_ARM_HUP;
        ++e->epoch;
        EpollUpdate(e);
      }
      break;
    case EPOLL_CTL_DEL:
      if (!e) {
        rc = enoent();
      } else {
        EpollDrop(s, e);
      }
      break;
    default:
      rc = einval();
      break;
  }
  if (!rc)
    EpollWake(s);
  pthread_mutex_unlock(&s->lock);
  pthread_mutex_unlock(&g_epoll_lock);
  __sig_unblock(m);
  return rc;
}

////////////////////////////////////////////////////////////////////////////////
// the wait

// what the pass found on the misc list without a completion: eventfds
// by their counter, pipes' output, and poll() results for the rest
textwindows static int EpollScanMisc(struct EpollSet *s, struct epoll_event *out,
                                     int got, int maxevents,
                                     struct pollfd *pfds, int np) {
  for (struct Dll *d = dll_first(s->misc); d && got < maxevents;
       d = dll_next(s->misc, d)) {
    struct EpollEntry *e = DLL_CONTAINER(struct EpollEntry, elem, d);
    uint32_t m = EpollMask(e);
    uint32_t ev = 0;
    if (!m || e->got)
      continue;
    if (e->kind == kEpollEvent) {
      if ((m & (EPOLLIN | EPOLLRDNORM)) &&
          __atomic_load_n(&__get_pib()->fds.p[e->fd].evcount, __ATOMIC_RELAXED))
        ev |= EPOLLIN | EPOLLRDNORM;
      if (m & EPOLL_OUT_BITS)
        ev |= m & EPOLL_OUT_BITS;
    } else if (e->kind == kEpollPipe) {
      if ((m & EPOLL_OUT_BITS) &&
          (__get_pib()->fds.p[e->fd].flags & O_ACCMODE) != O_RDONLY)
        ev |= m & EPOLL_OUT_BITS;
    } else {
      for (int i = 0; i < np; ++i) {
        if (pfds[i].fd == e->fd) {
          if (pfds[i].revents & POLLNVAL) {
            ev = 0;
          } else {
            ev = PollToEpoll(pfds[i].revents) & m;
            ev = EpollWithHup(ev);
          }
          break;
        }
      }
    }
    if (!ev)
      continue;
    STRACE("epoll_wait fd %d → %#x (misc)", e->fd, ev);
    out[got].events = ev;
    out[got].data.u64 = e->data;
    ++got;
    EpollDisarm(e, ev);
  }
  return got;
}

// a completion says what held when it landed. an edge triggered
// registration reports that as is, since the request was only in
// flight while the direction was armed, unless epoll_ctl() changed
// the registration after the request went out. so does a level
// triggered one whose request went out during this epoll_wait(). one
// that was in flight from an earlier call is asked again, because the
// reader may have drained the fd in between.
textwindows static uint32_t EpollFresh(struct EpollEntry *e, uint32_t ev,
                                       uint32_t pass) {
  if (e->issued == e->epoch &&
      ((e->events & (EPOLLET | EPOLLONESHOT)) || e->pass == pass))
    return ev;
  if (e->kind == kEpollSock) {
    struct sys_pollfd_nt p = {e->handle, 0, 0};
    if (ev & EPOLL_IN_BITS)
      p.events |= POLLRDNORM_ | POLLRDBAND_;
    if (ev & EPOLL_OUT_BITS)
      p.events |= POLLWRNORM_;
    int rc = WSAPoll(&p, 1, 0);
    if (rc == -1)
      return ev;
    uint32_t fresh = EPOLLERR | EPOLLHUP;
    if (p.revents & (POLLRDNORM_ | POLLRDBAND_ | POLLHUP_ | POLLERR_))
      fresh |= EPOLL_IN_BITS;
    if (p.revents & POLLWRNORM_)
      fresh |= EPOLL_OUT_BITS;
    if (p.revents & POLLHUP_)
      fresh |= EPOLLRDHUP;
    return ev & fresh;
  }
  if (e->kind == kEpollPipe && !(ev & (EPOLLERR | EPOLLHUP))) {
    uint32_t avail;
    if (PeekNamedPipe(e->handle, 0, 0, 0, &avail, 0) && !avail)
      return 0;
  }
  return ev;
}

// hands out what the completions brought. the list is taken as a
// whole first, so an entry that comes back during the pass, like a
// hung up pipe whose next read fails on the spot, waits for the next.
textwindows static int EpollScanReady(struct EpollSet *s,
                                      struct epoll_event *out, int got,
                                      int maxevents, uint32_t pass) {
  struct Dll *d;
  struct Dll *batch = s->ready;
  s->ready = 0;
  while (got < maxevents && (d = dll_first(batch))) {
    struct EpollEntry *e = DLL_CONTAINER(struct EpollEntry, ready, d);
    uint32_t ev = e->got & EpollMask(e);
    ev = EpollWithHup(ev);
    dll_remove(&batch, d);
    e->got = 0;
    if (ev)
      ev = EpollFresh(e, ev, pass);
    if (ev) {
      STRACE("epoll_wait fd %d → %#x", e->fd, ev);
      out[got].events = ev;
      out[got].data.u64 = e->data;
      ++got;
      EpollDisarm(e, ev);
    }
    EpollUpdate(e);
  }
  while ((d = dll_last(batch))) {
    dll_remove(&batch, d);
    dll_make_first(&s->ready, d);
  }
  return got;
}

textwindows static int sys_epoll_wait_nt_impl(struct EpollSet *s,
                                             struct epoll_event *out,
                                             int maxevents, int timeout,
                                             sigset_t waitmask) {
  struct pollfd small[32];
  struct pollfd *pfds = small;
  int pcap = ARRAYLEN(small);
  struct NtOverlappedEntry few[64];
  struct NtOverlappedEntry *ents = few;
  uint32_t ecap = ARRAYLEN(few);
  if (maxevents > ecap) {
    uint32_t want = MIN(maxevents, 256);
    struct NtOverlappedEntry *p;
    if ((p = malloc(want * sizeof(*p)))) {
      ents = p;
      ecap = want;
    }
  }
  uint32_t n = 0;
  int rc = 0;
  pthread_mutex_lock(&s->lock);
  uint32_t pass = ++s->pass;
  pthread_mutex_unlock(&s->lock);
  struct timespec deadline = timespec_max;
  if (timeout >= 0)
    deadline = timespec_add(timespec_mono(), timespec_frommillis(timeout));
  struct PosixThread *pt = _pthread_self();
  bool parked = false;
  for (;;) {
    // the leftovers are asked about outside the lock, since poll()
    // takes the fd table lock and close() comes the other way round
    int np = 0;
    int conwant = 0;
    pthread_mutex_lock(&s->lock);
    if (s->npoll) {
      if (s->npoll > pcap) {
        struct pollfd *p = malloc(s->npoll * sizeof(*p));
        if (!p) {
          pthread_mutex_unlock(&s->lock);
          rc = enomem();
          break;
        }
        if (pfds != small)
          free(pfds);
        pfds = p;
        pcap = s->npoll;
      }
      for (struct Dll *d = dll_first(s->misc); d; d = dll_next(s->misc, d)) {
        struct EpollEntry *e = DLL_CONTAINER(struct EpollEntry, elem, d);
        if (e->kind != kEpollPoll)
          continue;
        short events = EpollToPoll(EpollMask(e));
        if (!events)
          continue;
        conwant += e->console && (events & POLLIN);
        pfds[np].fd = e->fd;
        pfds[np].events = events;
        pfds[np].revents = 0;
        ++np;
      }
    }
    pthread_mutex_unlock(&s->lock);
    if (np) {
      struct timespec zero = {0};
      if (ppoll(pfds, np, &zero, 0) == -1)
        np = 0;
    }

    int got = 0;
    pthread_mutex_lock(&s->lock);
    EpollTake(s, ents, n);
    n = 0;
    got = EpollScanReady(s, out, got, maxevents, pass);
    got = EpollScanMisc(s, out, got, maxevents, pfds, np);
    bool closed = s->closed;
    if (!got && !closed) {
      // a request that failed on the way out is ready right away
      EpollFlush(s);
      if (s->ready) {
        pthread_mutex_unlock(&s->lock);
        continue;
      }
      // a console's input handle stays signaled while it holds records,
      // and the poll() above took them all, so it's armed only when an
      // entry would report what arrives
      if (conwant && !s->conarmed &&
          NtSuccess(NtAssociateWaitCompletionPacket(
              s->conpkt, s->port, s->cin, (void *)EPOLL_KEY_CONSOLE, 0, 0, 0,
              0)))
        s->conarmed = true;
    }
    bool sliced = s->nslice > 0 || (conwant && !s->conarmed);
    bool parking = !got && !closed;
    if (parking)
      atomic_fetch_add_explicit(&s->waiters, 1, memory_order_relaxed);
    pthread_mutex_unlock(&s->lock);
    if (got) {
      rc = got;
      break;
    }
    if (closed) {
      // one wakeup can be taken by a waiter along with others, so each
      // waiter that leaves passes it on to the next
      if (atomic_load_explicit(&s->waiters, memory_order_relaxed) > 0)
        PostQueuedCompletionStatus(s->port, 0, EPOLL_KEY_WAKE, 0);
      rc = ebadf();
      break;
    }
    // what's queued on the port is looked at once even when there's
    // no time left, so a zero timeout still hands out what's ready
    uint32_t ms = -1u;
    if (timeout >= 0) {
      struct timespec now = timespec_mono();
      if (timespec_cmp(now, deadline) >= 0) {
        if (parked) {
          atomic_fetch_sub_explicit(&s->waiters, 1, memory_order_relaxed);
          break;
        }
        ms = 0;
      } else {
        int64_t left = timespec_tomillis(timespec_subz(deadline, now));
        ms = left < 0xfffffffe ? left : 0xfffffffe;
      }
    }
    if (sliced)
      ms = MIN(ms, EPOLL_POLL_MS);

    // parks on the port. a signal for this thread is posted there by
    // __sig_wake(), and one that's already queued is taken up front.
    int sig = 0;
    bool32 ok = true;
    pt->pt_event = s->port;
    pt->pt_blkmask = waitmask;
    atomic_store_explicit(&pt->pt_blocker, PT_BLOCKER_IOCP,
                          memory_order_release);
    if (_is_canceled()) {
    } else if (_weaken(__sig_get) && (sig = _weaken(__sig_get)(waitmask))) {
    } else {
      // a timed wait is a timer for the caller, so it gets the fine
      // scheduler tick that nanosleep() asks for, not the 15ms one
      bool timed = ms && ms != -1u && _weaken(__nt_fast_tick);
      if (timed)
        _weaken(__nt_fast_tick)(true);
      ok = GetQueuedCompletionStatusEx(s->port, ents, ecap, &n, ms, false);
      if (timed)
        _weaken(__nt_fast_tick)(false);
    }
    for (;;)
      if (atomic_exchange(&pt->pt_blocker, 0))
        break;
    atomic_fetch_sub_explicit(&s->waiters, 1, memory_order_relaxed);
    parked = true;
    if (!ok) {
      n = 0;
      if (GetLastError() != kNtWaitTimeout) {
        rc = __winerr();
        break;
      }
    }
    int handled = 0;
    if (sig)
      handled = _weaken(__sig_relay)(sig, SI_KERNEL, waitmask);
    if (_check_cancel() == -1) {
      // what the port handed over is written into the entries already
      pthread_mutex_lock(&s->lock);
      EpollTake(s, ents, n);
      pthread_mutex_unlock(&s->lock);
      rc = -1;
      break;
    }
    if (handled) {
      rc = eintr();
      break;
    }
  }
  if (pfds != small)
    free(pfds);
  if (ents != few)
    free(ents);
  return rc;
}

textwindows static int sys_epoll_wait_nt(int epfd, struct epoll_event *out,
                                        int maxevents, int timeout,
                                        const sigset_t *sigmask) {
  int rc;
  struct EpollSet *s;
  if (!__isfdopen(epfd))
    return ebadf();
  BLOCK_SIGNALS;
  pthread_mutex_lock(&g_epoll_lock);
  if ((s = EpollSetOf(epfd)))
    ++s->refs;
  pthread_mutex_unlock(&g_epoll_lock);
  if (s) {
    rc = sys_epoll_wait_nt_impl(s, out, maxevents, timeout,
                                sigmask ? *sigmask : _SigMask);
    EpollRelease(s);
  } else {
    rc = einval();
  }
  ALLOW_SIGNALS;
  return rc;
}

////////////////////////////////////////////////////////////////////////////////
// the api

/**
 * Creates epoll instance.
 *
 * @param flags may have EPOLL_CLOEXEC
 * @return epoll file descriptor, or -1 w/ errno
 * @raise EINVAL if `flags` has unknown bits
 * @raise EMFILE if too many file descriptors are open
 * @raise ENOSYS on Metal
 */
int epoll_create1(int flags) {
  int rc;
  if (flags & ~EPOLL_CLOEXEC) {
    rc = einval();
  } else if (IsLinux()) {
    rc = sys_epoll_create1(flags);
  } else if (IsWindows()) {
    rc = sys_epoll_create_nt(flags);
  } else if (IsXnu() || IsBsd()) {
    rc = sys_epoll_create_kq(flags);
  } else {
    rc = enosys();
  }
  STRACE("epoll_create1(%#x) → %d% m", flags, rc);
  return rc;
}

/**
 * Creates epoll instance.
 *
 * @param size is ignored, but must be positive
 * @return epoll file descriptor, or -1 w/ errno
 * @raise EINVAL if `size` isn't positive
 */
int epoll_create(int size) {
  if (size <= 0)
    return einval();
  return epoll_create1(0);
}

/**
 * Changes epoll interest list.
 *
 * On XNU and BSD the list is the kernel's, so adding an fd that's
 * already registered updates it rather than failing with EEXIST.
 *
 * @param epfd is the epoll file descriptor
 * @param op is EPOLL_CTL_ADD, EPOLL_CTL_MOD, or EPOLL_CTL_DEL
 * @param fd is the file descriptor to watch
 * @param ev has the events and data, ignored by EPOLL_CTL_DEL
 * @return 0 on success, or -1 w/ errno
 * @raise EBADF if `epfd` or `fd` isn't open
 * @raise EINVAL if `epfd` isn't an epoll fd, or `fd` is `epfd`
 * @raise EEXIST if `fd` was already added (Linux and Windows)
 * @raise ENOENT if `fd` wasn't added
 * @raise EFAULT if `ev` is null and `op` needs it
 */
// a regular file or a directory, which linux won't put in an epoll set.
// windows goes by the kind of fd, since fstat() says regular for some
// that cosmo makes itself, like an eventfd
static bool EpollIsFile(int fd) {
  if (IsWindows()) {
    if (!__isfdopen(fd))
      return false;
    struct Fd *f = __get_pib()->fds.p + fd;
    return f->kind == kFdZip ||
           (f->kind == kFdFile && GetFileType(f->handle) == kNtFileTypeDisk);
  }
  struct stat st;
  return !fstat(fd, &st) && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode));
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) {
  int rc;
  if (op != EPOLL_CTL_ADD && op != EPOLL_CTL_MOD && op != EPOLL_CTL_DEL) {
    rc = einval();
  } else if (op != EPOLL_CTL_DEL && !ev) {
    rc = efault();
  } else if (IsLinux()) {
    rc = sys_epoll_ctl(epfd, op, fd, ev);
  } else if (op == EPOLL_CTL_ADD && EpollIsFile(fd)) {
    rc = eperm();  // linux has no readiness for these to report
  } else if (IsWindows()) {
    rc = sys_epoll_ctl_nt(epfd, op, fd, ev);
  } else if (IsXnu() || IsBsd()) {
    rc = sys_epoll_ctl_kq(epfd, op, fd, ev);
  } else {
    rc = enosys();
  }
  STRACE("epoll_ctl(%d, %d, %d, %p) → %d% m", epfd, op, fd, ev, rc);
  return rc;
}

/**
 * Waits for events on epoll instance.
 *
 * @param epfd is the epoll file descriptor
 * @param events receives the ready registrations
 * @param maxevents is how many `events` can hold
 * @param timeout is in milliseconds; -1 waits forever
 * @param sigmask is applied for the duration of the wait, if not null
 * @return number of events, 0 on timeout, or -1 w/ errno
 * @raise EBADF if `epfd` isn't open
 * @raise EINVAL if `epfd` isn't an epoll fd, or `maxevents` isn't positive
 * @raise EINTR if a signal was delivered
 * @raise ECANCELED if thread was cancelled in masked mode
 * @cancelationpoint
 * @norestart
 */
int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                int timeout, const sigset_t *sigmask) {
  int rc;
  BEGIN_CANCELATION_POINT;
  if (maxevents <= 0) {
    rc = einval();
  } else if (IsLinux()) {
    rc = sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask, 8);
  } else if (IsWindows()) {
    rc = sys_epoll_wait_nt(epfd, events, maxevents, timeout, sigmask);
  } else if (IsXnu() || IsBsd()) {
    rc = sys_epoll_wait_kq(epfd, events, maxevents, timeout, sigmask);
  } else {
    rc = enosys();
  }
  END_CANCELATION_POINT;
  STRACE("epoll_pwait(%d, %p, %d, %d, %s) → %d% m", epfd, events, maxevents,
         timeout, DescribeSigset(0, sigmask), rc);
  return rc;
}

/**
 * Waits for events on epoll instance.
 * @see epoll_pwait()
 */
int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
               int timeout) {
  return epoll_pwait(epfd, events, maxevents, timeout, 0);
}

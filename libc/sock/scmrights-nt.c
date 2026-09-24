#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/iovec.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/fds.h"
#include "libc/mem/mem.h"
#include "libc/nt/enum/processaccess.h"
#include "libc/nt/files.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/iovec.h"
#include "libc/nt/struct/overlapped.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/calls/struct/iovec.internal.h"
#include "libc/sock/struct/cmsghdr.h"
#include "libc/sock/struct/msghdr.h"
#include "libc/cosmotime.h"
#include "libc/nt/errors.h"
#include "libc/nt/synchronization.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/msg.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/scm.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#if SupportsWindows()

/**
 * @fileoverview SCM_RIGHTS over AF_UNIX stream sockets on Windows.
 *
 * NT has no ancillary data. A message that carries descriptors goes out
 * as a frame in the byte stream: a 16 byte magic, the count, then one
 * entry per descriptor holding a handle that was already duplicated into
 * the receiving process (SIO_AF_UNIX_GETPEERPID names it), followed by
 * the message bytes in the same WSASend. Every receive on such a socket
 * looks for the magic, pulls frames out of the data before it reaches
 * the caller, installs the handles in the descriptor table and queues
 * the new numbers on the socket until a recvmsg() with a control buffer
 * takes them.
 */

#define SIO_AF_UNIX_GETPEERPID 0x58000100u
#define SCM_MAX_FD             253
#define SCM_MAGIC_LEN          16

static const unsigned char kScmMagic[SCM_MAGIC_LEN] = {
    0xC0, 0x5E, 0x0F, 0xD5, 'c', 'o', 's', 'm', 'o', '.', 's', 'c', 'm', 0x01, 0xF3, 0x9A};

struct ScmHead {
  unsigned char magic[SCM_MAGIC_LEN];
  uint32_t nfds;
  uint32_t datalen;
};

struct ScmEntry {
  int64_t handle;
  int32_t kind;
  uint32_t flags;
  uint32_t mode;
  int32_t family;
  int32_t type;
  int32_t protocol;
  uint32_t evflags;
  int64_t offset;  // file position at the time of sending
};

struct ScmQueue {
  int n;
  int cap;
  int fds[];
};

struct ScmRecvArgs {
  struct NtIovec iov;
};

textwindows bool __scm_stream_nt(struct Fd *f) {
  return f->kind == kFdSocket && f->family == AF_UNIX && f->type == SOCK_STREAM;
}

textwindows static int ScmRecvStart(int64_t handle, struct NtOverlapped *overlap,
                                    uint32_t *flags, void *arg) {
  struct ScmRecvArgs *args = arg;
  return WSARecv(handle, &args->iov, 1, 0, flags, overlap, 0);
}

// pulls exactly n bytes out of the socket
textwindows static int ScmRecvAll(int64_t handle, void *buf, size_t n,
                                  uint64_t waitmask) {
  char *p = buf;
  while (n) {
    struct ScmRecvArgs args = {{n, p}};
    ssize_t got = __winsock_block(handle, 0, false, 0, waitmask, ScmRecvStart,
                                  &args);
    if (got == -1)
      return -1;
    if (!got)
      return econnreset();
    p += got;
    n -= got;
  }
  return 0;
}

// looks at the first n queued bytes without taking them. a frame is
// sent in one WSASend but a receive that was already pending completes
// as soon as the first bytes land, so when what is there so far looks
// like the start of the magic this waits up to `waitms` for the rest
// before calling it data. Returns how many bytes were peeked, or -1
textwindows static ssize_t ScmPeek(int64_t handle, void *buf, size_t n,
                                   int waitms, uint64_t waitmask) {
  ssize_t got = 0;
  struct timespec deadline =
      timespec_add(timespec_mono(), timespec_frommillis(waitms));
  for (;;) {
    if (__winsock_recv_ready(handle, MSG_PEEK)) {
      struct ScmRecvArgs args = {{n, buf}};
      got = __winsock_block(handle, __msg2host(MSG_PEEK), true, 0, waitmask,
                            ScmRecvStart, &args);
      if (got == -1) {
        if (errno != EAGAIN)
          return -1;
        got = 0;
      }
      if ((size_t)got == n)
        return got;
      if (got && memcmp(buf, kScmMagic, got))
        return got;  // not a frame, no point waiting
    }
    if (timespec_cmp(timespec_mono(), deadline) >= 0)
      return got;
    SleepEx(1, false);
  }
}

struct ScmRecvIov {
  const struct iovec *iov;
  size_t iovlen;
  struct NtIovec iovnt[16];
};

textwindows static int ScmRecvIovStart(int64_t handle,
                                       struct NtOverlapped *overlap,
                                       uint32_t *flags, void *arg) {
  struct ScmRecvIov *a = arg;
  return WSARecv(handle, a->iovnt, __iovec2nt(a->iovnt, a->iov, a->iovlen), 0,
                 flags, overlap, 0);
}

// the bytes a receive landed in the caller's iovecs, seen as one buffer

textwindows static unsigned char *ViewPtr(const struct iovec *iov, size_t iovlen,
                                          size_t off, size_t *run) {
  for (size_t i = 0; i < iovlen; ++i) {
    if (off < iov[i].iov_len) {
      *run = iov[i].iov_len - off;
      return (unsigned char *)iov[i].iov_base + off;
    }
    off -= iov[i].iov_len;
  }
  *run = 0;
  return 0;
}

// the leading n bytes of the caller's buffers as an iovec array of
// their own, so a receive can be told where to stop
textwindows static size_t ViewTrim(const struct iovec *iov, size_t iovlen,
                                   size_t n, struct iovec out[16]) {
  size_t k = 0;
  for (size_t i = 0; i < iovlen && k < 16 && n; ++i) {
    if (!iov[i].iov_len)
      continue;
    out[k].iov_base = iov[i].iov_base;
    out[k].iov_len = iov[i].iov_len < n ? iov[i].iov_len : n;
    n -= out[k].iov_len;
    ++k;
  }
  return k;
}

// finds the magic at or after `from`; a tail that matches only the
// start of the magic is reported through *partial
textwindows static ssize_t ViewFind(const struct iovec *iov, size_t iovlen,
                                    size_t total, size_t from, size_t *partial) {
  *partial = 0;
  size_t off = from;
  while (off < total) {
    size_t run;
    unsigned char *p = ViewPtr(iov, iovlen, off, &run);
    if (run > total - off)
      run = total - off;
    unsigned char *q = memchr(p, kScmMagic[0], run);
    if (!q) {
      off += run;
      continue;
    }
    off += q - p;
    size_t avail = total - off;
    size_t k = avail < SCM_MAGIC_LEN ? avail : SCM_MAGIC_LEN;
    size_t j;
    for (j = 1; j < k; ++j) {
      size_t r;
      if (*ViewPtr(iov, iovlen, off + j, &r) != kScmMagic[j])
        break;
    }
    if (j == SCM_MAGIC_LEN)
      return off;
    if (j == k) {
      *partial = k;
      return -1;
    }
    ++off;
  }
  return -1;
}

textwindows static void ScmInstall(struct Fd *f, uint32_t n,
                                   const struct ScmEntry *e,
                                   const struct NtWsaProtocolInfo *pi) {
  struct ScmQueue *q = f->scm;
  if (!q || q->n + n > q->cap) {
    int cap = (q ? q->cap : 0) + n + 8;
    struct ScmQueue *nq = realloc(q, sizeof(*q) + cap * sizeof(int));
    if (!nq) {
      for (uint32_t i = 0; i < n; ++i)
        if (e[i].kind != kFdSocket)
          CloseHandle(e[i].handle);
      return;
    }
    if (!q)
      nq->n = 0;
    nq->cap = cap;
    f->scm = q = nq;
  }
  uint32_t sk = 0;
  for (uint32_t i = 0; i < n; ++i) {
    int64_t handle;
    if (e[i].kind == kFdSocket) {
      // a socket travels as a WSAPROTOCOL_INFO blob so the receiver's
      // winsock provider knows it; a raw DuplicateHandle would let
      // recv/send through but leave WSAPoll() answering ENOTSOCK
      handle = WSASocket(-1, -1, -1, &pi[sk++], 0, kNtWsaFlagOverlapped);
      if (handle == -1)
        continue;
    } else {
      handle = e[i].handle;
    }
    int fd = __reservefd(-1);
    if (fd == -1) {
      if (e[i].kind == kFdSocket)
        CloseHandle(handle);
      else
        CloseHandle(handle);
      continue;
    }
    struct Fd *g = __get_pib()->fds.p + fd;
    g->flags = e[i].flags & ~O_CLOEXEC;
    g->mode = e[i].mode;
    g->handle = handle;
    g->family = e[i].family;
    g->type = e[i].type;
    g->protocol = e[i].protocol;
    g->evflags = e[i].evflags;
    g->was_created_during_vfork = __vforked;
    if (e[i].kind == kFdFile) {
      __fds_lock();
      g->cursor = __cursor_new();
      __fds_unlock();
      if (g->cursor)
        g->cursor->shared->pointer = e[i].offset;
    }
    g->kind = e[i].kind;
    q->fds[q->n++] = fd;
  }
}

// consumes a frame that sits at the front of the queue and installs
// its descriptors. returns how many data bytes belong to the message
textwindows static ssize_t ScmTakeFrame(struct Fd *f, uint64_t waitmask) {
  struct ScmHead head;
  if (ScmRecvAll(f->handle, &head, sizeof(head), waitmask) == -1)
    return -1;
  if (head.nfds > SCM_MAX_FD)
    return eproto();
  if (head.nfds) {
    size_t elen = head.nfds * sizeof(struct ScmEntry);
    struct ScmEntry *ents = malloc(elen);
    if (!ents)
      return enomem();
    if (ScmRecvAll(f->handle, ents, elen, waitmask) == -1) {
      free(ents);
      return -1;
    }
    uint32_t nsock = 0;
    for (uint32_t i = 0; i < head.nfds; ++i)
      nsock += ents[i].kind == kFdSocket;
    struct NtWsaProtocolInfo *pi = 0;
    if (nsock) {
      if (!(pi = malloc(nsock * sizeof(*pi)))) {
        free(ents);
        return enomem();
      }
      if (ScmRecvAll(f->handle, pi, nsock * sizeof(*pi), waitmask) == -1) {
        free(pi);
        free(ents);
        return -1;
      }
    }
    ScmInstall(f, head.nfds, ents, pi);
    free(pi);
    free(ents);
  }
  return head.datalen;
}

/**
 * Receives from a unix stream socket the way linux delivers it.
 *
 * A message that carried descriptors is never glued together with its
 * neighbours: a receive stops in front of a frame, and once a frame has
 * been taken it hands out no more than that message's own bytes. The
 * queue is peeked first so nothing past the boundary leaves the socket.
 *
 * @return bytes received, 0 on eof, or -1 w/ errno
 */
textwindows ssize_t __scm_recv_nt(struct Fd *f, const struct iovec *iov,
                                  size_t iovlen, uint32_t flags, bool nonblock,
                                  uint64_t waitmask) {
  bool peek = flags & MSG_PEEK;
  uint32_t pflags =
      __msg2host((flags & ~(MSG_DONTWAIT | MSG_WAITALL)) | MSG_PEEK);
  uint32_t hflags = __msg2host(flags & ~(MSG_DONTWAIT | MSG_WAITALL | MSG_PEEK));
  size_t room = 0;
  for (size_t i = 0; i < iovlen && i < 16; ++i)
    room += iov[i].iov_len;
  for (;;) {
    if (nonblock && !__winsock_recv_ready(f->handle, flags))
      return eagain();
    struct ScmRecvIov args = {iov, iovlen};
    ssize_t got = __winsock_block(f->handle, pflags, nonblock, f->rcvtimeo,
                                  waitmask, ScmRecvIovStart, &args);
    if (got == -1 && errno == kNtErrorHandleEof)
      got = 0;
    if (got <= 0)
      return got;
    size_t partial, want = got;
    ssize_t off = ViewFind(iov, iovlen, got, 0, &partial);
    if (off > 0) {
      want = off;
    } else if (off < 0 && partial) {
      want = got - partial;
      if (!want) {
        // everything queued so far could be the start of a frame
        unsigned char magic[SCM_MAGIC_LEN];
        ssize_t n = ScmPeek(f->handle, magic, SCM_MAGIC_LEN,
                            partial >= 2 ? 200 : 20, waitmask);
        if (n == -1)
          return -1;
        if ((size_t)n == SCM_MAGIC_LEN &&
            !memcmp(magic, kScmMagic, SCM_MAGIC_LEN)) {
          off = 0;
        } else {
          want = got;
        }
      }
    }
    if (off == 0) {
      ssize_t datalen = ScmTakeFrame(f, waitmask);
      if (datalen == -1)
        return -1;
      if (!datalen)
        continue;  // nothing but descriptors, keep going
      want = (size_t)datalen < room ? datalen : room;
      if (nonblock && !__winsock_recv_ready(f->handle, flags))
        return eagain();
    } else if (peek) {
      return want;  // the bytes already sit in the caller's buffers
    }
    struct iovec trim[16];
    struct ScmRecvIov take = {trim, ViewTrim(iov, iovlen, want, trim)};
    ssize_t rc = __winsock_block(f->handle, peek ? pflags : hflags, nonblock,
                                 f->rcvtimeo, waitmask, ScmRecvIovStart, &take);
    if (rc == -1 && errno == kNtErrorHandleEof)
      rc = 0;
    return rc;
  }
}

/**
 * Hands queued descriptors to a recvmsg() caller through msg_control.
 */
textwindows void __scm_take_nt(struct Fd *f, struct msghdr *msg, bool cloexec) {
  struct ScmQueue *q = f->scm;
  if (!q || !q->n) {
    msg->msg_controllen = 0;
    return;
  }
  size_t space = msg->msg_controllen;
  size_t fit = space >= CMSG_LEN(0) ? (space - CMSG_LEN(0)) / sizeof(int) : 0;
  if (fit > (size_t)q->n)
    fit = q->n;
  if (!fit) {
    msg->msg_controllen = 0;
    msg->msg_flags |= MSG_CTRUNC;
    return;
  }
  struct cmsghdr *c = msg->msg_control;
  c->cmsg_len = CMSG_LEN(fit * sizeof(int));
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  int *out = (int *)CMSG_DATA(c);
  for (size_t i = 0; i < fit; ++i) {
    out[i] = q->fds[i];
    if (cloexec)
      __get_pib()->fds.p[q->fds[i]].flags |= O_CLOEXEC;
  }
  memmove(q->fds, q->fds + fit, (q->n - fit) * sizeof(int));
  q->n -= fit;
  size_t used = CMSG_SPACE(fit * sizeof(int));
  msg->msg_controllen = used <= space ? used : c->cmsg_len;
  if (q->n)
    msg->msg_flags |= MSG_CTRUNC;
}

/**
 * Closes descriptors nobody took before the socket went away.
 */
textwindows void __scm_forget_nt(struct Fd *f) {
  struct ScmQueue *q = f->scm;
  if (!q)
    return;
  f->scm = 0;
  for (int i = 0; i < q->n; ++i)
    close(q->fds[i]);
  free(q);
}

textwindows static bool ScmPassable(int fd) {
  if (!__isfdopen(fd))
    return false;
  struct Fd *g = __get_pib()->fds.p + fd;
  switch (g->kind) {
    case kFdFile:
    case kFdConsole:
    case kFdDevNull:
    case kFdDevRandom:
    case kFdEvent:
      return true;
    case kFdSocket:
      return g->family != AF_PACKET;
    default:
      return false;
  }
}

/**
 * Sends a message with SCM_RIGHTS attached.
 */
textwindows ssize_t __scm_send_nt(int fd, const struct msghdr *msg, int flags) {
  int list[SCM_MAX_FD];
  size_t n = 0;
  for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
    if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
        c->cmsg_len < CMSG_LEN(0))
      return einval();
    size_t k = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    if (n + k > SCM_MAX_FD)
      return einval();
    memcpy(list + n, CMSG_DATA(c), k * sizeof(int));
    n += k;
  }
  if (!n)
    return sys_send_nt(fd, msg->msg_iov, msg->msg_iovlen, flags);
  size_t datalen = 0;
  for (size_t i = 0; i < msg->msg_iovlen; ++i)
    datalen += msg->msg_iov[i].iov_len;
  if (!datalen)
    return 0;
  for (size_t i = 0; i < n; ++i)
    if (!ScmPassable(list[i]))
      return ebadf();

  struct Fd *f = __get_pib()->fds.p + fd;
  uint32_t pid = 0, br;
  if (WSAIoctl(f->handle, SIO_AF_UNIX_GETPEERPID, 0, 0, &pid, sizeof(pid), &br,
               0, 0) == -1)
    return __winsockerr();
  int64_t proc;
  if (pid == GetCurrentProcessId()) {
    proc = GetCurrentProcess();
  } else if (!(proc = OpenProcess(kNtProcessDupHandle, false, pid))) {
    return __winerr();
  }

  size_t nsock = 0;
  for (size_t i = 0; i < n; ++i)
    nsock += __get_pib()->fds.p[list[i]].kind == kFdSocket;
  size_t hlen = sizeof(struct ScmHead) + n * sizeof(struct ScmEntry) +
                nsock * sizeof(struct NtWsaProtocolInfo);
  bool gather = msg->msg_iovlen < 16;
  unsigned char *frame = malloc(gather ? hlen : hlen + datalen);
  if (!frame) {
    if (proc != GetCurrentProcess())
      CloseHandle(proc);
    return enomem();
  }
  struct ScmHead *head = (struct ScmHead *)frame;
  struct ScmEntry *ents = (struct ScmEntry *)(frame + sizeof(*head));
  struct NtWsaProtocolInfo *pinfo =
      (struct NtWsaProtocolInfo *)(frame + sizeof(*head) +
                                   n * sizeof(struct ScmEntry));
  memcpy(head->magic, kScmMagic, SCM_MAGIC_LEN);
  head->nfds = n;
  head->datalen = datalen;
  size_t made = 0, pk = 0;
  ssize_t rc = 0;
  for (; made < n; ++made) {
    struct Fd *g = __get_pib()->fds.p + list[made];
    if (g->kind == kFdSocket) {
      // hand the socket over the winsock way so WSAPoll() works there
      if (WSADuplicateSocket(g->handle, pid, &pinfo[pk++]) == -1) {
        rc = __winsockerr();
        break;
      }
      ents[made].handle = 0;
    } else {
      int64_t dup;
      if (!DuplicateHandle(GetCurrentProcess(), g->handle, proc, &dup, 0, false,
                           kNtDuplicateSameAccess)) {
        rc = __winerr();
        break;
      }
      ents[made].handle = dup;
    }
    ents[made].kind = g->kind;
    ents[made].flags = g->flags;
    ents[made].mode = g->mode;
    ents[made].family = g->family;
    ents[made].type = g->type;
    ents[made].protocol = g->protocol;
    ents[made].evflags = g->evflags;
    ents[made].offset = g->cursor ? g->cursor->shared->pointer : 0;
  }
  if (rc != -1) {
    if (gather) {
      struct iovec iov[16];
      iov[0].iov_base = frame;
      iov[0].iov_len = hlen;
      for (size_t i = 0; i < msg->msg_iovlen; ++i)
        iov[i + 1] = msg->msg_iov[i];
      rc = sys_send_nt(fd, iov, msg->msg_iovlen + 1, flags);
    } else {
      unsigned char *p = frame + hlen;
      for (size_t i = 0; i < msg->msg_iovlen; ++i) {
        memcpy(p, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
        p += msg->msg_iov[i].iov_len;
      }
      rc = sys_send_nt(fd, &(struct iovec){frame, hlen + datalen}, 1, flags);
    }
    if (rc != -1 && (size_t)rc < hlen) {
      rc = eio();
    } else if (rc != -1) {
      rc -= hlen;
    }
  }
  if (rc == -1) {
    int e = errno;
    for (size_t i = 0; i < made; ++i)
      if (ents[i].kind != kFdSocket)
        DuplicateHandle(proc, ents[i].handle, 0, 0, 0, false,
                        kNtDuplicateCloseSource);
    errno = e;
  }
  if (proc != GetCurrentProcess())
    CloseHandle(proc);
  free(frame);
  return rc;
}

#endif /* SupportsWindows() */

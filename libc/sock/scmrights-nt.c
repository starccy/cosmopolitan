#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/intrin/weaken.h"
#include "libc/calls/struct/iovec.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/pgrp.h"
#include "libc/mem/mem.h"
#include "libc/nt/enum/processaccess.h"
#include "libc/nt/files.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/fileinfobyhandleclass.h"
#include "libc/nt/events.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/iovec.h"
#include "libc/nt/struct/overlapped.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/nt/ipc.h"
#include "libc/sysv/consts/poll.h"
#include "libc/sock/struct/pollfd.h"
#include "libc/macros.h"
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
#include "libc/sysv/consts/so.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#if SupportsWindows()

/**
 * @fileoverview SCM_RIGHTS over AF_UNIX sockets on Windows.
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
 *
 * When the peer is this very process, as with a socketpair() whose other
 * end may since have gone to a child, the receiver can't be known. Then
 * the handles stay in the sender and the frame names it as their source;
 * a receiver in another process takes them over from there, closing the
 * sender's copies. A socket that travels this way arrives as a plain
 * handle, which sends and receives but which WSAPoll() doesn't know.
 *
 * SOCK_DGRAM and SOCK_SEQPACKET pairs are message mode named pipes on NT
 * (socketpair-nt.c), where one message is one write. Their frame goes in
 * front of the data in the same message, and reads look for it there.
 *
 * A SOCK_SEQPACKET socket made by socket() is a stream socket underneath
 * (afunix has no other kind) on which every message is a frame, with or
 * without descriptors, and a receive takes one frame: what doesn't fit
 * is dropped and reported as MSG_TRUNC, as linux does.
 *
 * The sender of what a receive returns, for SO_PASSCRED: a socket comes
 * from a process (Fd::credpid), the one that made it or accepted it. A
 * peer's SIO_AF_UNIX_GETPEERPID names that process, and for a pair it's
 * the one that called socketpair(). Anyone else, a fork()ed child say,
 * puts a frame with its pid in front of each message it sends, but only
 * to a receiver that turned SO_PASSCRED on, since a host program at the
 * other end would take the frame for data. The receiver says so with a
 * named event under a key both ends work out: the pipe's name for a
 * pair, the two addresses of a stream socket.
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
  uint32_t srcpid;  // 0 when the handles are already the receiver's
  int32_t credpid;  // the sending process when it isn't the usual one
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
  return f->kind == kFdSocket && f->family == AF_UNIX &&
         (f->type == SOCK_STREAM || f->type == SOCK_SEQPACKET);
}

// a socket() made SOCK_SEQPACKET, framed on a stream
textwindows bool __scm_seqpacket_nt(struct Fd *f) {
  return f->kind == kFdSocket && f->family == AF_UNIX &&
         f->type == SOCK_SEQPACKET;
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

// a handle the frame carries, made ours. `src` is the sending process
// when the handles are still in it
textwindows static int64_t ScmTake(int64_t src, int64_t h) {
  int64_t mine;
  if (!src)
    return h;
  if (!DuplicateHandle(src, h, GetCurrentProcess(), &mine, 0, false,
                       kNtDuplicateSameAccess | kNtDuplicateCloseSource))
    return -1;
  return mine;
}

// a copy of a handle the frame carries, which stays in the frame
textwindows static int64_t ScmCopy(int64_t src, int64_t h) {
  int64_t mine;
  if (!DuplicateHandle(src ? src : GetCurrentProcess(), h, GetCurrentProcess(),
                       &mine, 0, false, kNtDuplicateSameAccess))
    return -1;
  return mine;
}

// installs a frame's descriptors on f. with `copy` the frame keeps its
// handles, for MSG_PEEK
textwindows static void ScmInstall(struct Fd *f, uint32_t n,
                                   const struct ScmEntry *e,
                                   const struct NtWsaProtocolInfo *pi,
                                   uint32_t srcpid, bool copy) {
  int64_t src = 0;
  bool ours = !srcpid || srcpid == GetCurrentProcessId();
  if (!ours && !(src = OpenProcess(kNtProcessDupHandle, false, srcpid)))
    return;  // the sender is gone and its handles with it
  struct ScmQueue *q = f->scm;
  if (!q || q->n + n > q->cap) {
    int cap = (q ? q->cap : 0) + n + 8;
    struct ScmQueue *nq = realloc(q, sizeof(*q) + cap * sizeof(int));
    if (!nq) {
      for (uint32_t i = 0; i < n && !copy; ++i)
        if (e[i].handle) {
          if (src)
            DuplicateHandle(src, e[i].handle, 0, 0, 0, false,
                            kNtDuplicateCloseSource);
          else
            CloseHandle(e[i].handle);
        }
      if (src)
        CloseHandle(src);
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
    if (e[i].kind == kFdSocket && ours) {
      // a socket travels as a WSAPROTOCOL_INFO blob so the receiver's
      // winsock provider knows it; a raw DuplicateHandle would let
      // recv/send through but leave WSAPoll() answering ENOTSOCK
      handle = WSASocket(-1, -1, -1, &pi[sk++], 0, kNtWsaFlagOverlapped);
      if (e[i].handle && !copy)
        CloseHandle(e[i].handle);  // the raw copy kept for other takers
      if (handle == -1)
        continue;
    } else {
      if (e[i].kind == kFdSocket)
        ++sk;
      if ((handle = copy ? ScmCopy(src, e[i].handle)
                         : ScmTake(src, e[i].handle)) == -1)
        continue;
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
  if (src)
    CloseHandle(src);
}

// consumes a frame that sits at the front of the queue and installs
// its descriptors. returns how many data bytes belong to the message,
// whose sender it notes for SO_PASSCRED
textwindows static ssize_t ScmTakeFrame(struct Fd *f, uint64_t waitmask) {
  struct ScmHead head;
  if (ScmRecvAll(f->handle, &head, sizeof(head), waitmask) == -1)
    return -1;
  f->credfrom = head.credpid;
  f->credleft = head.datalen;
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
    ScmInstall(f, head.nfds, ents, pi, head.srcpid, false);
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
  bool seq = f->type == SOCK_SEQPACKET;
  uint32_t pflags =
      __msg2host((flags & ~(MSG_DONTWAIT | MSG_WAITALL)) | MSG_PEEK);
  uint32_t hflags = __msg2host(flags & ~(MSG_DONTWAIT | MSG_WAITALL | MSG_PEEK));
  size_t room = 0;
  for (size_t i = 0; i < iovlen && i < 16; ++i)
    room += iov[i].iov_len;
  f->msgtrunc = false;
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
    ssize_t off = -1;
    if (f->credleft) {
      // the rest of a framed message, from its sender
      want = MIN(want, f->credleft);
    } else if (seq) {
      // every message is a frame, so what's queued starts with one
      f->credfrom = 0;
      off = 0;
    } else {
      f->credfrom = 0;
      off = ViewFind(iov, iovlen, got, 0, &partial);
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
    }
    if (off == 0) {
      ssize_t datalen = ScmTakeFrame(f, waitmask);
      if (datalen == -1)
        return -1;
      if (!datalen) {
        if (seq)
          return 0;  // an empty message
        continue;  // nothing but descriptors, keep going
      }
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
    if (rc > 0 && !peek)
      f->credleft -= MIN((size_t)rc, f->credleft);
    // a message is one receive: the rest of it is thrown away
    if (rc > 0 && !peek && seq && f->credleft) {
      char drop[512];
      while (f->credleft) {
        size_t n = MIN(f->credleft, sizeof(drop));
        if (ScmRecvAll(f->handle, drop, n, waitmask) == -1)
          break;
        f->credleft -= n;
      }
      f->msgtrunc = true;
    }
    return rc;
  }
}

/**
 * The process at the other end: for a stream socket the one the peer
 * comes from, for a pair the one that made it. 0 when there's none.
 */
textwindows int __scm_peer_pid_nt(struct Fd *f) {
  uint32_t pid = 0, br;
  if (__scm_msgpipe_nt(f)) {
    if (f->credpid)
      return f->credpid;
    GetNamedPipeServerProcessId(f->handle, &pid);
  } else if (f->kind == kFdSocket && f->family == AF_UNIX &&
             f->type == SOCK_STREAM) {
    if (WSAIoctl(f->handle, SIO_AF_UNIX_GETPEERPID, 0, 0, &pid, sizeof(pid),
                 &br, 0, 0) == -1)
      pid = 0;
  }
  return pid ? __pid_of_winpid(pid) : 0;
}

/**
 * Hands queued descriptors to a recvmsg() caller through msg_control,
 * after the sender's credentials when SO_PASSCRED asks for them.
 */
textwindows void __scm_take_nt(struct Fd *f, struct msghdr *msg, bool cloexec) {
  size_t off = 0;
  if (f->passcred)
    off = __cred_cmsg(msg, f->credfrom ? f->credfrom : __scm_peer_pid_nt(f));
  struct ScmQueue *q = f->scm;
  if (!q || !q->n) {
    msg->msg_controllen = off;
    return;
  }
  size_t space = msg->msg_controllen - off;
  size_t fit = space >= CMSG_LEN(0) ? (space - CMSG_LEN(0)) / sizeof(int) : 0;
  if (fit > (size_t)q->n)
    fit = q->n;
  if (!fit) {
    msg->msg_controllen = off;
    msg->msg_flags |= MSG_CTRUNC;
    return;
  }
  struct cmsghdr *c = (struct cmsghdr *)((char *)msg->msg_control + off);
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
  msg->msg_controllen = off + (used <= space ? used : c->cmsg_len);
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

// a SOCK_DGRAM or SOCK_SEQPACKET socketpair end, a message mode pipe
textwindows bool __scm_msgpipe_nt(struct Fd *f) {
  return f->kind == kFdFile && (f->mode & 0170000) == 0140000;
}

// the descriptors a message's SCM_RIGHTS carry, into list; -1 w/ errno
__msabi extern typeof(__sys_getsockname_nt) *const __imp_getsockname;
__msabi extern typeof(__sys_getpeername_nt) *const __imp_getpeername;

// the path in an address winsock gave back, which may be empty
textwindows static size_t ScmSunPath(const char *addr, uint32_t len,
                                     const char **path) {
  *path = addr + 2;
  return len > 2 ? strnlen(addr + 2, len - 2) : 0;
}

textwindows static uint64_t ScmHash(uint64_t h, const void *p, size_t n) {
  for (size_t i = 0; i < n; ++i)
    h = (h ^ ((const unsigned char *)p)[i]) * 0x100000001b3;
  return h;
}

// the event a receiver with SO_PASSCRED makes, see the top of this file
textwindows static bool ScmCredName(struct Fd *f, char16_t name[64]) {
  uint64_t h = 0xcbf29ce484222325;
  if (__scm_msgpipe_nt(f)) {
    struct {
      uint32_t n;
      char16_t s[128];
    } ni;
    if (!GetFileInformationByHandleEx(f->handle, kNtFileNameInfo, &ni,
                                      sizeof(ni)))
      return false;
    h = ScmHash(h, ni.s, ni.n);
  } else {
    char a[128], b[128];
    uint32_t al = sizeof(a), bl = sizeof(b);
    if (__imp_getsockname(f->handle, a, &al))
      al = 0;
    if (__imp_getpeername(f->handle, b, &bl))
      bl = 0;
    const char *pa, *pb;
    size_t na = ScmSunPath(a, al, &pa), nb = ScmSunPath(b, bl, &pb);
    int c = memcmp(pa, pb, MIN(na, nb));
    if (c > 0 || (!c && na > nb)) {
      const char *pt = pa;
      size_t nt = na;
      pa = pb, na = nb;
      pb = pt, nb = nt;
    }
    h = ScmHash(h, pa, na);
    h = ScmHash(h, "", 1);
    h = ScmHash(h, pb, nb);
  }
  static const char16_t kPrefix[] = u"Local\\cosmo.passcred.";
  memcpy(name, kPrefix, sizeof(kPrefix));
  char16_t *p = name + ARRAYLEN(kPrefix) - 1;
  for (int i = 16; i--;)
    *p++ = "0123456789abcdef"[(h >> (i * 4)) & 15];
  *p = 0;
  return true;
}

/**
 * Lets the senders at the other end of f know that it wants to be told
 * who they are, see the top of this file.
 */
textwindows void __scm_passcred_nt(struct Fd *f) {
  static struct {
    atomic_int lock;
    int n;
    uint64_t made[64];
  } g;
  char16_t name[64];
  if (!(__scm_msgpipe_nt(f) || __scm_stream_nt(f)) || !ScmCredName(f, name))
    return;
  uint64_t key = ScmHash(0, name, 64);
  while (atomic_exchange_explicit(&g.lock, 1, memory_order_acquire))
    SleepEx(0, false);
  bool made = false;
  for (int i = 0; i < g.n; ++i)
    made |= g.made[i] == key;
  if (!made && g.n < ARRAYLEN(g.made))
    g.made[g.n++] = key;
  atomic_store_explicit(&g.lock, 0, memory_order_release);
  // held until this process exits
  if (!made)
    CreateEvent(0, true, false, name);
}

// this process's pid when its messages need a frame to say who sent
// them, 0 when the receiver will know or doesn't care
textwindows static int32_t ScmCredPid(struct Fd *f) {
  int pid = __get_pib()->pid;
  if (f->credpid == pid)
    return 0;
  char16_t name[64];
  int64_t h;
  if (!ScmCredName(f, name) || !(h = OpenEvent(kNtSynchronize, false, name)))
    return 0;
  CloseHandle(h);
  return pid;
}

textwindows static ssize_t ScmList(const struct msghdr *msg,
                                   int list[SCM_MAX_FD]) {
  size_t n = 0;
  if (!msg->msg_control || !msg->msg_controllen)
    return 0;
  for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
    // the receiver learns who sent anyway, see the top of this file
    if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS) {
      if (__cred_check(c) == -1)
        return -1;
      continue;
    }
    if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
        c->cmsg_len < CMSG_LEN(0))
      return einval();
    size_t k = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    if (n + k > SCM_MAX_FD)
      return einval();
    memcpy(list + n, CMSG_DATA(c), k * sizeof(int));
    n += k;
  }
  for (size_t i = 0; i < n; ++i)
    if (!ScmPassable(list[i]))
      return ebadf();
  return n;
}


// Builds the head of a frame for n descriptors, made for process pid. When
// that's this process the handles stay ours, see the top of this file.
// Returns 0 or -1 w/ errno
textwindows static int ScmBuild(struct ScmFrame *fr, const int *list, size_t n,
                                uint32_t pid, size_t datalen, size_t room,
                                int32_t credpid) {
  bool keep = pid == GetCurrentProcessId();
  if (keep) {
    fr->proc = GetCurrentProcess();
  } else if (!(fr->proc = OpenProcess(kNtProcessDupHandle, false, pid))) {
    return __winerr();
  }
  size_t nsock = 0;
  for (size_t i = 0; i < n; ++i)
    nsock += __get_pib()->fds.p[list[i]].kind == kFdSocket;
  fr->hlen = sizeof(struct ScmHead) + n * sizeof(struct ScmEntry) +
             nsock * sizeof(struct NtWsaProtocolInfo);
  fr->made = 0;
  if (!(fr->p = malloc(fr->hlen + room))) {
    if (!keep)
      CloseHandle(fr->proc);
    return enomem();
  }
  struct ScmHead *head = (struct ScmHead *)fr->p;
  struct ScmEntry *ents = (struct ScmEntry *)(fr->p + sizeof(*head));
  struct NtWsaProtocolInfo *pinfo =
      (struct NtWsaProtocolInfo *)(fr->p + sizeof(*head) +
                                   n * sizeof(struct ScmEntry));
  memcpy(head->magic, kScmMagic, SCM_MAGIC_LEN);
  head->nfds = n;
  head->datalen = datalen;
  head->srcpid = keep ? GetCurrentProcessId() : 0;
  head->credpid = credpid;
  size_t pk = 0;
  for (; fr->made < n; ++fr->made) {
    struct Fd *g = __get_pib()->fds.p + list[fr->made];
    struct ScmEntry *e = ents + fr->made;
    e->handle = 0;
    if (g->kind == kFdSocket) {
      // hand the socket over the winsock way so WSAPoll() works there
      if (WSADuplicateSocket(g->handle, pid, &pinfo[pk++]) == -1) {
        __winsockerr();
        break;
      }
    }
    if (g->kind != kFdSocket || keep) {
      if (!DuplicateHandle(GetCurrentProcess(), g->handle, fr->proc, &e->handle,
                           0, false, kNtDuplicateSameAccess)) {
        __winerr();
        break;
      }
    }
    e->kind = g->kind;
    e->flags = g->flags;
    e->mode = g->mode;
    e->family = g->family;
    e->type = g->type;
    e->protocol = g->protocol;
    e->evflags = g->evflags;
    e->offset = g->cursor ? g->cursor->shared->pointer : 0;
  }
  if (fr->made < n) {
    int e = errno;
    for (size_t i = 0; i < fr->made; ++i)
      if (ents[i].handle)
        DuplicateHandle(fr->proc, ents[i].handle, 0, 0, 0, false,
                        kNtDuplicateCloseSource);
    if (!keep)
      CloseHandle(fr->proc);
    free(fr->p);
    errno = e;
    return -1;
  }
  return 0;
}

// frees a frame, taking its handles back if it never went out
textwindows static void ScmDone(struct ScmFrame *fr, bool sent) {
  if (!sent) {
    struct ScmEntry *ents =
        (struct ScmEntry *)(fr->p + sizeof(struct ScmHead));
    for (size_t i = 0; i < fr->made; ++i)
      if (ents[i].handle)
        DuplicateHandle(fr->proc, ents[i].handle, 0, 0, 0, false,
                        kNtDuplicateCloseSource);
  }
  if (fr->proc != GetCurrentProcess())
    CloseHandle(fr->proc);
  free(fr->p);
}

/**
 * Sends a message with SCM_RIGHTS attached.
 */
textwindows ssize_t __scm_send_nt(int fd, const struct msghdr *msg, int flags) {
  struct Fd *f = __get_pib()->fds.p + fd;
  int list[SCM_MAX_FD];
  ssize_t n = ScmList(msg, list);
  if (n == -1)
    return -1;
  int32_t credpid = ScmCredPid(f);
  bool seq = f->type == SOCK_SEQPACKET;
  if (!n && !credpid && !seq)
    return __winsock_send_nt(fd, msg->msg_iov, msg->msg_iovlen, flags);
  size_t datalen = 0;
  for (size_t i = 0; i < msg->msg_iovlen; ++i)
    datalen += msg->msg_iov[i].iov_len;
  if (!datalen && !seq)
    return 0;

  uint32_t pid = GetCurrentProcessId(), br;
  if (n && WSAIoctl(f->handle, SIO_AF_UNIX_GETPEERPID, 0, 0, &pid, sizeof(pid),
                    &br, 0, 0) == -1)
    return __winsockerr();

  bool gather = msg->msg_iovlen < 16;
  struct ScmFrame fr;
  if (ScmBuild(&fr, list, n, pid, datalen, gather ? 0 : datalen, credpid) ==
      -1)
    return -1;
  ssize_t rc;
  if (gather) {
    struct iovec iov[16];
    iov[0].iov_base = fr.p;
    iov[0].iov_len = fr.hlen;
    for (size_t i = 0; i < msg->msg_iovlen; ++i)
      iov[i + 1] = msg->msg_iov[i];
    rc = __winsock_send_nt(fd, iov, msg->msg_iovlen + 1, flags);
  } else {
    unsigned char *p = fr.p + fr.hlen;
    for (size_t i = 0; i < msg->msg_iovlen; ++i) {
      memcpy(p, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
      p += msg->msg_iov[i].iov_len;
    }
    rc = __winsock_send_nt(fd, &(struct iovec){fr.p, fr.hlen + datalen}, 1,
                           flags);
  }
  if (rc != -1 && (size_t)rc < fr.hlen) {
    rc = eio();
  } else if (rc != -1) {
    rc -= fr.hlen;
  }
  int e = errno;
  ScmDone(&fr, rc != -1);
  errno = e;
  return rc;
}

// the frame for the descriptors in msg, made out to pid: how many there
// were, 0 leaving fr empty, or -1 w/ errno
textwindows ssize_t __scm_frame_build_nt(struct ScmFrame *fr,
                                         const struct msghdr *msg,
                                         uint32_t pid, size_t datalen) {
  int list[SCM_MAX_FD];
  ssize_t n = ScmList(msg, list);
  if (n <= 0) {
    fr->p = 0;
    fr->hlen = 0;
    return n;
  }
  if (ScmBuild(fr, list, n, pid, datalen, 0, 0) == -1)
    return -1;
  return n;
}

textwindows void __scm_frame_done_nt(struct ScmFrame *fr, bool sent) {
  ScmDone(fr, sent);
}

// a frame at the front of buf: its descriptors are installed on f when
// `install` says so, and its length comes back; -1 when it isn't one
textwindows ssize_t __scm_frame_take_nt(struct Fd *f, const unsigned char *buf,
                                        size_t len, bool install) {
  const struct ScmHead *h = (const struct ScmHead *)buf;
  if (len < sizeof(*h) || memcmp(h->magic, kScmMagic, SCM_MAGIC_LEN) ||
      h->nfds > SCM_MAX_FD)
    return -1;
  const struct ScmEntry *ents = (const struct ScmEntry *)(buf + sizeof(*h));
  size_t hlen = sizeof(*h) + h->nfds * sizeof(struct ScmEntry);
  if (len < hlen)
    return -1;
  size_t nsock = 0;
  for (uint32_t i = 0; i < h->nfds; ++i)
    nsock += ents[i].kind == kFdSocket;
  hlen += nsock * sizeof(struct NtWsaProtocolInfo);
  if (len < hlen)
    return -1;
  if (install)
    ScmInstall(f, h->nfds, ents,
               (const struct NtWsaProtocolInfo *)(buf + sizeof(*h) +
                                                  h->nfds *
                                                      sizeof(struct ScmEntry)),
               h->srcpid, false);
  return hlen;
}

/**
 * Says what linux does to a write on a socketpair end whose peer is
 * gone: ECONNREFUSED for SOCK_DGRAM the first time, which leaves it
 * unconnected, ENOTCONN after that, and EPIPE for SOCK_SEQPACKET. No
 * SIGPIPE either way.
 */
textwindows int __msgpipe_gone_nt(struct Fd *f) {
  if (f->type != SOCK_DGRAM)
    return epipe();
  if (f->peergone)
    return enotconn();
  f->peergone = true;
  return econnrefused();
}

// one message out on a message mode pipe, MSG_DONTWAIT applying to this
// call only
textwindows static ssize_t MsgPipeWrite(int fd, void *p, size_t n, int flags) {
  struct Fd *f = __get_pib()->fds.p + fd;
  sigset_t m = __sig_block();
  ssize_t rc = sys_readwrite_nt_dontwait(fd, p, n, -1, f->handle, m,
                                         (void *)WriteFile,
                                         flags & MSG_DONTWAIT);
  __sig_unblock(m);
  if (rc == -2) {
    switch (GetLastError()) {
      case kNtErrorBrokenPipe:
      case kNtErrorNoData:
        rc = __msgpipe_gone_nt(f);
        break;
      default:
        rc = __winerr();
        break;
    }
  }
  if (rc == -1 && errno == EAGAIN && _weaken(__epoll_rearm_out))
    _weaken(__epoll_rearm_out)(fd);
  return rc;
}

/**
 * Sends one message on a SOCK_DGRAM or SOCK_SEQPACKET socketpair end.
 *
 * The iovecs go out as a single write, since each write is a message
 * of its own on a message mode pipe, with a frame in front when the
 * message carries descriptors. `flags` may have MSG_DONTWAIT and
 * MSG_NOSIGNAL, which changes nothing here; MSG_OOB is EOPNOTSUPP, as
 * on linux. An address is ignored on SOCK_SEQPACKET, while SOCK_DGRAM
 * sends there instead of to the peer, from an unnamed socket.
 */
textwindows ssize_t __scm_msgpipe_send_nt(int fd, const struct msghdr *msg,
                                          int flags) {
  if (flags & MSG_OOB)
    return eopnotsupp();
  struct Fd *f = __get_pib()->fds.p + fd;
  if (msg->msg_name && msg->msg_namelen && f->type == SOCK_DGRAM) {
    int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s == -1)
      return -1;
    ssize_t rc = sendmsg(s, msg, flags);
    int e = errno;
    close(s);
    errno = e;
    return rc;
  }
  int list[SCM_MAX_FD];
  ssize_t n = ScmList(msg, list);
  if (n == -1)
    return -1;
  size_t datalen = 0;
  for (size_t i = 0; i < msg->msg_iovlen; ++i)
    datalen += msg->msg_iov[i].iov_len;
  int32_t credpid = ScmCredPid(f);
  if (!n && datalen && msg->msg_iovlen == 1 && !credpid)
    return MsgPipeWrite(fd, msg->msg_iov[0].iov_base, datalen, flags);
  // an empty message goes out as a bare frame, since PeekNamedPipe() can't
  // tell an empty message from no message
  bool framed = n || !datalen || credpid;
  struct ScmFrame fr = {0};
  if (framed) {
    if (ScmBuild(&fr, list, n, GetCurrentProcessId(), datalen, datalen,
                 credpid) == -1)
      return -1;
  } else if (!(fr.p = malloc(datalen ? datalen : 1))) {
    return enomem();
  }
  unsigned char *p = fr.p + fr.hlen;
  for (size_t i = 0; i < msg->msg_iovlen; ++i) {
    memcpy(p, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
    p += msg->msg_iov[i].iov_len;
  }
  ssize_t rc = MsgPipeWrite(fd, fr.p, fr.hlen + datalen, flags);
  if (rc != -1)
    rc = rc > (ssize_t)fr.hlen ? rc - (ssize_t)fr.hlen : 0;
  int e = errno;
  if (framed) {
    ScmDone(&fr, rc != -1);
  } else {
    free(fr.p);
  }
  errno = e;
  return rc;
}

// copies up to n bytes into the caller's iovecs, returns how many
textwindows static size_t ScmCopyOut(const struct iovec *iov, size_t iovlen,
                                     const unsigned char *p, size_t n) {
  size_t done = 0;
  for (size_t i = 0; i < iovlen && done < n; ++i) {
    size_t k = MIN(iov[i].iov_len, n - done);
    memcpy(iov[i].iov_base, p + done, k);
    done += k;
  }
  return done;
}

// the rest of a message that didn't fit, read and thrown away; returns
// how many bytes that was
textwindows static size_t MsgPipeDrain(int fd, uint64_t waitmask) {
  struct Fd *f = __get_pib()->fds.p + fd;
  char scratch[512];
  size_t n = 0;
  for (;;) {
    ssize_t rc = sys_readwrite_nt_dontwait(fd, scratch, sizeof(scratch), -1,
                                           f->handle, waitmask,
                                           (void *)ReadFile, true);
    if (rc >= 0)
      return n + rc;
    if (rc != -2 || GetLastError() != kNtErrorMoreData)
      return n;
    n += sizeof(scratch);
  }
}

// closes descriptors a message carried that nobody took, as linux does,
// returning whether there were any
textwindows static bool ScmDiscard(struct Fd *f) {
  struct ScmQueue *q = f->scm;
  if (!q || !q->n)
    return false;
  for (int i = 0; i < q->n; ++i)
    close(q->fds[i]);
  q->n = 0;
  return true;
}

/**
 * Receives one message from a SOCK_DGRAM or SOCK_SEQPACKET socketpair
 * end, the way linux does.
 *
 * A message longer than the iovecs is cut short and the rest dropped,
 * with MSG_TRUNC in `msg->msg_flags`. `flags` may have MSG_PEEK, which
 * leaves the message queued and hands out copies of its descriptors,
 * MSG_TRUNC, which returns the full length of the message, and
 * MSG_DONTWAIT. Descriptors go to `msg`'s control buffer, and those that
 * don't fit, or have no `msg` to go to, are closed. With the peer gone
 * and nothing queued, SOCK_SEQPACKET reads end of file while SOCK_DGRAM
 * has nothing to wait for but a signal.
 */
textwindows ssize_t __scm_msgpipe_recv_nt(int fd, const struct iovec *iov,
                                          size_t iovlen, int flags,
                                          struct msghdr *msg, bool cloexec,
                                          uint64_t waitmask) {
  struct Fd *f = __get_pib()->fds.p + fd;
  bool dontwait = (flags & MSG_DONTWAIT) || (f->flags & O_NONBLOCK);
  struct ScmHead head;
  uint32_t got, avail, left;
  for (;;) {
    if (PeekNamedPipe(f->handle, &head, sizeof(head), &got, &avail, &left)) {
      if (avail)
        break;
    } else if (GetLastError() == kNtErrorBrokenPipe) {
      if (f->type != SOCK_DGRAM)
        return 0;
      if (dontwait)
        return eagain();
      for (;;)
        if (ppoll(0, 0, 0, (sigset_t *)&waitmask) == -1)
          return -1;
    } else {
      return __winerr();
    }
    if (dontwait)
      return eagain();
    struct pollfd p = {fd, POLLIN};
    if (ppoll(&p, 1, 0, (sigset_t *)&waitmask) == -1)
      return -1;
  }
  size_t size = (size_t)got + left;
  unsigned char *buf = malloc(size ? size : 1);
  if (!buf)
    return enomem();
  ssize_t rc;
  size_t dropped = 0;
  if (flags & MSG_PEEK) {
    if (!PeekNamedPipe(f->handle, buf, size, &got, 0, 0)) {
      free(buf);
      return __winerr();
    }
    rc = got;
  } else {
    rc = sys_readwrite_nt_dontwait(fd, buf, size, -1, f->handle, waitmask,
                                   (void *)ReadFile, dontwait);
    if (rc == -2) {
      // another reader took the message we sized, and the next is longer
      if (GetLastError() == kNtErrorMoreData) {
        rc = size;
        dropped = MsgPipeDrain(fd, waitmask);
      } else if (GetLastError() == kNtErrorBrokenPipe) {
        free(buf);
        return f->type == SOCK_DGRAM ? eagain() : 0;
      } else {
        free(buf);
        return __winerr();
      }
    } else if (rc < 0) {
      free(buf);
      return rc;
    }
  }
  unsigned char *data = buf;
  size_t datalen = rc;
  ssize_t hlen = __scm_frame_take_nt(f, buf, rc, false);
  struct ScmHead *h = (struct ScmHead *)buf;
  f->credfrom = 0;
  if (hlen != -1 && (size_t)rc - hlen >= h->datalen) {
    f->credfrom = h->credpid;
    struct ScmEntry *ents = (struct ScmEntry *)(buf + sizeof(*h));
    if (h->nfds)
      ScmInstall(f, h->nfds, ents,
                 (struct NtWsaProtocolInfo *)(ents + h->nfds), h->srcpid,
                 flags & MSG_PEEK);
    data = buf + hlen;
    datalen = h->datalen;
  }
  size_t room = 0;
  for (size_t i = 0; i < iovlen; ++i)
    room += iov[i].iov_len;
  size_t copied = ScmCopyOut(iov, iovlen, data, datalen);
  free(buf);
  datalen += dropped;
  if (msg) {
    msg->msg_flags = datalen > room ? MSG_TRUNC : 0;
    if (msg->msg_control) {
      __scm_take_nt(f, msg, cloexec);
    } else {
      msg->msg_controllen = 0;
    }
    if (ScmDiscard(f))
      msg->msg_flags |= MSG_CTRUNC;
  } else {
    ScmDiscard(f);
  }
  return (flags & MSG_TRUNC) ? (ssize_t)datalen : (ssize_t)copied;
}

#define MSGPIPE_BUFSIZE 212992  // linux's default socket buffer
#define SO_PROTOCOL_linux 38
#define SO_DOMAIN_linux   39

/**
 * Answers getsockopt() for a SOCK_DGRAM or SOCK_SEQPACKET socketpair
 * end, which is a named pipe and not a winsock socket.
 */
textwindows int __scm_msgpipe_getsockopt_nt(struct Fd *f, int level,
                                            int optname, void *optval,
                                            uint32_t *optlen) {
  int v;
  if (level != SOL_SOCKET)
    return eopnotsupp();
  switch (optname) {
    case SO_TYPE:
      v = f->type ? f->type : SOCK_DGRAM;
      break;
    case SO_DOMAIN_linux:
      v = AF_UNIX;
      break;
    case SO_PROTOCOL_linux:
    case SO_ERROR:
    case SO_ACCEPTCONN:
      v = 0;
      break;
    case SO_SNDBUF:
    case SO_RCVBUF:
      v = MSGPIPE_BUFSIZE;
      break;
    default:
      return enoprotoopt();
  }
  if (!optval || !optlen)
    return efault();
  uint32_t n = MIN(*optlen, sizeof(v));
  memcpy(optval, &v, n);
  *optlen = n;
  return 0;
}

/**
 * Answers setsockopt() for a SOCK_DGRAM or SOCK_SEQPACKET socketpair
 * end. The buffer sizes are taken and dropped, since the pipe is made
 * with linux's default already and can't be resized.
 */
textwindows int __scm_msgpipe_setsockopt_nt(int level, int optname,
                                            const void *optval,
                                            uint32_t optlen) {
  if (level != SOL_SOCKET)
    return eopnotsupp();
  if (optname != SO_SNDBUF && optname != SO_RCVBUF)
    return enoprotoopt();
  if (optlen < sizeof(int))
    return einval();
  return 0;
}

/**
 * Receives one message from a SOCK_DGRAM or SOCK_SEQPACKET socketpair
 * end for recv(), recvfrom() and recvmsg(), see __scm_msgpipe_recv_nt().
 */
textwindows ssize_t sys_recv_msgpipe_nt(int fd, const struct iovec *iov,
                                        size_t iovlen, int flags,
                                        struct msghdr *msg, bool cloexec) {
  sigset_t m = __sig_block();
  ssize_t rc =
      __scm_msgpipe_recv_nt(fd, iov, iovlen, flags, msg, cloexec, m);
  __sig_unblock(m);
  if ((rc > 0 || (rc == -1 && errno == EAGAIN)) && _weaken(__epoll_rearm_in))
    _weaken(__epoll_rearm_in)(fd, (flags & MSG_PEEK) ? 0 : rc);
  return rc;
}

#endif /* SupportsWindows() */

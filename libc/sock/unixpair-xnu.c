#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/stat.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/fds.h"
#include "libc/macros.h"
#include "libc/str/str.h"
#include "libc/sock/struct/ucred.h"
#include "libc/mem/mem.h"
#include "libc/mem/alloca.h"
#include "libc/sock/internal.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/msghdr.h"
#include "libc/sock/struct/msghdr.internal.h"
#include "libc/sock/struct/pollfd.h"
#include "libc/sock/struct/sockaddr.internal.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/f.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/msg.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/poll.h"
#include "libc/sysv/consts/so.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/errfuns.h"

// AF_UNIX datagram sockets on xnu, made to behave like linux's
//
// - socketpair(SOCK_SEQPACKET) is a datagram pair, since xnu has no
//   SOCK_SEQPACKET for AF_UNIX. its ends are marked in the descriptor
//   table with their inode, which tells a live mark from one left on a
//   number the kernel has since handed to something else
// - buffers start at linux's 212992 bytes, where xnu's 2048 byte send
//   buffer caps a datagram at 2kb
// - a full peer is EAGAIN, or waited out, where xnu says ENOBUFS
// - a gone peer: SOCK_SEQPACKET reads end of file and writes EPIPE,
//   SOCK_DGRAM reads nothing more and writes ECONNREFUSED once, then
//   ENOTCONN, where xnu says ECONNRESET to whichever call comes first
//   and EDESTADDRREQ after
// - MSG_WAITALL is ignored and MSG_TRUNC returns the datagram's length
//
// xnu wakes nobody when a datagram peer goes away, so a blocking read on
// a seqpacket end, and a poll() that has one, wait in slices of up to
// 50ms that look for that
//
// SO_PASSCRED: xnu can't tell a receiver who sent a datagram. a named
// datagram socket of ours with SO_PASSCRED on puts an attribute on the
// file it's bound to; a sender of ours that finds it there puts a head
// with its pid in front of each datagram, and the receiver takes it off
// again. host programs never set the attribute and never see the head.
// a connected socket's sender is the one LOCAL_PEERPID names

#define LINUX_BUFSIZE 212992
#define XNU_SO_NREAD  0x1020
#define SLICE_MS      50

#define XNU_LOCAL_PEERPID   2
#define XNU_XATTR_NOFOLLOW  1
#define CRED_XATTR          "cosmo.passcred"

struct CredHead {
  char magic[16];
  int32_t pid;
  uint32_t reserved[3];
};

static const char kCredMagic[16] = "cosmo-unix-cred";

ssize_t sys_getxattr(const char *, const char *, void *, size_t, uint32_t,
                     int);
int sys_setxattr(const char *, const char *, const void *, size_t, long, int);
int sys_removexattr(const char *, const char *, int);

#define KIND_OTHER     0
#define KIND_DGRAM     1
#define KIND_SEQPACKET 2

static int GetSockInt(int fd, int opt) {
  int v = 0;
  uint32_t n = sizeof(v);
  if (sys_getsockopt(fd, __sol2host(SOL_SOCKET), opt, &v, &n) == -1)
    return -1;
  return v;
}

static int64_t Inode(int fd) {
  struct stat st;
  int e = errno;
  if (fstat(fd, &st) == -1) {
    errno = e;
    return -1;
  }
  return st.st_ino;
}

// whether fd carries a seqpacket mark, without asking the kernel
static bool Marked(int fd) {
  return fd >= 0 && fd < __get_pib()->fds.n &&
         __get_pib()->fds.p[fd].xnupkt;
}

static int Kind(int fd) {
  int e = errno;
  if (Marked(fd)) {
    if (Inode(fd) == __get_pib()->fds.p[fd].xnuino)
      return KIND_SEQPACKET;
    __get_pib()->fds.p[fd].xnupkt = false;
  }
  int kind = KIND_OTHER;
  if (GetSockInt(fd, __sockopt2host(SOL_SOCKET, SO_TYPE)) == SOCK_DGRAM) {
    union sockaddr_storage_bsd ss;
    uint32_t len = sizeof(ss);
    if (__sys_getsockname(fd, &ss, &len) != -1 &&
        ss.sa.sa_family == __af2host(AF_UNIX))
      kind = KIND_DGRAM;
  }
  errno = e;
  return kind;
}

/**
 * Sets up a new AF_UNIX datagram socket on xnu.
 */
void __xnu_unix_setup(int fd, bool seqpacket, bool pair) {
  int v = LINUX_BUFSIZE;
  int e = errno;
  sys_setsockopt(fd, __sol2host(SOL_SOCKET),
                 __sockopt2host(SOL_SOCKET, SO_SNDBUF), &v, sizeof(v));
  sys_setsockopt(fd, __sol2host(SOL_SOCKET),
                 __sockopt2host(SOL_SOCKET, SO_RCVBUF), &v, sizeof(v));
  int64_t ino = Inode(fd);
  errno = e;
  __fds_lock();
  if (__ensurefds_unlocked(fd) != -1) {
    __get_pib()->fds.p[fd].xnupkt = seqpacket && ino != -1;
    __get_pib()->fds.p[fd].xnudgram = !pair && ino != -1;
    __get_pib()->fds.p[fd].xnugone = false;
    __get_pib()->fds.p[fd].xnuino = ino;
  }
  __fds_unlock();
}

/**
 * Returns whether fd is a socketpair(SOCK_SEQPACKET) end on xnu.
 */
bool __xnu_seqpacket(int fd) {
  return Marked(fd) && Kind(fd) == KIND_SEQPACKET;
}

// a datagram socket made by socket(), whose mark is still its own
static bool NamedDgram(int fd) {
  if (fd < 0 || fd >= __get_pib()->fds.n || !__get_pib()->fds.p[fd].xnudgram)
    return false;
  if (Inode(fd) == __get_pib()->fds.p[fd].xnuino)
    return true;
  __get_pib()->fds.p[fd].xnudgram = false;
  return false;
}

// the path in a host AF_UNIX address, false for an unnamed one
static bool SunPath(const void *addr, uint32_t len, char path[105]) {
  const char *p = (const char *)addr + 2;
  if (len <= 2 || !*p)
    return false;
  size_t n = MIN(len - 2, 104);
  memcpy(path, p, n);
  path[n] = 0;
  return true;
}

static bool BoundPath(int fd, bool peer, char path[105]) {
  union sockaddr_storage_bsd ss;
  uint32_t len = sizeof(ss);
  int e = errno;
  bool ok = (peer ? __sys_getpeername(fd, &ss, &len)
                  : __sys_getsockname(fd, &ss, &len)) != -1 &&
            SunPath(&ss, len, path);
  errno = e;
  return ok;
}

/**
 * Says on the file a named datagram socket is bound to whether it wants
 * SO_PASSCRED heads, see above.
 */
void __xnu_unix_passcred(int fd, bool on) {
  char path[105];
  if (!NamedDgram(fd) || !BoundPath(fd, false, path))
    return;
  int e = errno;
  if (on)
    sys_setxattr(path, CRED_XATTR, "1", 1, 0, XNU_XATTR_NOFOLLOW);
  else
    sys_removexattr(path, CRED_XATTR, XNU_XATTR_NOFOLLOW);
  errno = e;
}

// whether the receiver of what `io` sends asked for our pid
static bool CredWanted(int fd, struct XnuIo *io) {
  char path[105];
  struct msghdr *m = io->msg;
  bool named;
  if (io->addrsize && *io->addrsize)
    named = SunPath(io->addr, *io->addrsize, path);
  else if (m && m->msg_name && m->msg_namelen)
    named = SunPath(m->msg_name, m->msg_namelen, path);
  else
    named = BoundPath(fd, true, path);
  if (!named)
    return false;
  int e = errno;
  bool want = sys_getxattr(path, CRED_XATTR, 0, 0, 0, XNU_XATTR_NOFOLLOW) >= 0;
  errno = e;
  return want;
}

// `io` as a host msghdr with `extra` in front of its iovecs, which go
// in `iov`; its iovecs and address stay the caller's
static void CredMsg(struct XnuIo *io, struct iovec *extra, struct iovec *iov,
                    struct msghdr *m) {
  const struct iovec *src;
  int n;
  if (io->msg) {
    *m = *(struct msghdr *)io->msg;
    src = m->msg_iov;
    n = (uint32_t)m->msg_iovlen;
  } else {
    bzero(m, sizeof(*m));
    m->msg_name = io->addr;
    m->msg_namelen = io->addrsize ? *io->addrsize : 0;
    src = io->iov;
    n = io->iovlen;
  }
  iov[0] = *extra;
  memcpy(iov + 1, src, n * sizeof(*iov));
  m->msg_iov = iov;
  m->msg_iovlen = n + 1;
}

static ssize_t XnuCredRecvmsg(struct XnuIo *a, int flags) {
  int hflags = __msg2host(flags);
  if (hflags == -1)
    return einval();
  return sys_recvmsg(a->fd, a->msg, hflags);
}

static ssize_t XnuCredSendmsg(struct XnuIo *a, int flags) {
  int hflags = __msg2host(flags);
  if (hflags == -1)
    return einval();
  return sys_sendmsg(a->fd, a->msg, hflags);
}

/**
 * The sender of what the last receive on fd returned, for SO_PASSCRED:
 * the pid a head had, else the process LOCAL_PEERPID names. 0 if none.
 */
int __xnu_unix_cred(int fd) {
  int pid = 0;
  if (fd >= 0 && fd < __get_pib()->fds.n &&
      (pid = __get_pib()->fds.p[fd].credfrom)) {
    __get_pib()->fds.p[fd].credfrom = 0;
    return pid;
  }
  uint32_t len = sizeof(pid);
  int e = errno;
  if (sys_getsockopt(fd, 0, XNU_LOCAL_PEERPID, &pid, &len) == -1)
    pid = 0;
  errno = e;
  return pid;
}

/**
 * SO_PEERCRED where LOCAL_PEERPID has no answer: nothing more to know.
 */
int __xnu_unix_peer_pid(int fd, struct ucred *c) {
  return 0;
}

// remembers that a datagram socket's peer is gone, which a later send
// reports as ECONNREFUSED
static void SetGone(int fd) {
  int64_t ino = Inode(fd);
  __fds_lock();
  if (ino != -1 && __ensurefds_unlocked(fd) != -1) {
    __get_pib()->fds.p[fd].xnugone = true;
    __get_pib()->fds.p[fd].xnuino = ino;
  }
  __fds_unlock();
}

// takes back what SetGone() left, if it's for this socket
static bool TakeGone(int fd) {
  if (fd < 0 || fd >= __get_pib()->fds.n || !__get_pib()->fds.p[fd].xnugone)
    return false;
  __get_pib()->fds.p[fd].xnugone = false;
  return Inode(fd) == __get_pib()->fds.p[fd].xnuino;
}

// a seqpacket end whose peer is gone, with nothing left to read
static bool SeqpacketEof(int fd) {
  union sockaddr_storage_bsd ss;
  uint32_t len = sizeof(ss);
  int e = errno;
  bool eof = __sys_getpeername(fd, &ss, &len) == -1 && errno == ENOTCONN &&
             !GetSockInt(fd, XNU_SO_NREAD);
  errno = e;
  return eof;
}

static bool NonBlocking(int fd, int flags) {
  if (flags & MSG_DONTWAIT)
    return true;
  int e = errno;
  int fl = fcntl(fd, F_GETFL);
  errno = e;
  return fl != -1 && (fl & O_NONBLOCK);
}

// the receive, see __xnu_unix_recv()
static ssize_t RecvCore(int fd, int flags, ssize_t op(struct XnuIo *, int),
                        struct XnuIo *ctx) {
  int kind = -1;
  int nread = -1;
  if (Marked(fd) && (kind = Kind(fd)) == KIND_SEQPACKET) {
    if (SeqpacketEof(fd))
      return 0;
    if (!NonBlocking(fd, flags)) {
      for (int ms = 1;; ms = MIN(ms * 2, SLICE_MS)) {
        struct pollfd p = {fd, POLLIN};
        int r = poll(&p, 1, ms);
        if (r == -1)
          return -1;
        if (SeqpacketEof(fd))
          return 0;
        if (r)
          break;
      }
    }
  }
  if (flags & (MSG_WAITALL | MSG_TRUNC)) {
    if (kind == -1)
      kind = Kind(fd);
    if (kind != KIND_OTHER) {
      flags &= ~MSG_WAITALL;
      if (flags & MSG_TRUNC) {
        flags &= ~MSG_TRUNC;
        // the datagram has to be there to be measured
        if (!NonBlocking(fd, flags)) {
          struct pollfd p = {fd, POLLIN};
          if (poll(&p, 1, -1) == -1)
            return -1;
        }
        nread = GetSockInt(fd, XNU_SO_NREAD);
      }
    }
  }
  for (int tries = 0;; ++tries) {
    ssize_t rc = op(ctx, flags);
    if (rc != -1)
      return nread > rc ? nread : rc;
    if (errno != ECONNRESET)
      return -1;
    if (kind == -1)
      kind = Kind(fd);
    if (kind == KIND_SEQPACKET)
      return 0;
    if (kind != KIND_DGRAM || tries)
      return -1;
    SetGone(fd);
    // the error was the peer going away, which linux doesn't report on a
    // datagram socket; reading again finds what linux would
  }
}

// the send, see __xnu_unix_send()
static ssize_t SendCore(int fd, int flags, ssize_t op(struct XnuIo *, int),
                        struct XnuIo *ctx) {
  int kind = -1;
  int ms = 1;
  for (;;) {
    ssize_t rc = op(ctx, flags);
    if (rc != -1)
      return rc;
    int e = errno;
    if (e != ENOBUFS && e != EDESTADDRREQ && e != ECONNRESET)
      return -1;
    if (kind == -1)
      kind = Kind(fd);
    if (kind == KIND_OTHER) {
      errno = e;
      return -1;
    }
    if (e == EDESTADDRREQ || e == ECONNRESET) {
      if (kind == KIND_SEQPACKET)
        return epipe();
      // the peer leaving queued ECONNRESET, which goes the first time
      int err = 0;
      uint32_t n = sizeof(err);
      if (e == EDESTADDRREQ)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &n);
      if (TakeGone(fd) || e == ECONNRESET || err == ECONNRESET)
        return econnrefused();
      return enotconn();
    }
    // the peer's queue is full, which xnu reports at once
    if (NonBlocking(fd, flags))
      return eagain();
    if (poll(0, 0, ms) == -1)
      return -1;
    ms = MIN(ms * 2, 10);
  }
}

// a receive on a named datagram socket with SO_PASSCRED on, which takes
// off the head a sender of ours put in front, see the top of this file
static ssize_t CredRecv(int fd, int flags, struct XnuIo *io) {
  struct CredHead head;
  int n = io->msg ? (uint32_t)((struct msghdr *)io->msg)->msg_iovlen
                  : io->iovlen;
  struct iovec *iov = alloca((n + 1) * sizeof(*iov));
  struct msghdr m;
  CredMsg(io, &(struct iovec){&head, sizeof(head)}, iov, &m);
  ssize_t rc = RecvCore(fd, flags, XnuCredRecvmsg,
                        &(struct XnuIo){.fd = fd, .msg = &m});
  if (rc == -1)
    return -1;
  size_t cap = 0;
  for (int i = 1; i <= n; ++i)
    cap += iov[i].iov_len;
  size_t got = MIN((size_t)rc, sizeof(head) + cap);
  if (got >= sizeof(head) && !memcmp(head.magic, kCredMagic, sizeof(kCredMagic))) {
    __get_pib()->fds.p[fd].credfrom = head.pid;
    rc -= sizeof(head);
  } else {
    // not from us: the bytes that went into the head go in front
    char *tmp;
    if (!(tmp = malloc(got ? got : 1)))
      return enomem();
    size_t k = MIN(got, sizeof(head)), at = k;
    memcpy(tmp, &head, k);
    for (int i = 1; i <= n && at < got; ++i) {
      size_t c = MIN(iov[i].iov_len, got - at);
      memcpy(tmp + at, iov[i].iov_base, c);
      at += c;
    }
    size_t out = MIN(got, cap);
    at = 0;
    for (int i = 1; i <= n && at < out; ++i) {
      size_t c = MIN(iov[i].iov_len, out - at);
      memcpy(iov[i].iov_base, tmp + at, c);
      at += c;
    }
    free(tmp);
    if (got > cap)
      m.msg_controllen |= (uint64_t)__msg2host(MSG_TRUNC) << 32;
    if (!(flags & MSG_TRUNC))
      rc = out;
  }
  if (io->msg) {
    struct msghdr *um = io->msg;
    um->msg_namelen = m.msg_namelen;
    um->msg_controllen = m.msg_controllen;
  } else if (io->addrsize) {
    *io->addrsize = m.msg_namelen;
  }
  return rc;
}

/**
 * Does a read or receive on xnu, the way linux would on an AF_UNIX
 * datagram socket. `flags` are linux's MSG_* bits, which `op` turns
 * into the host's.
 */
ssize_t __xnu_unix_recv(int fd, int flags, ssize_t op(struct XnuIo *, int),
                        struct XnuIo *ctx) {
  if (fd >= 0 && fd < __get_pib()->fds.n && __get_pib()->fds.p[fd].passcred) {
    __get_pib()->fds.p[fd].credfrom = 0;
    if (NamedDgram(fd))
      return CredRecv(fd, flags, ctx);
  }
  return RecvCore(fd, flags, op, ctx);
}

/**
 * Does a write or send on xnu, the way linux would on an AF_UNIX
 * datagram socket. `flags` are linux's MSG_* bits, which `op` turns
 * into the host's.
 */
ssize_t __xnu_unix_send(int fd, int flags, ssize_t op(struct XnuIo *, int),
                        struct XnuIo *ctx) {
  if (!NamedDgram(fd) || !CredWanted(fd, ctx))
    return SendCore(fd, flags, op, ctx);
  struct CredHead head = {0};
  memcpy(head.magic, kCredMagic, sizeof(kCredMagic));
  head.pid = getpid();
  int n = ctx->msg ? (uint32_t)((struct msghdr *)ctx->msg)->msg_iovlen
                   : ctx->iovlen;
  struct iovec *iov = alloca((n + 1) * sizeof(*iov));
  struct msghdr m;
  CredMsg(ctx, &(struct iovec){&head, sizeof(head)}, iov, &m);
  ssize_t rc = SendCore(fd, flags, XnuCredSendmsg,
                        &(struct XnuIo){.fd = fd, .msg = &m});
  if (rc != -1)
    rc = rc > (ssize_t)sizeof(head) ? rc - (ssize_t)sizeof(head) : 0;
  return rc;
}

/**
 * Sends to an address on a connected AF_UNIX datagram socket on xnu,
 * which says EISCONN where linux sends there anyway. SOCK_SEQPACKET
 * ignores the address and SOCK_DGRAM sends from an unnamed socket.
 * Returns -2 if fd is neither.
 */
ssize_t __xnu_unix_sendto_connected(int fd, const struct msghdr *msg,
                                    int flags) {
  int kind = Kind(fd);
  if (kind == KIND_SEQPACKET) {
    struct msghdr m = *msg;
    m.msg_name = 0;
    m.msg_namelen = 0;
    return sendmsg(fd, &m, flags);
  }
  if (kind != KIND_DGRAM)
    return -2;
  int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s == -1)
    return -1;
  ssize_t rc = sendmsg(s, msg, flags);
  int e = errno;
  close(s);
  errno = e;
  return rc;
}

/**
 * Returns whether any of fds is a socketpair(SOCK_SEQPACKET) end, for
 * which poll() waits in slices.
 */
bool __xnu_unix_poll_sliced(const struct pollfd *fds, size_t n) {
  for (size_t i = 0; i < n; ++i)
    if (Marked(fds[i].fd) && Kind(fds[i].fd) == KIND_SEQPACKET)
      return true;
  return false;
}

/**
 * Counts the socketpair(SOCK_SEQPACKET) ends among fds whose peer is
 * gone, which linux's poll() reports as a hangup and end of file to
 * read, and with `apply` adds that to their revents.
 */
int __xnu_unix_poll(struct pollfd *fds, size_t n, bool apply) {
  int gone = 0;
  for (size_t i = 0; i < n; ++i) {
    if (!Marked(fds[i].fd) || Kind(fds[i].fd) != KIND_SEQPACKET)
      continue;
    union sockaddr_storage_bsd ss;
    uint32_t len = sizeof(ss);
    int e = errno;
    if (__sys_getpeername(fds[i].fd, &ss, &len) == -1 && errno == ENOTCONN) {
      ++gone;
      if (apply)
        fds[i].revents |= POLLHUP | (fds[i].events & POLLIN);
    }
    errno = e;
  }
  return gone;
}

static ssize_t XnuRecvfrom(struct XnuIo *a, int flags) {
  int hflags = __msg2host(flags);
  if (hflags == -1)
    return einval();
  return sys_recvfrom(a->fd, a->iov[0].iov_base, a->iov[0].iov_len, hflags,
                      a->addr, a->addrsize);
}

static ssize_t XnuSendto(struct XnuIo *a, int flags) {
  int hflags = __msg2host(flags);
  if (hflags == -1)
    return einval();
  return sys_sendto(a->fd, a->iov[0].iov_base, a->iov[0].iov_len, hflags,
                    a->addr, a->addrsize ? *a->addrsize : 0);
}

static ssize_t XnuRecvmsg(struct XnuIo *a, int flags) {
  int hflags = __msg2host(flags);
  if (hflags == -1)
    return einval();
  return sys_recvmsg(a->fd, a->msg, hflags);
}

static ssize_t XnuSendmsg(struct XnuIo *a, int flags) {
  int hflags = __msg2host(flags);
  if (hflags == -1)
    return einval();
  return sys_sendmsg(a->fd, a->msg, hflags);
}

/**
 * Calls the host's recvfrom() on xnu, see __xnu_unix_recv().
 */
ssize_t __xnu_unix_recvfrom(int fd, void *buf, size_t size, int flags,
                            void *addr, uint32_t *addrsize) {
  return __xnu_unix_recv(
      fd, flags, XnuRecvfrom,
      &(struct XnuIo){fd, &(struct iovec){buf, size}, 1, addr, addrsize});
}

/**
 * Calls the host's sendto() on xnu with a host address, see
 * __xnu_unix_send().
 */
ssize_t __xnu_unix_sendto(int fd, const void *buf, size_t size, int flags,
                          const void *addr, uint32_t addrsize) {
  return __xnu_unix_send(fd, flags, XnuSendto,
                         &(struct XnuIo){fd, &(struct iovec){(void *)buf, size},
                                         1, (void *)addr, &addrsize});
}

/**
 * Calls the host's recvmsg() on xnu with a host msghdr, see
 * __xnu_unix_recv().
 */
ssize_t __xnu_unix_recvmsg(int fd, void *msg, int flags) {
  return __xnu_unix_recv(fd, flags, XnuRecvmsg,
                         &(struct XnuIo){.fd = fd, .msg = msg});
}

/**
 * Calls the host's sendmsg() on xnu with a host msghdr, see
 * __xnu_unix_send().
 */
ssize_t __xnu_unix_sendmsg(int fd, const void *msg, int flags) {
  return __xnu_unix_send(fd, flags, XnuSendmsg,
                         &(struct XnuIo){.fd = fd, .msg = (void *)msg});
}

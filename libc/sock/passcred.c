#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/dce.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/weaken.h"
#include "libc/macros.h"
#include "libc/sock/internal.h"
#include "libc/sock/struct/cmsghdr.h"
#include "libc/sock/struct/msghdr.h"
#include "libc/sock/struct/sockaddr.internal.h"
#include "libc/sock/struct/ucred.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/msg.h"
#include "libc/sysv/consts/scm.h"
#include "libc/sysv/consts/so.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

// SO_PASSCRED and SO_PEERCRED off linux. SO_PASSCRED is kept in the
// descriptor table, and a receive on such a unix socket gets an
// SCM_CREDENTIALS message naming the sender, from what the socket code
// of the host knows about it (scmrights-nt.c, unixdgram-nt.c,
// unixpair-xnu.c)

#define XNU_SOL_LOCAL      0
#define XNU_LOCAL_PEERCRED 1
#define XNU_LOCAL_PEERPID  2

struct xucred_xnu {
  uint32_t cr_version;
  uint32_t cr_uid;
  int16_t cr_ngroups;
  uint32_t cr_groups[16];
};

bool __credopt(int level, int optname) {
  return !IsLinux() && level == SOL_SOCKET &&
         (optname == SO_PASSCRED || optname == SO_PEERCRED);
}

// 1 for a unix socket, 0 for another kind, -1 w/ errno for no socket
static int cred_unix(int fd) {
  if (IsWindows()) {
    if (!__isfdopen(fd))
      return ebadf();
    struct Fd *f = __get_pib()->fds.p + fd;
    if (__isfdkind(fd, kFdSocket))
      return f->family == AF_UNIX;
    if (_weaken(__scm_msgpipe_nt) && _weaken(__scm_msgpipe_nt)(f))
      return 1;
    return enotsock();
  }
  union sockaddr_storage_bsd ss;
  uint32_t len = sizeof(ss);
  if (__sys_getsockname(fd, &ss, &len) == -1)
    return -1;
  return ss.sa.sa_family == __af2host(AF_UNIX);
}

int __credopt_set(int fd, int optname, const void *optval, uint32_t optlen) {
  if (optname == SO_PEERCRED)
    return enoprotoopt();
  if (optlen < sizeof(int))
    return einval();
  int u;
  if ((u = cred_unix(fd)) == -1)
    return -1;
  if (!u)
    return eopnotsupp();
  __fds_lock();
  if (__ensurefds_unlocked(fd) == -1) {
    __fds_unlock();
    return -1;
  }
  __get_pib()->fds.p[fd].passcred = !!*(const int *)optval;
  __fds_unlock();
  if (IsXnu() && _weaken(__xnu_unix_passcred))
    _weaken(__xnu_unix_passcred)(fd, !!*(const int *)optval);
  if (IsWindows() && *(const int *)optval && _weaken(__scm_passcred_nt))
    _weaken(__scm_passcred_nt)(__get_pib()->fds.p + fd);
  return 0;
}

// the process at the other end of a connected unix socket, 0 if none
static int cred_peer(int fd, struct ucred *c) {
  if (IsWindows()) {
    struct Fd *f = __get_pib()->fds.p + fd;
    // linux knows the peer of a pair or a connected stream, and of no
    // datagram socket, connected or not
    int pid = 0;
    if (!(__isfdkind(fd, kFdSocket) && __udg_nt(f)) &&
        _weaken(__scm_peer_pid_nt))
      pid = _weaken(__scm_peer_pid_nt)(f);
    if (pid) {
      c->pid = pid;
      c->uid = getuid();
      c->gid = getgid();
    }
    return pid;
  }
  // a datagram socket made by socket(), connected or not, has none
  if (fd < __get_pib()->fds.n && __get_pib()->fds.p[fd].xnudgram)
    return 0;
  int32_t pid = 0;
  uint32_t len = sizeof(pid);
  if (sys_getsockopt(fd, XNU_SOL_LOCAL, XNU_LOCAL_PEERPID, &pid, &len) == -1 ||
      !pid)
    return _weaken(__xnu_unix_peer_pid) ? _weaken(__xnu_unix_peer_pid)(fd, c)
                                        : 0;
  c->pid = pid;
  c->uid = getuid();
  c->gid = getgid();
  // xnu knows the user of a stream peer only
  struct xucred_xnu xu;
  len = sizeof(xu);
  if (sys_getsockopt(fd, XNU_SOL_LOCAL, XNU_LOCAL_PEERCRED, &xu, &len) != -1) {
    c->uid = xu.cr_uid;
    if (xu.cr_ngroups > 0)
      c->gid = xu.cr_groups[0];
  }
  return pid;
}

int __credopt_get(int fd, int optname, void *optval, uint32_t *optlen) {
  if (!optval || !optlen)
    return efault();
  int u;
  if ((u = cred_unix(fd)) == -1)
    return -1;
  if (optname == SO_PASSCRED) {
    if (!u)
      return eopnotsupp();
    int v = fd < __get_pib()->fds.n && __get_pib()->fds.p[fd].passcred;
    uint32_t n = MIN(*optlen, sizeof(v));
    memcpy(optval, &v, n);
    *optlen = n;
    return 0;
  }
  struct ucred c = {0, -1, -1};
  if (u)
    cred_peer(fd, &c);
  uint32_t n = MIN(*optlen, sizeof(c));
  memcpy(optval, &c, n);
  *optlen = n;
  return 0;
}

/**
 * Puts an SCM_CREDENTIALS message naming `pid` at the front of the
 * control buffer of `msg`, returning the bytes it takes, or 0 with
 * MSG_CTRUNC when it doesn't fit.
 */
size_t __cred_cmsg(struct msghdr *msg, int pid) {
  if (!msg->msg_control ||
      msg->msg_controllen < CMSG_LEN(sizeof(struct ucred))) {
    msg->msg_flags |= MSG_CTRUNC;
    return 0;
  }
  struct cmsghdr *c = msg->msg_control;
  c->cmsg_len = CMSG_LEN(sizeof(struct ucred));
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_CREDENTIALS;
  struct ucred u = {pid, getuid(), getgid()};
  memcpy(CMSG_DATA(c), &u, sizeof(u));
  return MIN(CMSG_SPACE(sizeof(u)), msg->msg_controllen);
}

/**
 * Puts an SCM_CREDENTIALS message naming `pid` in front of what a host
 * receive left in the control buffer of `msg`, which has room for `cap`
 * bytes. Messages that no longer fit are dropped with MSG_CTRUNC, and
 * the descriptors they carried closed.
 */
void __cred_prepend(struct msghdr *msg, size_t cap, int pid) {
  size_t need = CMSG_SPACE(sizeof(struct ucred));
  size_t used = msg->msg_control ? msg->msg_controllen : 0;
  if (used && used + need > cap) {
    for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c))
      if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
        for (int *p = (int *)CMSG_DATA(c);
             (char *)(p + 1) <= (char *)c + c->cmsg_len; ++p)
          close(*p);
    msg->msg_flags |= MSG_CTRUNC;
    used = 0;
  }
  if (used)
    memmove((char *)msg->msg_control + need, msg->msg_control, used);
  msg->msg_controllen = cap;
  size_t got = __cred_cmsg(msg, pid);
  msg->msg_controllen = got ? got + used : used;
}

/**
 * Checks an SCM_CREDENTIALS message a sender put in, where linux lets a
 * process name nobody but itself.
 */
int __cred_check(const struct cmsghdr *c) {
  if (c->cmsg_len < CMSG_LEN(sizeof(struct ucred)))
    return einval();
  struct ucred u;
  memcpy(&u, CMSG_DATA(c), sizeof(u));
  if (u.pid != getpid() || (u.uid != getuid() && u.uid != geteuid()) ||
      (u.gid != getgid() && u.gid != getegid()))
    return eperm();
  return 0;
}

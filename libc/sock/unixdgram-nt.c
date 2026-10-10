#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/iovec.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/fds.h"
#include "libc/limits.h"
#include "libc/macros.h"
#include "libc/mem/mem.h"
#include "libc/nt/createfile.h"
#include "libc/nt/dll.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/enum/fsctl.h"
#include "libc/nt/enum/io.h"
#include "libc/nt/enum/wait.h"
#include "libc/nt/errors.h"
#include "libc/nt/files.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/synchronization.h"
#include "libc/nt/systeminfo.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/nt/winsock.h"
#include "libc/sock/internal.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/msghdr.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/msg.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/consts/sol.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/cosmotime.h"

/**
 * @fileoverview AF_UNIX SOCK_DGRAM on Windows.
 *
 * Winsock's AF_UNIX is stream only, so a datagram socket is a UDP socket
 * on the loopback interface. bind(path) leaves a file at the path with
 * the same reparse tag winsock puts on its own socket files, so stat()
 * calls it a socket; the port and the binder's pid are in the reparse
 * data. sendto(path) reads that back, and each datagram goes out with a
 * header naming the sender's own path, which is how recvfrom() can say
 * where it came from. SCM_RIGHTS rides along as the frame the stream and
 * socketpair code uses, made out to the pid the record names, or to
 * whoever holds the port when that process has gone (the daemon that
 * forked after binding).
 *
 * The file stays after close(), as on Linux; a later bind() to the same
 * path is EADDRINUSE until it's unlinked. Where Linux blocks a sender
 * when the receiver's queue is full, UDP drops, so the receive buffer is
 * made large.
 */

#if SupportsWindows()

#define UDG_PATH_MAX 108
#define UDG_MAX_DGRAM 65507
#define UDG_CACHE_MS  1000

#define UDG_SCM 1  // head.flags: an SCM_RIGHTS frame follows the name

__msabi extern typeof(__sys_bind_nt) *const __imp_bind;
__msabi extern typeof(__sys_getsockname_nt) *const __imp_getsockname;
__msabi extern typeof(__sys_setsockopt_nt) *const __imp_setsockopt;
__msabi extern typeof(__sys_closesocket_nt) *const __imp_closesocket;

__HOSTCONST(int, SOL_SOCKET);
__HOSTCONST(int, SO_RCVBUF);

// in the reparse data of the file bind() leaves behind
struct UdgRecord {
  char magic[16];
  uint32_t pid;
  uint16_t port;
  uint16_t pad;
};

// the REPARSE_DATA_BUFFER that carries it: tag, length, then the data
struct UdgReparse {
  uint32_t tag;
  uint16_t len;
  uint16_t reserved;
  struct UdgRecord rec;
};

// in front of every datagram, then srclen bytes of the sender's name
struct UdgHead {
  char magic[8];
  uint32_t srcpid;
  uint16_t srclen;
  uint8_t flags;
  uint8_t pad;
};

struct UnixDgram {
  int refs;
  uint16_t port;
  uint16_t boundlen;
  uint16_t peerlen;
  uint32_t peerpid;
  char bound[UDG_PATH_MAX];
  char peer[UDG_PATH_MAX];
  // the destination last looked up
  uint16_t cachelen, cacheport;
  uint32_t cachepid;
  int64_t cachewhen;
  char cache[UDG_PATH_MAX];
};

static const char kUdgMagic[8] = "cosmoUDG";
static const char kUdgRecord[16] = "cosmo-unix-dgram";

textwindows bool __udg_nt(const struct Fd *f) {
  return f->kind == kFdSocket && f->udg;
}

// the path bytes of an AF_UNIX address: a filesystem path ends at its
// first NUL, an abstract name (leading NUL) is taken whole
textwindows static int udg_parse(const void *addr, uint32_t addrsize,
                                 char out[UDG_PATH_MAX], uint16_t *outlen) {
  const struct sockaddr_un *sun = addr;
  if (!addr || addrsize < sizeof(sun->sun_family))
    return einval();
  if (sun->sun_family != AF_UNIX)
    return eafnosupport();
  size_t n = addrsize - offsetof(struct sockaddr_un, sun_path);
  if (n > UDG_PATH_MAX)
    n = UDG_PATH_MAX;
  if (n && sun->sun_path[0])
    n = strnlen(sun->sun_path, n);
  memcpy(out, sun->sun_path, n);
  *outlen = n;
  return 0;
}

// where the record for a name lives: the path itself, or for an abstract
// name a file named by the bytes under the temp directory
textwindows static int udg_record_path(const char *name, uint16_t len,
                                       char16_t path[PATH_MAX]) {
  if (!len)
    return einval();
  if (name[0]) {
    char tmp[UDG_PATH_MAX + 1];
    memcpy(tmp, name, len);
    tmp[len] = 0;
    return __mkntpath(tmp, path);
  }
  uint32_t n = GetTempPath(PATH_MAX, path);
  if (!n || n + 32 + len * 2 + 8 >= PATH_MAX)
    return enametoolong();
  static const char16_t dir[] = u"cosmo-unix-dgram";
  memcpy(path + n, dir, sizeof(dir));
  n += sizeof(dir) / sizeof(dir[0]) - 1;
  CreateDirectory(path, 0);
  path[n++] = '\\';
  for (int i = 1; i < len; ++i) {
    path[n++] = "0123456789abcdef"[(name[i] >> 4) & 15];
    path[n++] = "0123456789abcdef"[name[i] & 15];
  }
  path[n] = 0;
  return 0;
}

textwindows static int udg_record_write(const char16_t *path, uint16_t port) {
  int64_t h = CreateFile(path, kNtGenericRead | kNtGenericWrite, 0, 0,
                         kNtCreateNew,
                         kNtFileAttributeNormal | kNtFileFlagOpenReparsePoint,
                         0);
  if (h == -1) {
    switch (GetLastError()) {
      case kNtErrorFileExists:
      case kNtErrorAlreadyExists:
        return eaddrinuse();
      default:
        return __winerr();
    }
  }
  struct UdgReparse rd;
  bzero(&rd, sizeof(rd));
  rd.tag = kNtIoReparseTagAfUnix;
  rd.len = sizeof(rd.rec);
  memcpy(rd.rec.magic, kUdgRecord, sizeof(kUdgRecord));
  rd.rec.pid = GetCurrentProcessId();
  rd.rec.port = port;
  uint32_t br;
  bool ok = DeviceIoControl(h, kNtFsctlSetReparsePoint, &rd, sizeof(rd), 0, 0,
                            &br, 0);
  int e = ok ? 0 : __winerr();
  CloseHandle(h);
  if (!ok) {
    DeleteFile(path);
    return e;
  }
  return 0;
}

// what's bound at a path: ENOENT when nothing is there, ECONNREFUSED
// when the file isn't one of ours
textwindows static int udg_record_read(const char16_t *path, uint16_t *port,
                                       uint32_t *pid) {
  int64_t h = CreateFile(
      path, kNtGenericRead,
      kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete, 0,
      kNtOpenExisting,
      kNtFileFlagOpenReparsePoint | kNtFileFlagBackupSemantics, 0);
  if (h == -1)
    return __winerr();
  struct {
    struct UdgReparse rd;
    char slack[64];
  } buf;
  struct UdgReparse *rd = &buf.rd;
  uint32_t br;
  bool ok = DeviceIoControl(h, kNtFsctlGetReparsePoint, 0, 0, &buf, sizeof(buf),
                            &br, 0);
  CloseHandle(h);
  if (!ok || rd->tag != kNtIoReparseTagAfUnix || rd->len < sizeof(rd->rec) ||
      memcmp(rd->rec.magic, kUdgRecord, sizeof(kUdgRecord)))
    return econnrefused();
  *port = rd->rec.port;
  *pid = rd->rec.pid;
  return 0;
}

textwindows static bool udg_pid_alive(uint32_t pid) {
  if (pid == GetCurrentProcessId())
    return true;
  int64_t h = OpenProcess(kNtSynchronize, false, pid);
  if (!h)
    return GetLastError() == kNtErrorAccessDenied;  // there, not ours to ask
  bool alive = WaitForSingleObject(h, 0) == kNtWaitTimeout;
  CloseHandle(h);
  return alive;
}

struct NtUdpRowOwnerPid {
  uint32_t dwLocalAddr;
  uint32_t dwLocalPort;  // network order in the low 16 bits
  uint32_t dwOwningPid;
};

// who holds a loopback UDP port, 0 when nobody, -1 when the system can't
// say: the binder may have forked and gone, leaving the socket to a
// child the record can't name, or closed it, which linux refuses with
// ECONNREFUSED and UDP would carry to nobody
textwindows static int64_t udg_port_owner(uint16_t port) {
  typedef uint32_t(__msabi * GetExtendedUdpTableF)(void *, uint32_t *, bool32,
                                                   uint32_t, int, uint32_t);
  static GetExtendedUdpTableF get;
  if (!get) {
    int64_t dll = LoadLibrary(u"iphlpapi.dll");
    if (dll)
      get = (GetExtendedUdpTableF)GetProcAddress(dll, "GetExtendedUdpTable");
    if (!get)
      return -1;
  }
  uint32_t size = 0;
  get(0, &size, false, 2 /* AF_INET */, 1 /* UDP_TABLE_OWNER_PID */, 0);
  if (!size)
    return -1;
  char *buf = malloc(size);
  if (!buf)
    return -1;
  int64_t owner = 0;
  if (!get(buf, &size, false, 2, 1, 0)) {
    uint32_t n = *(uint32_t *)buf;
    struct NtUdpRowOwnerPid *row = (struct NtUdpRowOwnerPid *)(buf + 4);
    for (uint32_t i = 0; i < n; ++i)
      if ((uint16_t)row[i].dwLocalPort == htons(port) &&
          (row[i].dwLocalAddr == htonl(0x7f000001) ||
           row[i].dwLocalAddr == 0)) {
        owner = row[i].dwOwningPid;
        break;
      }
  }
  free(buf);
  return owner;
}

// the port and pid behind a name, remembered for a moment since a
// program tends to keep talking to the same socket
textwindows static int udg_resolve(struct UnixDgram *u, const char *name,
                                   uint16_t len, uint16_t *port,
                                   uint32_t *pid) {
  int64_t now = timespec_tomillis(timespec_mono());
  if (u->cachelen == len && !memcmp(u->cache, name, len) &&
      now - u->cachewhen < UDG_CACHE_MS) {
    *port = u->cacheport;
    *pid = u->cachepid;
    return 0;
  }
  char16_t path[PATH_MAX];
  if (udg_record_path(name, len, path) == -1)
    return -1;
  if (udg_record_read(path, port, pid) == -1)
    return -1;
  int64_t owner = udg_port_owner(*port);
  if (!owner)
    return econnrefused();
  if (owner > 0) {
    *pid = owner;
  } else if (!udg_pid_alive(*pid)) {
    return econnrefused();
  }
  u->cachelen = len;
  memcpy(u->cache, name, len);
  u->cacheport = *port;
  u->cachepid = *pid;
  u->cachewhen = now;
  return 0;
}

textwindows static void udg_loopback(struct sockaddr_in *sin, uint16_t port) {
  bzero(sin, sizeof(*sin));
  sin->sin_family = AF_INET;
  sin->sin_port = htons(port);
  sin->sin_addr.s_addr = htonl(0x7f000001);
}

/**
 * Makes the UDP socket that stands in for an AF_UNIX datagram socket.
 * The slot `fd` is reserved by the caller; returns fd or -1 w/ errno.
 */
textwindows int __udg_socket_nt(int fd, int type, int protocol) {
  struct UnixDgram *u = calloc(1, sizeof(*u));
  if (!u)
    return -1;
  int64_t h = WSASocket(AF_INET, SOCK_DGRAM, 17 /* IPPROTO_UDP */, 0, 0,
                        kNtWsaFlagOverlapped);
  if (h == -1) {
    free(u);
    return __winsockerr();
  }
  struct sockaddr_in sin;
  udg_loopback(&sin, 0);
  uint32_t len = sizeof(sin);
  if (__imp_bind(h, &sin, sizeof(sin)) == -1 ||
      __imp_getsockname(h, &sin, &len) == -1) {
    int rc = __winsockerr();
    __imp_closesocket(h);
    free(u);
    return rc;
  }
  int rcvbuf = 4 * 1024 * 1024;
  __imp_setsockopt(h, __host_SOL_SOCKET, __host_SO_RCVBUF, &rcvbuf,
                   sizeof(rcvbuf));
  __winsock_udp_connreset(h, false);
  u->refs = 1;
  u->port = ntohs(sin.sin_port);
  struct Fd *f = __get_pib()->fds.p + fd;
  f->family = AF_UNIX;
  f->type = SOCK_DGRAM;
  f->protocol = protocol;
  f->flags = O_RDWR | ((type & SOCK_CLOEXEC) ? O_CLOEXEC : 0) |
             ((type & SOCK_NONBLOCK) ? O_NONBLOCK : 0);
  f->mode = 0140666;
  f->handle = h;
  f->isbound = true;  // the UDP socket is; the name comes with bind()
  f->was_created_during_vfork = __vforked;
  f->udg = u;
  f->kind = kFdSocket;
  return fd;
}

textwindows int __udg_bind_nt(struct Fd *f, const void *addr,
                              uint32_t addrsize) {
  struct UnixDgram *u = f->udg;
  char name[UDG_PATH_MAX];
  uint16_t len;
  if (udg_parse(addr, addrsize, name, &len) == -1)
    return -1;
  if (u->boundlen)
    return einval();
  if (!len)
    return 0;  // linux would make up an abstract name; we stay unnamed
  char16_t path[PATH_MAX];
  if (udg_record_path(name, len, path) == -1)
    return -1;
  if (udg_record_write(path, u->port) == -1) {
    // an abstract name dies with its socket on linux, so one left by a
    // socket that's gone gives way; a path stays taken until unlinked
    uint16_t port;
    uint32_t pid;
    if (name[0] || errno != EADDRINUSE ||
        udg_record_read(path, &port, &pid) == -1 || udg_port_owner(port) ||
        !DeleteFile(path) || udg_record_write(path, u->port) == -1)
      return -1;
  }
  memcpy(u->bound, name, len);
  u->boundlen = len;
  return 0;
}

textwindows int __udg_connect_nt(struct Fd *f, const void *addr,
                                 uint32_t addrsize) {
  struct UnixDgram *u = f->udg;
  struct sockaddr_in sin;
  if (addrsize >= sizeof(uint16_t) &&
      ((const struct sockaddr *)addr)->sa_family == AF_UNSPEC) {
    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    if (WSAConnect(f->handle, (struct sockaddr *)&sin, sizeof(sin), 0, 0, 0,
                   0))
      return __winsockerr();
    __winsock_udp_connreset(f->handle, false);
    u->peerlen = 0;
    u->peerpid = 0;
    f->connecting = 0;
    return 0;
  }
  char name[UDG_PATH_MAX];
  uint16_t len, port;
  uint32_t pid;
  if (udg_parse(addr, addrsize, name, &len) == -1)
    return -1;
  if (!len)
    return einval();
  if (udg_resolve(u, name, len, &port, &pid) == -1)
    return -1;
  udg_loopback(&sin, port);
  if (WSAConnect(f->handle, (struct sockaddr *)&sin, sizeof(sin), 0, 0, 0, 0))
    return __winsockerr();
  __winsock_udp_connreset(f->handle, true);
  memcpy(u->peer, name, len);
  u->peerlen = len;
  u->peerpid = pid;
  f->connecting = 2;
  return 0;
}

/**
 * Sends one datagram; `msg` is the sendmsg() header when there is one,
 * for the descriptors it may carry. Returns the data bytes sent.
 */
textwindows ssize_t __udg_sendto_nt(int fd, const struct iovec *iov,
                                    size_t iovlen, int flags,
                                    const void *addr, uint32_t addrsize,
                                    const struct msghdr *msg) {
  struct Fd *f = __get_pib()->fds.p + fd;
  struct UnixDgram *u = f->udg;
  struct sockaddr_in sin;
  const void *ntaddr = 0;
  uint32_t ntaddrsize = 0;
  uint32_t pid = u->peerpid;
  if (addr && addrsize) {
    char name[UDG_PATH_MAX];
    uint16_t len, port;
    if (udg_parse(addr, addrsize, name, &len) == -1)
      return -1;
    if (!len)
      return einval();
    if (udg_resolve(u, name, len, &port, &pid) == -1)
      return -1;
    udg_loopback(&sin, port);
    ntaddr = &sin;
    ntaddrsize = sizeof(sin);
  } else if (!u->peerlen) {
    return edestaddrreq();
  }
  size_t datalen = 0;
  for (size_t i = 0; i < iovlen; ++i)
    datalen += iov[i].iov_len;
  struct ScmFrame fr = {0};
  ssize_t nfds = 0;
  if (msg && (nfds = __scm_frame_build_nt(&fr, msg, pid, datalen)) == -1)
    return -1;
  size_t hlen = sizeof(struct UdgHead) + u->boundlen + fr.hlen;
  if (hlen + datalen > UDG_MAX_DGRAM) {
    if (nfds)
      __scm_frame_done_nt(&fr, false);
    return emsgsize();
  }
  unsigned char *buf = malloc(hlen + datalen);
  if (!buf) {
    if (nfds)
      __scm_frame_done_nt(&fr, false);
    return enomem();
  }
  struct UdgHead *head = (struct UdgHead *)buf;
  memcpy(head->magic, kUdgMagic, sizeof(kUdgMagic));
  head->srcpid = GetCurrentProcessId();
  head->srclen = u->boundlen;
  head->flags = nfds ? UDG_SCM : 0;
  head->pad = 0;
  unsigned char *p = buf + sizeof(*head);
  memcpy(p, u->bound, u->boundlen);
  p += u->boundlen;
  if (nfds) {
    memcpy(p, fr.p, fr.hlen);
    p += fr.hlen;
  }
  for (size_t i = 0; i < iovlen; ++i) {
    memcpy(p, iov[i].iov_base, iov[i].iov_len);
    p += iov[i].iov_len;
  }
  ssize_t rc = __winsock_sendto_nt(fd, &(struct iovec){buf, hlen + datalen}, 1,
                                   flags, ntaddr, ntaddrsize, 0, 0);
  int e = errno;
  free(buf);
  if (nfds)
    __scm_frame_done_nt(&fr, rc != -1);
  errno = e;
  if (rc == -1)
    return -1;
  return rc >= (ssize_t)hlen ? rc - hlen : 0;
}

textwindows static size_t udg_copy_out(const struct iovec *iov, size_t iovlen,
                                       const unsigned char *p, size_t n) {
  size_t done = 0;
  for (size_t i = 0; i < iovlen && done < n; ++i) {
    size_t k = MIN(iov[i].iov_len, n - done);
    memcpy(iov[i].iov_base, p + done, k);
    done += k;
  }
  return done;
}

/**
 * Receives one datagram into the caller's iovecs, naming the sender in
 * `addr` as an AF_UNIX address. Returns the bytes copied; `*truncated`
 * says when the datagram had more.
 */
textwindows ssize_t __udg_recv_nt(int fd, const struct iovec *iov,
                                  size_t iovlen, int flags, void *addr,
                                  uint32_t *addrsize, bool *truncated) {
  struct Fd *f = __get_pib()->fds.p + fd;
  unsigned char *buf = malloc(65536);
  if (!buf)
    return enomem();
  uint32_t hostflags = flags & ~MSG_WAITALL;
  for (;;) {
    struct sockaddr_in sin;
    uint32_t sinlen = sizeof(sin);
    ssize_t rc = __winsock_recvfrom_nt(fd, &(struct iovec){buf, 65536}, 1,
                                       hostflags, &sin, &sinlen, 0);
    if (rc == -1) {
      int e = errno;
      free(buf);
      errno = e;
      return -1;
    }
    struct UdgHead *head = (struct UdgHead *)buf;
    bool ours = sinlen >= sizeof(sin) && sin.sin_family == AF_INET &&
                sin.sin_addr.s_addr == htonl(0x7f000001) &&
                (size_t)rc >= sizeof(*head) &&
                !memcmp(head->magic, kUdgMagic, sizeof(kUdgMagic)) &&
                head->srclen <= UDG_PATH_MAX &&
                sizeof(*head) + head->srclen <= (size_t)rc;
    if (!ours) {
      // not from one of us: thrown away, which a peek has to do itself
      if (flags & MSG_PEEK)
        __winsock_recvfrom_nt(fd, &(struct iovec){buf, 65536}, 1,
                              hostflags & ~MSG_PEEK, 0, 0, 0);
      continue;
    }
    const unsigned char *p = buf + sizeof(*head);
    const unsigned char *src = p;
    p += head->srclen;
    if (head->flags & UDG_SCM) {
      ssize_t hlen =
          __scm_frame_take_nt(f, p, rc - (p - buf), !(flags & MSG_PEEK));
      if (hlen == -1) {
        if (flags & MSG_PEEK)
          __winsock_recvfrom_nt(fd, &(struct iovec){buf, 65536}, 1,
                                hostflags & ~MSG_PEEK, 0, 0, 0);
        continue;
      }
      p += hlen;
    }
    size_t datalen = rc - (p - buf);
    size_t got = udg_copy_out(iov, iovlen, p, datalen);
    if (truncated)
      *truncated = got < datalen;
    if (addr && addrsize) {
      // an unnamed sender is a zero length address, as linux has it
      struct sockaddr_un sun;
      bzero(&sun, sizeof(sun));
      sun.sun_family = AF_UNIX;
      memcpy(sun.sun_path, src, head->srclen);
      uint32_t outlen =
          head->srclen ? offsetof(struct sockaddr_un, sun_path) + head->srclen
                       : 0;
      uint32_t copy = MIN(*addrsize, outlen);
      if (copy)
        memcpy(addr, &sun, copy);
      *addrsize = outlen;
    }
    free(buf);
    return got;
  }
}

textwindows ssize_t __udg_recvmsg_nt(int fd, struct msghdr *msg, int flags,
                                     bool cloexec) {
  bool truncated = false;
  ssize_t rc = __udg_recv_nt(fd, msg->msg_iov, msg->msg_iovlen, flags,
                             msg->msg_name,
                             msg->msg_name ? &msg->msg_namelen : 0, &truncated);
  if (rc == -1)
    return -1;
  msg->msg_flags = truncated ? MSG_TRUNC : 0;
  if (msg->msg_control) {
    __scm_take_nt(__get_pib()->fds.p + fd, msg, cloexec);
  } else {
    msg->msg_controllen = 0;
  }
  return rc;
}

textwindows int __udg_getname_nt(struct Fd *f, bool peer,
                                 struct sockaddr_storage *ss, uint32_t *size) {
  struct UnixDgram *u = f->udg;
  struct sockaddr_un *sun = (struct sockaddr_un *)ss;
  uint16_t len = peer ? u->peerlen : u->boundlen;
  if (peer && !len)
    return enotconn();
  bzero(ss, sizeof(*ss));
  sun->sun_family = AF_UNIX;
  memcpy(sun->sun_path, peer ? u->peer : u->bound, len);
  *size = offsetof(struct sockaddr_un, sun_path) + len;
  return 0;
}

textwindows void __udg_ref_nt(struct Fd *f) {
  struct UnixDgram *u = f->udg;
  if (u)
    ++u->refs;
}

textwindows void __udg_close_nt(struct Fd *f) {
  struct UnixDgram *u = f->udg;
  if (!u)
    return;
  f->udg = 0;
  if (!--u->refs)
    free(u);
}

#endif /* __x86_64__ */

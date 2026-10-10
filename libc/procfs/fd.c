#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/nt/files.h"
#include "libc/procfs/internal.h"
#include "libc/procfs/xnu.internal.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/sock/struct/sockaddr6.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/consts/f.h"

// /proc/self/fd, read out of cosmo's own descriptor table. For any other
// process only the socket tables say what it holds, but for ourselves
// __get_pib()->fds knows every descriptor, its kind, and its NT handle -- so
// the entries here carry the real fd numbers and cover files, pipes and
// devices, not just sockets. A socket's inode is computed from the same
// identity the table rows hash, so following a socket:[N] link from here lands
// on the right row of /proc/net/tcp.

// The identity the socket tables hash, taken from the descriptor itself.
// An unconnected or unbound end reads as zeros, which is also how the
// tables report it.

static void socket_text(int fd, const struct Fd *f, char *out, size_t n) {
  uint8_t laddr[16] = {0}, raddr[16] = {0};
  uint16_t lport = 0, rport = 0;
  uint8_t family = f->family == AF_INET6 ? 6 : 4;
  uint8_t proto = f->type == SOCK_DGRAM ? 1 : 0;

  struct sockaddr_storage ss;
  uint32_t sl = sizeof ss;
  if (!getsockname(fd, (struct sockaddr *)&ss, &sl)) {
    if (ss.ss_family == AF_INET) {
      struct sockaddr_in *a = (struct sockaddr_in *)&ss;
      memcpy(laddr, &a->sin_addr, 4);
      lport = ntohs(a->sin_port);
    } else if (ss.ss_family == AF_INET6) {
      struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
      memcpy(laddr, &a->sin6_addr, 16);
      lport = ntohs(a->sin6_port);
    }
  }
  sl = sizeof ss;
  if (!getpeername(fd, (struct sockaddr *)&ss, &sl)) {
    if (ss.ss_family == AF_INET) {
      struct sockaddr_in *a = (struct sockaddr_in *)&ss;
      memcpy(raddr, &a->sin_addr, 4);
      rport = ntohs(a->sin_port);
    } else if (ss.ss_family == AF_INET6) {
      struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
      memcpy(raddr, &a->sin6_addr, 16);
      rport = ntohs(a->sin6_port);
    }
  }
  uint64_t inode =
      pfs_net_inode(proto, family, pfs_self_pid(), lport, rport, laddr, raddr);
  snprintf(out, n, "socket:[%llu]", (unsigned long long)inode);
}

// A file descriptor's path, when NT will name it. Anonymous pipes and other
// unnameable handles read as pipe:[hash] -- the number only needs to be
// stable and distinct, the way Linux's anonymous inode numbers are.
static void file_text(const struct Fd *f, char *out, size_t n) {
  char16_t w[512];
  uint32_t len = GetFinalPathNameByHandle(f->handle, w, 512, 0);
  if (len && len < 512) {
    // cosmo's own spelling of the path, the one getcwd() and
    // GetProgramExecutableName() use; heap, since the calling thread
    // may have a small stack
    char *u8 = malloc(PATH_MAX);
    int m = u8 ? __mkunixpath(w, u8) : -1;
    if (m >= 0) {
      if ((size_t)m + 1 > n)
        m = (int)n - 1;
      memcpy(out, u8, (size_t)m);
      out[m] = 0;
    } else {
      size_t k = 0;
      for (uint32_t i = 0; i < len && k < n - 1; i++)
        out[k++] = w[i] == '\\' ? '/' : (w[i] < 128 ? (char)w[i] : '_');
      out[k] = 0;
    }
    free(u8);
    return;
  }
  uint64_t h = 0xcbf29ce484222325ull;
  for (int i = 0; i < 8; i++) {
    h ^= (uint8_t)(f->handle >> (i * 8));
    h *= 0x100000001b3ull;
  }
  snprintf(out, n, "pipe:[%llu]", (unsigned long long)(h & 0xffffffffffull));
}

int pfs_self_fds(struct pfs_fdent **out) {
  *out = 0;
  if (IsXnuSilicon()) {
    // the kernel names the descriptor a /proc handle sits on (a dup of
    // stderr); the table knows what it stands for
    int n = pfs_xnu_fds_of(pfs_self_pid(), out);
    for (int i = 0; i < n; i++)
      if (__isfdkind((*out)[i].fd, kFdProc))
        pc_fd_vpath((*out)[i].fd, (*out)[i].text, sizeof (*out)[i].text);
    return n;
  }
  if (!IsWindows())
    return 0;
  int nfds = (int)__get_pib()->fds.n;
  struct pfs_fdent *ents = malloc((nfds ? nfds : 1) * sizeof *ents);
  if (!ents)
    return 0;
  int n = 0;
  for (int fd = 0; fd < nfds; fd++) {
    const struct Fd *f = &__get_pib()->fds.p[fd];
    struct pfs_fdent *e = &ents[n];
    switch (f->kind) {
      case kFdFile:
        file_text(f, e->text, sizeof e->text);
        break;
      case kFdSocket:
        socket_text(fd, f, e->text, sizeof e->text);
        break;
      case kFdConsole:
      case kFdSerial:
        snprintf(e->text, sizeof e->text, "/dev/tty");
        break;
      case kFdDevNull:
        snprintf(e->text, sizeof e->text, "/dev/null");
        break;
      case kFdDevRandom:
        snprintf(e->text, sizeof e->text, "/dev/urandom");
        break;
      case kFdZip:
        snprintf(e->text, sizeof e->text, "/zip");
        break;
      case kFdProc:
        pc_fd_vpath(fd, e->text, sizeof e->text);
        break;
      case kFdEvent:
        snprintf(e->text, sizeof e->text, "anon_inode:[%s]",
                 f->evflags & __EFD_INOTIFY   ? "inotify"
                 : f->evflags & __EFD_TIMERFD ? "timerfd"
                                              : "eventfd");
        break;
      case kFdEpoll:
        snprintf(e->text, sizeof e->text, "anon_inode:[eventpoll]");
        break;
      case kFdEmpty:
        continue;
      default:
        snprintf(e->text, sizeof e->text, "anon_inode:[kind%d]", f->kind);
        break;
    }
    e->fd = fd;
    n++;
  }
  *out = ents;
  return n;
}

// Another process's descriptors, where the kernel will enumerate them. NT
// will not; -1 sends its callers to the socket tables (pfs_net_fds_of),
// the one cross-process source it has.
int pfs_other_fds(uint32_t pid, struct pfs_fdent **out) {
  *out = 0;
  if (IsXnuSilicon())
    return pfs_xnu_fds_of(pid, out);
  return -1;
}

// /proc/<pid>/fdinfo/<fd>. Our own descriptors answer from the fd table
// and the descriptor itself (flags, offset, and a stat for files); on
// XNU the kernel's per-descriptor facts cover any process the caller may
// see. Another process on NT is only known through the socket tables,
// whose dense numbering carries no offset or flags.
bool pfs_fd_info(uint32_t pid, int fd, struct pfs_fdinfo *out) {
  memset(out, 0, sizeof *out);
  if (fd < 0)
    return false;
  if (pid == pfs_self_pid()) {
    if (IsWindows()) {
      if (!__isfdopen(fd))
        return false;
      if (__isfdkind(fd, kFdFile)) {
        int64_t pos = lseek(fd, 0, SEEK_CUR);
        out->pos = pos < 0 ? 0 : pos;
        struct stat st;
        if (!fstat(fd, &st))
          out->ino = st.st_ino;
      }
    } else if (!pfs_xnu_fd_info(pid, fd, out)) {
      return false;
    }
    // the descriptor itself says what it was opened with, in our own
    // spelling of the flags
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0)
      out->flags = (unsigned)fl;
    if (fcntl(fd, F_GETFD) > 0)
      out->flags |= O_CLOEXEC;
    return true;
  }
  if (IsXnuSilicon())
    return pfs_xnu_fd_info(pid, fd, out);
  uint64_t *inodes;
  int n = pfs_net_fds_of(pid, &inodes);
  bool ok = fd < n;
  if (ok) {
    out->flags = O_RDWR;
    out->ino = inodes[fd];
  }
  free(inodes);
  return ok;
}

// The file's text: offset, the open flags in octal, and the inode of
// what sits behind it (0 where nothing has one), the kernel's shape.
bool pfs_gen_fdinfo(struct pfs_buf *b, uint32_t pid, int fd) {
  struct pfs_fdinfo fi;
  if (!pfs_fd_info(pid, fd, &fi))
    return false;
  pfs_printf(b, "pos:\t%lld\nflags:\t0%o\nmnt_id:\t0\nino:\t%llu\n",
             (long long)fi.pos, fi.flags, (unsigned long long)fi.ino);
  return true;
}

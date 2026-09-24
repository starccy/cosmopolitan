/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2026 Justine Alexandra Roberts Tunney                              │
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
#include "libc/calls/blockcancel.internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-sysv.internal.h"
#include "libc/intrin/weaken.h"
#include "libc/procfs/internal.h"
#include "libc/sysv/consts/f.h"
#include "libc/calls/struct/sigset.internal.h"

// The descriptors of the tree. A content file opened for reading gets a
// handle holding the text generated for that open, a directory one
// holding its listing, a link opened with O_PATH one holding its target.
// The number is a reserved slot on NT and a claimed kernel descriptor on
// the unix side (the zipos pattern: a dup of stderr, or /dev/null when
// that is closed), so the kernel never sees the file and cosmo's own fd
// table tells the two apart by kind. A monitor that keeps hundreds of
// these open costs the host nothing.
//
// The text is fresh at every open and regenerated in place by
// lseek(fd, 0, SEEK_SET) for readers that keep it open, which is what
// the kernel's /proc gives a reader that rewinds. Two threads may share
// one open file, so pos and the text are guarded by a lock per handle.

// The handle keeps the path with the self alias resolved, the way the
// kernel names the file behind a descriptor in /proc/<pid>/fd.
struct ProcfsHandle *pc_handle_new(const char *vpath) {
  struct ProcfsHandle *h = calloc(1, sizeof *h);
  if (!h)
    return 0;
  atomic_init(&h->refs, 1);
  pthread_mutex_init(&h->lock, 0);
  if (!strncmp(vpath, "/proc/self", 10) && (!vpath[10] || vpath[10] == '/')) {
    snprintf(h->vpath, sizeof h->vpath, "/proc/%u%s", pfs_self_pid(),
             vpath + 10);
  } else {
    strlcpy(h->vpath, vpath, sizeof h->vpath);
  }
  return h;
}

struct ProcfsHandle *__procfs_keep(struct ProcfsHandle *h) {
  atomic_fetch_add_explicit(&h->refs, 1, memory_order_relaxed);
  return h;
}

void __procfs_drop(struct ProcfsHandle *h) {
  if (atomic_fetch_sub_explicit(&h->refs, 1, memory_order_release) != 1)
    return;
  atomic_thread_fence(memory_order_acquire);
  pthread_mutex_destroy(&h->lock);
  free(h->p);
  free(h->ents);
  free(h);
}

static int pc_mkfd(int minfd) {
  int cmd;
  if (IsXnu()) {
    cmd = 67;
  } else if (IsFreebsd()) {
    cmd = 17;
  } else if (IsOpenbsd()) {
    cmd = 10;
  } else if (IsNetbsd()) {
    cmd = 12;
  } else {
    cmd = F_DUPFD_CLOEXEC;
  }
  int fd, e = errno;
  if ((fd = __sys_fcntl(2, cmd, minfd)) != -1) {
    return fd;
  } else if (errno == EINVAL) {
    errno = e;
    return __fixupnewfd(__sys_fcntl(2, F_DUPFD, minfd), O_CLOEXEC);
  } else {
    return fd;
  }
}

static int pc_setfd(int fd, struct ProcfsHandle *h, int flags, unsigned mode) {
  int want = fd;
  atomic_compare_exchange_strong_explicit(&__get_pib()->fds.f, &want, fd + 1,
                                          memory_order_release,
                                          memory_order_relaxed);
  struct Fd *f = &__get_pib()->fds.p[fd];
  f->kind = kFdProc;
  f->handle = (intptr_t)h;
  f->flags = flags & (O_ACCMODE | O_CLOEXEC | O_NONBLOCK);
  if (!IsWindows())
    f->flags |= O_CLOEXEC;  // the kernel descriptor behind it is
  f->mode = mode;
  __fds_unlock();
  return fd;
}

// A descriptor number for h, which the table then owns. -1 with errno,
// and h is dropped.
int pc_handle_fd(struct ProcfsHandle *h, int flags, unsigned mode) {
  int fd, minfd = 3;
  __fds_lock();
TryAgain:
  if (IsWindows() || IsMetal()) {
    if ((fd = __reservefd_unlocked(-1)) != -1)
      return pc_setfd(fd, h, flags, mode);
  } else if ((fd = pc_mkfd(minfd)) != -1) {
    if (__ensurefds_unlocked(fd) != -1) {
      if (__get_pib()->fds.p[fd].kind) {
        sys_close(fd);
        minfd = fd + 1;
        goto TryAgain;
      }
      return pc_setfd(fd, h, flags, mode);
    }
    sys_close(fd);
  }
  __fds_unlock();
  __procfs_drop(h);
  return -1;
}

bool pc_fd_vpath(int fd, char *out, size_t n) {
  if (!__isfdkind(fd, kFdProc))
    return false;
  struct ProcfsHandle *h =
      (struct ProcfsHandle *)(intptr_t)__get_pib()->fds.p[fd].handle;
  strlcpy(out, h->vpath, n);
  return true;
}

int pc_open_dir(const char *vpath, int flags) {
  struct pfs_virtent *ents;
  int n = pc_list_dir(vpath, &ents);
  if (n == -2)
    return enoent();
  if (n < 0)
    return enotdir();
  struct ProcfsHandle *h = pc_handle_new(vpath);
  if (!h) {
    free(ents);
    return enomem();
  }
  h->dir = true;
  h->ents = ents;
  h->nents = n;
  return pc_handle_fd(h, flags, S_IFDIR | 0555);
}

int pc_open_content(const char *vpath, int flags) {
  struct pfs_buf b = {0};
  if (!pc_gen_vpath(vpath, &b))
    return enoent();
  struct ProcfsHandle *h = pc_handle_new(vpath);
  if (!h) {
    pfs_buf_free(&b);
    return enomem();
  }
  h->p = b.p;
  h->n = b.n;
  pthread_mutex_lock(&pc_lock);
  h->gen = pc_content_gen(vpath);
  pthread_mutex_unlock(&pc_lock);
  return pc_handle_fd(h, flags, S_IFREG | 0444);
}

ssize_t __procfs_read(struct ProcfsHandle *h, const struct iovec *iov,
                      size_t iovlen, ssize_t off) {
  if (h->dir)
    return eisdir();
  if (h->link)
    return ebadf();
  size_t done = 0;
  pthread_mutex_lock(&h->lock);
  size_t pos = off < 0 ? h->pos : (size_t)off;
  for (size_t i = 0; i < iovlen && pos < h->n; i++) {
    size_t k = h->n - pos;
    if (k > iov[i].iov_len)
      k = iov[i].iov_len;
    memcpy(iov[i].iov_base, h->p + pos, k);
    pos += k;
    done += k;
  }
  if (off < 0)
    h->pos = pos;
  pthread_mutex_unlock(&h->lock);
  return (ssize_t)done;
}

// A reader that keeps /proc/<pid>/stat open and rewinds it each round
// (sysinfo does) gets the kernel's fresh text on Linux; here the text is
// regenerated on the rewind, so it sees the present rather than the moment
// of open. The volatile pid files come from a slot generation that is
// fixed for a throttle window, so a rewind inside the window that produced
// the text changes nothing.
int64_t __procfs_seek(struct ProcfsHandle *h, int64_t off, unsigned whence) {
  if (off == 0 && whence == SEEK_SET && !pc_busy && !h->dir && !h->link) {
    bool stale;
    pthread_mutex_lock(&pc_lock);
    stale = !h->gen || h->gen != pc_content_gen(h->vpath);
    pthread_mutex_unlock(&pc_lock);
    if (stale) {
      // generated outside h->lock, since generation takes pc_lock and
      // may be slow; swapped in under it
      struct pfs_buf b = {0};
      if (pc_gen_vpath(h->vpath, &b)) {
        pthread_mutex_lock(&pc_lock);
        int64_t gen = pc_content_gen(h->vpath);
        pthread_mutex_unlock(&pc_lock);
        pthread_mutex_lock(&h->lock);
        free(h->p);
        h->p = b.p;
        h->n = b.n;
        h->gen = gen;
        h->pos = 0;
        pthread_mutex_unlock(&h->lock);
        return 0;
      }
    }
    pthread_mutex_lock(&h->lock);
    h->pos = 0;
    pthread_mutex_unlock(&h->lock);
    return 0;
  }
  pthread_mutex_lock(&h->lock);
  int64_t base, rc;
  switch (whence) {
    case SEEK_SET:
      base = 0;
      break;
    case SEEK_CUR:
      base = (int64_t)h->pos;
      break;
    case SEEK_END:
      base = (int64_t)h->n;
      break;
    default:
      base = -1;
      break;
  }
  if (base < 0 || base + off < 0) {
    rc = einval();
  } else {
    h->pos = (size_t)(base + off);
    rc = (int64_t)h->pos;
  }
  pthread_mutex_unlock(&h->lock);
  return rc;
}

int __procfs_fstat(struct ProcfsHandle *h, struct stat *st) {
  memset(st, 0, sizeof *st);
  pthread_mutex_lock(&h->lock);
  size_t n = h->n;
  pthread_mutex_unlock(&h->lock);
  if (h->dir) {
    st->st_mode = S_IFDIR | 0555;
    st->st_nlink = 2;
  } else if (h->link) {
    st->st_mode = S_IFLNK | pc_link_mode(h->vpath);
    st->st_nlink = 1;
    st->st_size = (int64_t)n;
  } else {
    st->st_mode = S_IFREG | 0444;
    st->st_nlink = 1;
    st->st_size = (int64_t)n;
    st->st_blocks = (int64_t)((n + 511) / 512);
  }
  st->st_blksize = 4096;
  st->st_dev = 0x70726f63;  // "proc"
  st->st_ino = pc_inode(h->vpath);
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  st->st_atim = st->st_mtim = st->st_ctim = now;
  return 0;
}

int __procfs_readdir(struct ProcfsHandle *h, long index, struct dirent *ent) {
  if (!h->dir || index < 0 || index >= h->nents)
    return 0;
  const struct pfs_virtent *e = &h->ents[index];
  char path[PC_PATH_MAX + 40];
  snprintf(path, sizeof path, "%s/%s", h->vpath, e->name);
  ent->d_ino = pc_inode(path);
  ent->d_off = index;
  ent->d_type = e->type;
  strlcpy(ent->d_name, e->name, sizeof ent->d_name);
  return 1;
}

int __procfs_close(int fd) {
  int rc;
  if (!IsWindows()) {
    rc = sys_close(fd);
  } else {
    rc = 0;
  }
  if (!__vforked) {
    struct ProcfsHandle *h =
        (struct ProcfsHandle *)(intptr_t)__get_pib()->fds.p[fd].handle;
    __procfs_drop(h);
  }
  return rc;
}

// After a unix dup: the table entry follows the kernel descriptor.
void __procfs_postdup(int oldfd, int newfd) {
  if (oldfd == newfd)
    return;
  BLOCK_SIGNALS;
  BLOCK_CANCELATION;
  __fds_lock();
  if (__isfdkind(newfd, kFdProc)) {
    __procfs_drop(
        (struct ProcfsHandle *)(intptr_t)__get_pib()->fds.p[newfd].handle);
    if (!__isfdkind(oldfd, kFdProc))
      bzero(__get_pib()->fds.p + newfd, sizeof(*__get_pib()->fds.p));
  }
  if (__isfdkind(oldfd, kFdProc)) {
    __procfs_keep(
        (struct ProcfsHandle *)(intptr_t)__get_pib()->fds.p[oldfd].handle);
    __ensurefds_unlocked(newfd);
    __get_pib()->fds.p[newfd] = __get_pib()->fds.p[oldfd];
  }
  __fds_unlock();
  ALLOW_CANCELATION;
  ALLOW_SIGNALS;
}

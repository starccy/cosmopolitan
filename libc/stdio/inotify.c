#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/struct/dirent.h"
#include "libc/calls/struct/inotify_event.h"
#include "libc/calls/struct/sigset.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/fmt/wintime.internal.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/getenv.h"
#include "libc/intrin/strace.h"
#include "libc/limits.h"
#include "libc/macros.h"
#include "libc/mem/alg.h"
#include "libc/mem/mem.h"
#include "libc/nt/createfile.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/fileaction.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/enum/filenotifychange.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/enum/findexinfolevels.h"
#include "libc/nt/enum/findexsearchops.h"
#include "libc/nt/errors.h"
#include "libc/nt/files.h"
#include "libc/nt/iocp.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/filenotifyinformation.h"
#include "libc/nt/struct/overlapped.h"
#include "libc/nt/struct/win32finddata.h"
#include "libc/nt/thread.h"
#include "libc/runtime/runtime.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/clock.h"
#include "libc/sysv/consts/efd.h"
#include "libc/sysv/consts/in.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/thread/thread.h"
#include "libc/thread/thread2.h"

/**
 * @fileoverview inotify for every host.
 *
 * Linux has it. Elsewhere an instance is an eventfd (libc/calls/eventfd.c)
 * with a queue of records behind it. A thread stats the watched paths and
 * queues what changed since it last looked, in the Linux wire format; the
 * counter is nonzero while the queue holds something, so poll() and epoll
 * see the descriptor the way they see any eventfd, and read() hands out
 * whole records.
 *
 * When to look: on Windows each watched directory is opened for
 * ReadDirectoryChangesW and the request completes on a port the thread
 * waits on, so a change is seen as it happens and an idle tree costs
 * nothing; the listing is still what's compared, the request only says
 * which directory to compare, and its rename pairs become IN_MOVED_FROM
 * and IN_MOVED_TO with a cookie. Watched files, directories that can't be
 * opened this way, and every watch on the other hosts are scanned on a
 * timer, 200ms unless COSMOPOLITAN_INOTIFY_MS says otherwise; directories
 * with a request get a safety scan every five seconds.
 *
 * What a scan can't report: IN_OPEN, IN_ACCESS and the IN_CLOSE pair have
 * no trace in a stat. A rename is a delete and a create with no cookie
 * where there's no request to pair it, and on Windows, where the listing
 * has no inode numbers, a rename onto an existing name is a modify. A
 * change made and undone between two looks is never seen, and a watched
 * file replaced by rename keeps its watch (Linux drops it).
 *
 * COSMOPOLITAN_INOTIFY_EMULATE=1 takes this path on Linux too, which is
 * how it's checked against the kernel.
 */

#define INOTIFY_MAX_WATCHES 8192   // the kernel's max_user_watches default
#define INOTIFY_MAX_QUEUED  16384  // the kernel's max_queued_events default
#define INOTIFY_INTERVAL_MS 200
#define INOTIFY_SWEEP_MS    5000  // windows: scan of the request-backed watches
#define INOTIFY_COALESCE_MS 5     // windows: wait for the rest of a burst
#define INOTIFY_EVENT_SIZE  sizeof(struct inotify_event)

#define INOTIFY_FILTER                                                 \
  (kNtFileNotifyChangeFileName | kNtFileNotifyChangeDirName |          \
   kNtFileNotifyChangeAttributes | kNtFileNotifyChangeSize |           \
   kNtFileNotifyChangeLastWrite | kNtFileNotifyChangeCreation |        \
   kNtFileNotifyChangeSecurity)

struct InotifyRec {
  struct InotifyRec *next;
  size_t size;  // of the inotify_event that follows
};

struct InotifyKid {
  char *name;
  uint64_t ino;
  int64_t mtime;
  int64_t mtime_ns;
  int64_t size;
  uint32_t mode;
  bool isdir;
};

struct InotifyRename {
  char *from;
  char *to;
  uint32_t cookie;
};

// windows: the change request behind a directory watch. it outlives the
// watch entry, which moves when the table grows or a watch is reaped
struct InotifyIo {
  struct NtOverlapped ov;
  char buf[4096];  // right after ov, which keeps it aligned for the request
  int64_t handle;
  int wd;
  bool pending;
  bool dead;   // the watch is gone; freed once the request lands
  bool issue;  // the scanner should send the request
};

struct InotifyWatch {
  int wd;
  uint32_t mask;
  bool isdir;
  bool dropped;  // IN_IGNORED is queued; reaped after the scan
  bool dirty;    // windows: the request landed; compare this one
  char *path;
  struct InotifyIo *io;
  char *from;  // a rename whose new name hasn't been reported yet
  struct InotifyRename *renames;  // reported by the last request
  size_t nrenames;
  struct InotifyKid self;   // a file: its last stat
  struct InotifyKid *kids;  // a directory: its last listing, sorted by name
  size_t nkids;
};

struct Inotify {
  pthread_mutex_t lock;
  int fd;
  int pid;  // of the process the scanner runs in
  int refs;
  int next_wd;
  int inflight;   // windows: requests that haven't landed
  int64_t port;   // windows: where they land
  uint32_t cookie;
  bool dead;  // closed; the scanner frees the instance on its way out
  bool scanning;
  bool overflow;  // IN_Q_OVERFLOW is the last record queued
  size_t queued;
  struct InotifyRec *head;
  struct InotifyRec **tail;
  struct InotifyWatch *watches;
  size_t nwatches;
  size_t cap;
};

// what one request reported, taken off the port before the lock is held
struct InotifyLanded {
  struct InotifyIo *io;
  uint32_t bytes;
  uint32_t err;
};

static bool InotifyEmulated(void) {
  static int emulated = -1;
  if (emulated == -1) {
    const char *s = __getenv(environ, "COSMOPOLITAN_INOTIFY_EMULATE").s;
    emulated = !IsLinux() || (s && *s);
  }
  return emulated;
}

static int InotifyIntervalMs(void) {
  static int ms = -1;
  if (ms == -1) {
    int n = 0;
    const char *s = __getenv(environ, "COSMOPOLITAN_INOTIFY_MS").s;
    for (; s && '0' <= *s && *s <= '9' && n < 60000; ++s)
      n = n * 10 + (*s - '0');
    ms = n > 0 ? n : INOTIFY_INTERVAL_MS;
  }
  return ms;
}

static int64_t InotifyNowMs(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// a forked child inherits the instance but not the thread or the handles
static bool InotifyScanning(struct Inotify *in) {
  return in->scanning && in->pid == getpid();
}

static bool InotifyLive(struct Inotify *in) {
  return !in->scanning || in->pid == getpid();
}

static void InotifyKidsFree(struct InotifyKid *kids, size_t n) {
  for (size_t i = 0; i < n; ++i)
    free(kids[i].name);
  free(kids);
}

static void InotifyRenamesFree(struct InotifyWatch *w) {
  for (size_t i = 0; i < w->nrenames; ++i) {
    free(w->renames[i].from);
    free(w->renames[i].to);
  }
  free(w->renames);
  w->renames = 0;
  w->nrenames = 0;
  free(w->from);
  w->from = 0;
}

// the request in flight is cancelled and freed when it lands; in a forked
// child the handles aren't ours, so only the memory goes
static void InotifyIoDrop(struct InotifyWatch *w, bool live) {
  struct InotifyIo *io = w->io;
  if (!io)
    return;
  w->io = 0;
  if (!live) {
    free(io);
  } else if (io->pending) {
    io->dead = true;
    CancelIoEx(io->handle, &io->ov);
  } else {
    CloseHandle(io->handle);
    free(io);
  }
}

static void InotifyWatchFree(struct InotifyWatch *w, bool live) {
  InotifyIoDrop(w, live);
  InotifyRenamesFree(w);
  InotifyKidsFree(w->kids, w->nkids);
  free(w->path);
  bzero(w, sizeof(*w));
}

static void InotifyFree(struct Inotify *in, bool live) {
  for (size_t i = 0; i < in->nwatches; ++i)
    InotifyWatchFree(&in->watches[i], live);
  free(in->watches);
  while (in->head) {
    struct InotifyRec *r = in->head;
    in->head = r->next;
    free(r);
  }
  if (in->port && live)
    CloseHandle(in->port);
  pthread_mutex_destroy(&in->lock);
  free(in);
}

// queues one record. the name is padded with zeros to a multiple of the
// header size and the padding counts in len, as the kernel does it
static void InotifyPush(struct Inotify *in, int wd, uint32_t mask,
                        uint32_t cookie, const char *name) {
  size_t n = 0, len = 0;
  if (in->dead)
    return;
  if (in->queued >= INOTIFY_MAX_QUEUED) {
    if (in->overflow)
      return;
    in->overflow = true;
    wd = -1;
    mask = IN_Q_OVERFLOW;
    cookie = 0;
    name = 0;
  }
  if (name && *name) {
    n = strlen(name);
    if (n > NAME_MAX)
      n = NAME_MAX;
    len = ROUNDUP(n + 1, INOTIFY_EVENT_SIZE);
  }
  struct InotifyRec *r = malloc(sizeof(*r) + INOTIFY_EVENT_SIZE + len);
  if (!r)
    return;
  struct inotify_event *ev = (struct inotify_event *)(r + 1);
  r->next = 0;
  r->size = INOTIFY_EVENT_SIZE + len;
  ev->wd = wd;
  ev->mask = mask;
  ev->cookie = cookie;
  ev->len = len;
  if (len) {
    memcpy(ev->name, name, n);
    bzero(ev->name + n, len - n);
  }
  *in->tail = r;
  in->tail = &r->next;
  ++in->queued;
  __eventfd_post(in->fd, 1);
}

static void InotifyDrop(struct Inotify *in, struct InotifyWatch *w) {
  if (w->dropped)
    return;
  w->dropped = true;
  InotifyPush(in, w->wd, IN_IGNORED, 0, 0);
}

static void InotifyEmit(struct Inotify *in, struct InotifyWatch *w,
                        uint32_t mask, uint32_t cookie, const char *name) {
  if (w->dropped || !(mask & w->mask & IN_ALL_EVENTS))
    return;
  InotifyPush(in, w->wd, mask, cookie, name);
  if (w->mask & IN_ONESHOT)
    InotifyDrop(in, w);
}

static void InotifyKidFromStat(struct InotifyKid *k, const struct stat *st) {
  k->ino = st->st_ino;
  k->mtime = st->st_mtim.tv_sec;
  k->mtime_ns = st->st_mtim.tv_nsec;
  k->size = st->st_size;
  k->mode = st->st_mode;
  k->isdir = S_ISDIR(st->st_mode);
}

static int InotifyKidCompare(const void *a, const void *b) {
  return strcmp(((const struct InotifyKid *)a)->name,
                ((const struct InotifyKid *)b)->name);
}

static struct InotifyKid *InotifyKidNew(struct InotifyKid **kids, size_t *n,
                                        size_t *cap, const char *name) {
  if (*n == *cap) {
    size_t ncap = *cap ? *cap * 2 : 16;
    struct InotifyKid *p = realloc(*kids, ncap * sizeof(*p));
    if (!p)
      return 0;
    *kids = p;
    *cap = ncap;
  }
  struct InotifyKid *k = *kids + *n;
  bzero(k, sizeof(*k));
  if (!(k->name = strdup(name)))
    return 0;
  ++*n;
  return k;
}

// one FindFirstFileEx call returns names, sizes and write times together,
// where a stat per entry would open each file
static int InotifyListNt(const char *path, struct InotifyKid **out,
                         size_t *outn) {
  int rc = -1;
  char16_t *path16;
  if (!(path16 = malloc(PATH_MAX * sizeof(char16_t) + PATH_MAX)))
    return -1;
  char *name = (char *)(path16 + PATH_MAX);
  int len = __mkntpath(path, path16);
  if (len < 0 || len + 3 >= PATH_MAX)
    goto Done;
  if (len && path16[len - 1] != u'\\')
    path16[len++] = u'\\';
  path16[len++] = u'*';
  path16[len] = 0;
  struct NtWin32FindData fd;
  int64_t h = FindFirstFileEx(path16, kNtFindExInfoBasic, &fd,
                              kNtFindExSearchNameMatch, 0,
                              kNtFindFirstExLargeFetch);
  if (h == -1)
    goto Done;
  struct InotifyKid *kids = 0;
  size_t n = 0, cap = 0;
  do {
    if (!tprecode16to8(name, PATH_MAX, fd.cFileName).ax)
      continue;
    if (!strcmp(name, ".") || !strcmp(name, ".."))
      continue;
    struct InotifyKid *k = InotifyKidNew(&kids, &n, &cap, name);
    if (!k)
      break;
    struct timespec ts = FileTimeToTimeSpec(fd.ftLastWriteTime);
    k->mtime = ts.tv_sec;
    k->mtime_ns = ts.tv_nsec;
    k->size = (int64_t)fd.nFileSizeHigh << 32 | fd.nFileSizeLow;
    k->isdir = !!(fd.dwFileAttributes & kNtFileAttributeDirectory);
    if (fd.dwFileAttributes & kNtFileAttributeReparsePoint) {
      k->mode = 0120777;
    } else {
      k->mode = (k->isdir ? 040000 : 0100000) |
                ((fd.dwFileAttributes & kNtFileAttributeReadonly) ? 0555
                                                                  : 0777);
    }
  } while (FindNextFile(h, &fd));
  FindClose(h);
  *out = kids;
  *outn = n;
  rc = 0;
Done:
  free(path16);
  return rc;
}

static int InotifyListUnix(const char *path, struct InotifyKid **out,
                           size_t *outn) {
  DIR *d;
  if (!(d = opendir(path)))
    return -1;
  char *child;
  if (!(child = malloc(PATH_MAX))) {
    closedir(d);
    return -1;
  }
  size_t plen = strlen(path);
  struct InotifyKid *kids = 0;
  size_t n = 0, cap = 0;
  struct dirent *e;
  while ((e = readdir(d))) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
      continue;
    size_t nlen = strlen(e->d_name);
    if (plen + 1 + nlen >= PATH_MAX)
      continue;
    memcpy(child, path, plen);
    child[plen] = '/';
    memcpy(child + plen + 1, e->d_name, nlen + 1);
    struct stat st;
    if (lstat(child, &st))
      continue;  // gone between the listing and the stat
    struct InotifyKid *k = InotifyKidNew(&kids, &n, &cap, e->d_name);
    if (!k)
      break;
    InotifyKidFromStat(k, &st);
  }
  closedir(d);
  free(child);
  *out = kids;
  *outn = n;
  return 0;
}

static int InotifyList(const char *path, struct InotifyKid **out,
                       size_t *outn) {
  if (!(IsWindows() && !InotifyListNt(path, out, outn)) &&
      InotifyListUnix(path, out, outn))
    return -1;
  if (*outn > 1)
    qsort(*out, *outn, sizeof(**out), InotifyKidCompare);
  return 0;
}

static struct InotifyRename *InotifyRenameFrom(struct InotifyWatch *w,
                                               const char *name) {
  for (size_t i = 0; i < w->nrenames; ++i)
    if (!strcmp(w->renames[i].from, name))
      return &w->renames[i];
  return 0;
}

static struct InotifyRename *InotifyRenameTo(struct InotifyWatch *w,
                                             const char *name) {
  for (size_t i = 0; i < w->nrenames; ++i)
    if (!strcmp(w->renames[i].to, name))
      return &w->renames[i];
  return 0;
}

// walks the old and new listings in step
static void InotifyScanDir(struct Inotify *in, struct InotifyWatch *w) {
  struct InotifyKid *now = 0;
  size_t n = 0;
  if (InotifyList(w->path, &now, &n)) {
    if (errno == ENOENT || errno == ENOTDIR) {
      InotifyEmit(in, w, IN_DELETE_SELF, 0, 0);
      InotifyDrop(in, w);
    }
    InotifyRenamesFree(w);
    return;
  }
  size_t i = 0, j = 0;
  while (i < w->nkids || j < n) {
    int c;
    if (i == w->nkids) {
      c = 1;
    } else if (j == n) {
      c = -1;
    } else {
      c = strcmp(w->kids[i].name, now[j].name);
    }
    if (c < 0) {
      struct InotifyKid *o = &w->kids[i++];
      uint32_t isdir = o->isdir ? IN_ISDIR : 0;
      struct InotifyRename *r = InotifyRenameFrom(w, o->name);
      if (r) {
        InotifyEmit(in, w, IN_MOVED_FROM | isdir, r->cookie, o->name);
      } else {
        InotifyEmit(in, w, IN_DELETE | isdir, 0, o->name);
      }
    } else if (c > 0) {
      struct InotifyKid *p = &now[j++];
      uint32_t isdir = p->isdir ? IN_ISDIR : 0;
      struct InotifyRename *r = InotifyRenameTo(w, p->name);
      if (r) {
        InotifyEmit(in, w, IN_MOVED_TO | isdir, r->cookie, p->name);
      } else {
        InotifyEmit(in, w, IN_CREATE | isdir, 0, p->name);
      }
    } else {
      struct InotifyKid *o = &w->kids[i++];
      struct InotifyKid *p = &now[j++];
      uint32_t isdir = p->isdir ? IN_ISDIR : 0;
      if (o->ino != p->ino) {
        // the name survived, the file behind it didn't
        InotifyEmit(in, w, IN_DELETE | isdir, 0, o->name);
        InotifyEmit(in, w, IN_CREATE | isdir, 0, p->name);
      } else {
        if (o->mtime != p->mtime || o->mtime_ns != p->mtime_ns ||
            o->size != p->size)
          InotifyEmit(in, w, IN_MODIFY | isdir, 0, p->name);
        if (o->mode != p->mode)
          InotifyEmit(in, w, IN_ATTRIB | isdir, 0, p->name);
      }
    }
  }
  InotifyKidsFree(w->kids, w->nkids);
  w->kids = now;
  w->nkids = n;
  InotifyRenamesFree(w);
}

static void InotifyScanFile(struct Inotify *in, struct InotifyWatch *w) {
  struct stat st;
  int rc = (w->mask & IN_DONT_FOLLOW) ? lstat(w->path, &st)
                                      : stat(w->path, &st);
  if (rc) {
    if (errno == ENOENT || errno == ENOTDIR) {
      InotifyEmit(in, w, IN_DELETE_SELF, 0, 0);
      InotifyDrop(in, w);
    }
    return;
  }
  struct InotifyKid now = {0};
  InotifyKidFromStat(&now, &st);
  if (now.ino != w->self.ino) {
    // replaced by rename: the kernel reports the link count changing on
    // the old inode, then drops the watch; this keeps watching the path
    InotifyEmit(in, w, IN_ATTRIB, 0, 0);
  } else {
    if (now.mtime != w->self.mtime || now.mtime_ns != w->self.mtime_ns ||
        now.size != w->self.size)
      InotifyEmit(in, w, IN_MODIFY, 0, 0);
    if (now.mode != w->self.mode)
      InotifyEmit(in, w, IN_ATTRIB, 0, 0);
  }
  w->self = now;
}

static void InotifyScanWatch(struct Inotify *in, struct InotifyWatch *w) {
  w->dirty = false;
  if (w->dropped)
    return;
  if (w->isdir) {
    InotifyScanDir(in, w);
  } else {
    InotifyScanFile(in, w);
  }
}

static void InotifyReap(struct Inotify *in) {
  for (size_t i = 0; i < in->nwatches;) {
    if (!in->watches[i].dropped) {
      ++i;
      continue;
    }
    InotifyWatchFree(&in->watches[i], true);
    memmove(&in->watches[i], &in->watches[i + 1],
            (in->nwatches - i - 1) * sizeof(in->watches[0]));
    --in->nwatches;
  }
}

// every watch, or only the ones a request didn't cover, or only the
// ones whose request landed
enum InotifyWhich { kInotifyAll, kInotifyPolled, kInotifyDirty };

static void InotifyScan(struct Inotify *in, enum InotifyWhich which) {
  for (size_t i = 0; i < in->nwatches; ++i) {
    struct InotifyWatch *w = &in->watches[i];
    if (which == kInotifyPolled && w->io)
      continue;
    if (which == kInotifyDirty && !w->dirty)
      continue;
    InotifyScanWatch(in, w);
  }
  InotifyReap(in);
}

static void *InotifyScannerPoll(struct Inotify *in) {
  int ms = InotifyIntervalMs();
  struct timespec nap = {ms / 1000, ms % 1000 * 1000000};
  for (;;) {
    nanosleep(&nap, 0);
    pthread_mutex_lock(&in->lock);
    if (in->dead)
      break;
    InotifyScan(in, kInotifyAll);
    pthread_mutex_unlock(&in->lock);
  }
  pthread_mutex_unlock(&in->lock);
  InotifyFree(in, true);
  return 0;
}

static struct InotifyWatch *InotifyWatchByWd(struct Inotify *in, int wd) {
  for (size_t i = 0; i < in->nwatches; ++i)
    if (in->watches[i].wd == wd && !in->watches[i].dropped)
      return &in->watches[i];
  return 0;
}

// windows: opens the directory the request is made on. the scanner sends
// the request itself, since windows cancels a thread's i/o when it exits
static void InotifyIoOpen(struct Inotify *in, struct InotifyWatch *w) {
  int64_t h = -1;
  char16_t *path16;
  if (!(path16 = malloc(PATH_MAX * sizeof(char16_t))))
    return;
  if (__mkntpath(w->path, path16) >= 0)
    h = CreateFile(path16, kNtFileListDirectory,
                   kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete,
                   0, kNtOpenExisting,
                   kNtFileFlagBackupSemantics | kNtFileFlagOverlapped, 0);
  free(path16);
  if (h == -1)
    return;
  struct InotifyIo *io = calloc(1, sizeof(*io));
  if (!io || CreateIoCompletionPort(h, in->port, 0, 0) != in->port) {
    CloseHandle(h);
    free(io);
    return;
  }
  io->handle = h;
  io->wd = w->wd;
  io->issue = true;
  w->io = io;
  STRACE("inotify: wd %d watches %#s through a change request", w->wd, w->path);
}

// a directory whose request can't be made is scanned on the interval
static void InotifyIoIssue(struct Inotify *in, struct InotifyWatch *w) {
  struct InotifyIo *io = w->io;
  io->issue = false;
  bzero(&io->ov, sizeof(io->ov));
  if (ReadDirectoryChangesW(io->handle, io->buf, sizeof(io->buf), false,
                            INOTIFY_FILTER, 0, &io->ov, 0)) {
    io->pending = true;
    ++in->inflight;
    STRACE("inotify: wd %d request sent", w->wd);
  } else {
    STRACE("inotify: wd %d request refused% m; scanning it instead", w->wd);
    CloseHandle(io->handle);
    free(io);
    w->io = 0;
    w->dirty = true;
  }
}

static void InotifyIssue(struct Inotify *in) {
  for (size_t i = 0; i < in->nwatches; ++i)
    if (in->watches[i].io && in->watches[i].io->issue)
      InotifyIoIssue(in, &in->watches[i]);
}

static void InotifyRenameAdd(struct Inotify *in, struct InotifyWatch *w,
                             char *from, const char *to) {
  struct InotifyRename *p =
      realloc(w->renames, (w->nrenames + 1) * sizeof(*p));
  if (!p) {
    free(from);
    return;
  }
  w->renames = p;
  p += w->nrenames;
  p->from = from;
  if (!(p->to = strdup(to))) {
    free(from);
    return;
  }
  if (!++in->cookie)
    ++in->cookie;
  p->cookie = in->cookie;
  ++w->nrenames;
}

// the old name and the new name of a rename come as consecutive entries,
// though not always in the same request
static void InotifyIoParse(struct Inotify *in, struct InotifyWatch *w,
                           uint32_t bytes) {
  char *from = w->from;
  char16_t name16[NAME_MAX + 1];
  char name[NAME_MAX * 3 + 1];
  struct InotifyIo *io = w->io;
  for (uint32_t off = 0; off + sizeof(struct NtFileNotifyInformation) <= bytes;) {
    struct NtFileNotifyInformation *fni = (void *)(io->buf + off);
    uint32_t n = fni->FileNameLength / 2;
    if (n <= NAME_MAX &&
        off + sizeof(*fni) + fni->FileNameLength <= bytes) {
      memcpy(name16, fni->FileName, n * 2);
      name16[n] = 0;
      if (tprecode16to8(name, sizeof(name), name16).ax) {
        if (fni->Action == kNtFileActionRenamedOldName) {
          free(from);
          from = strdup(name);
        } else if (fni->Action == kNtFileActionRenamedNewName && from) {
          InotifyRenameAdd(in, w, from, name);
          from = 0;
        }
      }
    }
    if (!fni->NextEntryOffset)
      break;
    off += fni->NextEntryOffset;
  }
  w->from = from;
}

static void InotifyIoLanded(struct Inotify *in, struct InotifyLanded *l) {
  struct InotifyIo *io = l->io;
  io->pending = false;
  --in->inflight;
  STRACE("inotify: wd %d request landed with %u bytes, error %u", io->wd,
         l->bytes, l->err);
  struct InotifyWatch *w = io->dead ? 0 : InotifyWatchByWd(in, io->wd);
  if (!w) {
    CloseHandle(io->handle);
    free(io);
    return;
  }
  w->dirty = true;
  if (!l->err) {
    // zero bytes is the buffer having overflowed, and the scan covers it
    if (l->bytes)
      InotifyIoParse(in, w, l->bytes);
    io->issue = true;
  } else if (l->err == kNtErrorNotifyEnumDir) {
    io->issue = true;
  } else {
    // the directory went away or the request stopped being answered;
    // the interval scan takes it from here
    CloseHandle(io->handle);
    free(io);
    w->io = 0;
  }
}

// windows: the port hands over landed requests and posted wakeups; the
// timeout is whichever of the interval scan and the safety sweep is due.
// a landed request is sent again before the scan, and the scan waits for
// a quiet moment, so what a burst reports after the first request lands
// is in hand when the directory is compared
static void *InotifyScannerNt(struct Inotify *in) {
  int interval = InotifyIntervalMs();
  int64_t now = InotifyNowMs();
  int64_t poll_due = now + interval;
  int64_t sweep_due = now + INOTIFY_SWEEP_MS;
  for (;;) {
    now = InotifyNowMs();
    int64_t due = MIN(poll_due, sweep_due);
    uint32_t ms = due > now ? due - now : 0;
    uint32_t bytes = 0;
    uint64_t key = 0;
    struct NtOverlapped *ov = 0;
    bool32 ok = GetQueuedCompletionStatus(in->port, &bytes, &key, &ov, ms);
    int total = 0;
    for (;;) {
      struct InotifyLanded landed[16];
      int n = 0;
      bool woke = false;
      for (;;) {
        if (ov) {
          landed[n].io = (struct InotifyIo *)ov;
          landed[n].bytes = bytes;
          landed[n].err = ok ? 0 : GetLastError();
          ++n;
        } else if (ok) {
          woke = true;
        } else {
          break;  // the timeout
        }
        if (n == ARRAYLEN(landed))
          break;
        ov = 0;
        ok = GetQueuedCompletionStatus(in->port, &bytes, &key, &ov,
                                       INOTIFY_COALESCE_MS);
      }
      STRACE("inotify: scanner woke: %d landed, wake %d, waited %u ms", n,
             woke, ms);
      pthread_mutex_lock(&in->lock);
      if (in->dead)
        goto Dead;
      for (int i = 0; i < n; ++i)
        InotifyIoLanded(in, &landed[i]);
      if (n || woke)
        InotifyIssue(in);
      pthread_mutex_unlock(&in->lock);
      total += n;
      if (!n)
        break;
      ov = 0;
      ok = GetQueuedCompletionStatus(in->port, &bytes, &key, &ov,
                                     INOTIFY_COALESCE_MS);
      if (!ok && !ov)
        break;
    }
    pthread_mutex_lock(&in->lock);
    if (in->dead)
      goto Dead;
    now = InotifyNowMs();
    if (now >= sweep_due) {
      InotifyScan(in, kInotifyAll);
      sweep_due = now + INOTIFY_SWEEP_MS;
      poll_due = now + interval;
    } else if (now >= poll_due) {
      InotifyScan(in, kInotifyPolled);
      poll_due = now + interval;
      InotifyScan(in, kInotifyDirty);
    } else if (total) {
      InotifyScan(in, kInotifyDirty);
    }
    pthread_mutex_unlock(&in->lock);
  }
Dead:
  // what's in flight has to land before its memory can go
  for (size_t i = 0; i < in->nwatches; ++i)
    InotifyIoDrop(&in->watches[i], true);
  for (int tries = 0; in->inflight > 0 && tries < 100; ++tries) {
    uint32_t bytes;
    uint64_t key;
    struct NtOverlapped *ov = 0;
    GetQueuedCompletionStatus(in->port, &bytes, &key, &ov, 10);
    if (ov) {
      struct InotifyIo *io = (struct InotifyIo *)ov;
      --in->inflight;
      CloseHandle(io->handle);
      free(io);
    }
  }
  pthread_mutex_unlock(&in->lock);
  InotifyFree(in, true);
  return 0;
}

static void *InotifyScanner(void *arg) {
  struct Inotify *in = arg;
  if (IsWindows() && in->port)
    return InotifyScannerNt(in);
  return InotifyScannerPoll(in);
}

// the scanner never runs signal handlers
static int InotifyStart(struct Inotify *in) {
  int rc;
  sigset_t all;
  pthread_t th;
  pthread_attr_t attr;
  sigfillset(&all);
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setsigmask_np(&attr, &all);
  rc = pthread_create(&th, &attr, InotifyScanner, in);
  pthread_attr_destroy(&attr);
  return rc;
}

static void InotifyWake(struct Inotify *in) {
  if (IsWindows() && in->port && InotifyScanning(in))
    PostQueuedCompletionStatus(in->port, 0, 0, 0);
}

static struct Inotify *GetInotify(int fd) {
  if (!__isfdopen(fd)) {
    ebadf();
    return 0;
  }
  struct Fd *f = __get_pib()->fds.p + fd;
  if (f->kind != kFdEvent || !(f->evflags & __EFD_INOTIFY)) {
    einval();
    return 0;
  }
  return f->inotify;
}

static int InotifyInit(int flags) {
  struct Inotify *in;
  if (flags & ~(IN_NONBLOCK | IN_CLOEXEC))
    return einval();
  if (!(in = calloc(1, sizeof(*in))))
    return -1;
  int fd = __eventfd_emu(0, (flags & IN_NONBLOCK ? EFD_NONBLOCK : 0) |
                                (flags & IN_CLOEXEC ? EFD_CLOEXEC : 0));
  if (fd == -1) {
    free(in);
    return -1;
  }
  pthread_mutex_init(&in->lock, 0);
  in->fd = fd;
  in->refs = 1;
  in->next_wd = 1;
  in->tail = &in->head;
  if (IsWindows()) {
    // a port that can't be had leaves every watch on the interval scan
    in->port = CreateIoCompletionPort(-1, 0, 0, 1);
    if (in->port == -1)
      in->port = 0;
  }
  struct Fd *f = __get_pib()->fds.p + fd;
  f->flags = (f->flags & ~O_ACCMODE) | O_RDONLY;
  f->evflags |= __EFD_INOTIFY;
  f->inotify = in;
  return fd;
}

static int InotifyAddWatch(struct Inotify *in, const char *path,
                           uint32_t mask) {
  struct stat st;
  if (!(mask & IN_ALL_EVENTS))
    return einval();
  if ((mask & IN_DONT_FOLLOW) ? lstat(path, &st) : stat(path, &st))
    return -1;
  bool isdir = S_ISDIR(st.st_mode);
  if ((mask & IN_ONLYDIR) && !isdir)
    return enotdir();

  pthread_mutex_lock(&in->lock);
  for (size_t i = 0; i < in->nwatches; ++i) {
    struct InotifyWatch *w = &in->watches[i];
    if (w->dropped || strcmp(w->path, path))
      continue;
    if (mask & IN_MASK_CREATE) {
      pthread_mutex_unlock(&in->lock);
      return eexist();
    }
    w->mask = (mask & IN_MASK_ADD) ? (w->mask | mask) : mask;
    int wd = w->wd;
    pthread_mutex_unlock(&in->lock);
    return wd;
  }
  if (in->nwatches >= INOTIFY_MAX_WATCHES) {
    pthread_mutex_unlock(&in->lock);
    return enospc();
  }
  if (!InotifyScanning(in)) {
    in->scanning = true;
    in->pid = getpid();
    pthread_mutex_unlock(&in->lock);
    if (InotifyStart(in)) {
      pthread_mutex_lock(&in->lock);
      in->scanning = false;
      pthread_mutex_unlock(&in->lock);
      return eagain();
    }
    pthread_mutex_lock(&in->lock);
  }
  if (in->nwatches == in->cap) {
    size_t ncap = in->cap ? in->cap * 2 : 8;
    struct InotifyWatch *p = realloc(in->watches, ncap * sizeof(*p));
    if (!p) {
      pthread_mutex_unlock(&in->lock);
      return enomem();
    }
    in->watches = p;
    in->cap = ncap;
  }
  struct InotifyWatch *w = &in->watches[in->nwatches];
  bzero(w, sizeof(*w));
  if (!(w->path = strdup(path))) {
    pthread_mutex_unlock(&in->lock);
    return enomem();
  }
  w->wd = in->next_wd++;
  w->mask = mask;
  w->isdir = isdir;
  InotifyKidFromStat(&w->self, &st);
  // what's there now was there before, not a burst of IN_CREATE
  if (isdir)
    InotifyList(path, &w->kids, &w->nkids);
  if (isdir && IsWindows() && in->port)
    InotifyIoOpen(in, w);
  ++in->nwatches;
  int wd = w->wd;
  bool request = !!w->io;
  pthread_mutex_unlock(&in->lock);
  if (request)
    InotifyWake(in);
  return wd;
}

static int InotifyRmWatch(struct Inotify *in, int wd) {
  pthread_mutex_lock(&in->lock);
  for (size_t i = 0; i < in->nwatches; ++i) {
    struct InotifyWatch *w = &in->watches[i];
    if (w->wd != wd || w->dropped)
      continue;
    InotifyDrop(in, w);
    InotifyIoDrop(w, InotifyLive(in));
    InotifyReap(in);
    pthread_mutex_unlock(&in->lock);
    return 0;
  }
  pthread_mutex_unlock(&in->lock);
  return einval();
}

// copies out whole records; 0 when the queue is empty
static ssize_t InotifyTake(struct Inotify *in, int fd, struct Fd *f,
                           char *buf, size_t size) {
  ssize_t got = 0;
  pthread_mutex_lock(&in->lock);
  if (in->head && in->head->size > size) {
    got = einval();
  } else {
    while (in->head && in->head->size <= size - got) {
      struct InotifyRec *r = in->head;
      memcpy(buf + got, r + 1, r->size);
      got += r->size;
      if (!(in->head = r->next))
        in->tail = &in->head;
      --in->queued;
      free(r);
    }
    if (in->queued < INOTIFY_MAX_QUEUED)
      in->overflow = false;
    if (got) {
      if (!in->head) {
        __eventfd_drain(fd);
      } else if (!IsWindows()) {
        // the wait below eats a byte; keep one on the wire while there's
        // more to read
        sys_write(f->evpeer, "", 1);
      }
    }
  }
  pthread_mutex_unlock(&in->lock);
  return got;
}

// called by read() on an inotify descriptor
ssize_t __inotify_read(int fd, struct Fd *f, void *buf, size_t size) {
  ssize_t rc;
  sigset_t m = 0;
  struct Inotify *in = f->inotify;
  if (IsWindows())
    m = __sig_block();
  for (;;) {
    if ((rc = InotifyTake(in, fd, f, buf, size)))
      break;
    if (f->flags & O_NONBLOCK) {
      rc = eagain();
      break;
    }
    if (IsWindows()) {
      if (__eventfd_wait_nt(f->handle, m) == -1) {
        rc = -1;
        break;
      }
    } else {
      char c;
      ssize_t r = sys_read(fd, &c, 1);
      if (r == -1) {
        rc = -1;
        break;
      }
      if (!r) {
        rc = eio();
        break;
      }
    }
  }
  if (IsWindows())
    __sig_unblock(m);
  return rc;
}

// called by dup() on windows, where the table entry is copied
void __inotify_ref(struct Fd *f) {
  struct Inotify *in = f->inotify;
  pthread_mutex_lock(&in->lock);
  ++in->refs;
  pthread_mutex_unlock(&in->lock);
}

// called by close() with the entry already taken out of the table
void __inotify_close(struct Fd *f) {
  struct Inotify *in = f->inotify;
  if (!in)
    return;
  f->inotify = 0;
  pthread_mutex_lock(&in->lock);
  if (--in->refs > 0) {
    pthread_mutex_unlock(&in->lock);
    return;
  }
  in->dead = true;
  bool scanning = InotifyScanning(in);
  bool live = InotifyLive(in);
  pthread_mutex_unlock(&in->lock);
  if (scanning) {
    InotifyWake(in);
  } else {
    InotifyFree(in, live);
  }
}

/**
 * Creates file descriptor that reports file system changes.
 *
 * @param flags can have IN_{NONBLOCK,CLOEXEC}
 * @return file descriptor, or -1 w/ errno
 */
int inotify_init1(int flags) {
  int rc;
  if (!InotifyEmulated()) {
    rc = sys_inotify_init1(flags);
  } else {
    rc = InotifyInit(flags);
  }
  STRACE("inotify_init1(%#x) → %d% m", flags, rc);
  return rc;
}

int inotify_init(void) {
  return inotify_init1(0);
}

/**
 * Watches a path for changes.
 *
 * @param fd was returned by inotify_init1()
 * @param mask is the IN_* events wanted, plus IN_{ONLYDIR,DONT_FOLLOW,
 *     MASK_ADD,MASK_CREATE,ONESHOT}
 * @return watch descriptor, or -1 w/ errno
 */
int inotify_add_watch(int fd, const char *path, uint32_t mask) {
  int rc;
  struct Inotify *in;
  if (!InotifyEmulated()) {
    rc = sys_inotify_add_watch(fd, path, mask);
  } else if (!path) {
    rc = efault();
  } else if ((in = GetInotify(fd))) {
    rc = InotifyAddWatch(in, path, mask);
  } else {
    rc = -1;
  }
  STRACE("inotify_add_watch(%d, %#s, %#x) → %d% m", fd, path, mask, rc);
  return rc;
}

/**
 * Stops watching a path; IN_IGNORED is queued for the watch.
 *
 * @return 0 on success, or -1 w/ errno
 */
int inotify_rm_watch(int fd, int wd) {
  int rc;
  struct Inotify *in;
  if (!InotifyEmulated()) {
    rc = sys_inotify_rm_watch(fd, wd);
  } else if ((in = GetInotify(fd))) {
    rc = InotifyRmWatch(in, wd);
  } else {
    rc = -1;
  }
  STRACE("inotify_rm_watch(%d, %d) → %d% m", fd, wd, rc);
  return rc;
}

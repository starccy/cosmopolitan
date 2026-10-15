#include "libc/calls/calls.h"
#include "libc/calls/internal.h"
#include "libc/calls/struct/dirent.h"
#include "libc/calls/struct/inotify_event.h"
#include "libc/calls/struct/metastat.internal.h"
#include "libc/calls/struct/sigset.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/struct/timespec.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/fmt/wintime.internal.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/getenv.h"
#include "libc/intrin/strace.h"
#include "libc/intrin/weaken.h"
#include "libc/limits.h"
#include "libc/macros.h"
#include "libc/mem/alg.h"
#include "libc/mem/mem.h"
#include "libc/nt/createfile.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/fileaction.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/enum/fileinfobyhandleclass.h"
#include "libc/nt/enum/filenotifychange.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/enum/findexinfolevels.h"
#include "libc/nt/enum/findexsearchops.h"
#include "libc/nt/errors.h"
#include "libc/nt/files.h"
#include "libc/nt/nt/file.h"
#include "libc/nt/struct/iostatusblock.h"
#include "libc/nt/struct/objectattributes.h"
#include "libc/nt/struct/unicodestring.h"
#include "libc/nt/iocp.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/filenotifyinformation.h"
#include "libc/nt/struct/overlapped.h"
#include "libc/nt/struct/win32finddata.h"
#include "libc/nt/thread.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/syslib.internal.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/at.h"
#include "libc/sysv/consts/clock.h"
#include "libc/sysv/consts/efd.h"
#include "libc/sysv/consts/f.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/in.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/s.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#include "libc/thread/thread.h"
#include "libc/time.h"
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
 * and IN_MOVED_TO with a cookie. On XNU each watch holds an O_EVTONLY
 * descriptor with an EVFILT_VNODE filter on a kqueue the thread waits
 * on: a directory is compared as soon as its entries change, and a
 * watched file's writes, attribute changes, rename and deletion are
 * reported straight from the filter, with the watch following the file
 * the way it does on Linux. Everything else, including the contents of
 * the files in a watched directory on XNU, is scanned on a timer, 200ms
 * unless COSMOPOLITAN_INOTIFY_MS says otherwise; directories with a
 * request get a safety scan every five seconds.
 *
 * What a scan can't report: IN_OPEN, IN_ACCESS and the IN_CLOSE pair have
 * no trace in a stat. A rename within a directory is paired by inode
 * number where the listing has one, so it's IN_MOVED_FROM and IN_MOVED_TO
 * with a cookie; a move between two directories is a delete and a
 * create, and on Windows a rename onto an existing name that no request
 * reported is a modify, since the listing has no inode numbers. A change
 * made and undone between two looks is never seen, and a watched file
 * replaced by rename keeps its watch except on XNU (Linux drops it).
 *
 * COSMOPOLITAN_INOTIFY_EMULATE=1 takes this path on Linux too, which is
 * how it's checked against the kernel.
 */

#define INOTIFY_MAX_WATCHES 8192   // the kernel's max_user_watches default
#define INOTIFY_MAX_QUEUED  16384  // the kernel's max_queued_events default
#define INOTIFY_INTERVAL_MS 200
#define INOTIFY_SWEEP_MS    5000  // windows: scan of the request-backed watches
#define INOTIFY_COALESCE_MS 2     // wait for the rest of a burst
#define INOTIFY_NUDGE_MS    50    // windows: a nonblocking read waits this long for a round

// the completion keys of the scanner's port: a request's overlapped
// says which, 0 is close() or InotifyWake(), this one is a reader
// asking for a round right away
#define kInotifyNudge 1
#define INOTIFY_EVENT_SIZE  sizeof(struct inotify_event)

// <sync with the xnu headers>
#define XNU_O_EVTONLY    0x00008000
#define XNU_O_CLOEXEC    0x01000000
#define XNU_F_GETPATH    50
#define XNU_MAXPATHLEN   1024
#define XNU_EVFILT_VNODE -4
#define XNU_EVFILT_USER  -10
#define XNU_NOTE_TRIGGER 0x01000000
#define XNU_EV_ADD       0x0001
#define XNU_EV_ENABLE    0x0004
#define XNU_EV_CLEAR     0x0020
#define XNU_NOTE_DELETE  0x0001
#define XNU_NOTE_WRITE   0x0002
#define XNU_NOTE_EXTEND  0x0004
#define XNU_NOTE_ATTRIB  0x0008
#define XNU_NOTE_LINK    0x0010
#define XNU_NOTE_RENAME  0x0020
#define XNU_NOTE_REVOKE  0x0040
// </sync with the xnu headers>

#define INOTIFY_NOTES                                                        \
  (XNU_NOTE_DELETE | XNU_NOTE_WRITE | XNU_NOTE_EXTEND | XNU_NOTE_ATTRIB |    \
   XNU_NOTE_LINK | XNU_NOTE_RENAME | XNU_NOTE_REVOKE)

struct KeventXnu {
  uint64_t ident;
  int16_t filter;
  uint16_t flags;
  uint32_t fflags;
  int64_t data;
  uint64_t udata;
};

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
  int64_t birth;  // creation time in seconds, or 0 where unknown
  bool isdir;
};

// a name that left or arrived in one directory during a scan, held
// until every directory of the round has been looked at, so a move
// between two watched directories is told from a delete and a create
struct InotifyPend {
  int wd;
  bool came;
  bool isdir;
  bool hint;  // the host said it was renamed, so it moved in or out
  bool done;
  int pair;   // index of the other half, or -1
  int over;   // what arrived under this name, if the file was replaced
  uint64_t ino;
  char *name;
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
  bool first;  // not sent yet, so what changed before it isn't in it
  char *name;  // a file's watch: its name in the directory watched
};

static void InotifyIoFree(struct InotifyIo *io) {
  CloseHandle(io->handle);
  free(io->name);
  free(io);
}

struct InotifyWatch {
  int wd;
  uint32_t mask;
  bool isdir;
  bool dropped;  // IN_IGNORED is queued; reaped after the scan
  bool dirty;    // the request landed or the directory changed
  uint32_t scanned;  // the round that last compared it
  int64_t listed;    // when kids was listed, in wall clock seconds
  int vfd;       // xnu: the O_EVTONLY descriptor on the kqueue, or -1
  uint64_t vdev;  // xnu: what vfd was opened on, so a descriptor the
  uint64_t vino;  // program closed and reused isn't closed again
  char *path;
  char *real;    // xnu: the canonical path, as fsevents names it
  struct InotifyIo *io;
  char *from;  // a rename whose new name hasn't been reported yet
  struct InotifyRename *renames;  // reported by the last request
  size_t nrenames;
  char **hints;  // names the host reported renamed since the last scan
  size_t nhints;
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
  int kq;         // xnu: where the vnode filters are, or -1
  bool fs;         // xnu: watched through fsevents rather than the kqueue
  bool fsrebuild;  // xnu: the stream no longer covers the watches
  void *rl;        // xnu: the scanner's run loop
  void *src;       // xnu: signaled to wake it
  void *stream;
  atomic_int *let_go;  // xnu: set by the scanner once its fds are closed
  uint32_t cookie;
  bool round;  // a scan is collecting what left and arrived
  uint32_t roundno;
  struct InotifyPend *pend;
  size_t npend;
  size_t cpend;
  bool dead;  // closed; the scanner frees the instance on its way out
  bool scanning;
  uint32_t rounds;        // scanner passes, for the nudge below
  pthread_cond_t rounded;
  bool nudged;  // xnu: a reader asked for a full look
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
  for (size_t i = 0; i < w->nhints; ++i)
    free(w->hints[i]);
  free(w->hints);
  w->hints = 0;
  w->nhints = 0;
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
    InotifyIoFree(io);
  }
}

static bool InotifyVnodeSame(struct InotifyWatch *w) {
  union metastat st;
  return __sys_fstat(w->vfd, &st) != -1 && st.xnu.st_dev == w->vdev &&
         st.xnu.st_ino == w->vino;
}

// the kqueue forgets a filter whose descriptor is closed
static void InotifyVnodeClose(struct InotifyWatch *w, bool live) {
  if (w->vfd < 0)
    return;
  if (live && InotifyVnodeSame(w))
    sys_close(w->vfd);
  w->vfd = -1;
}

static void InotifyWatchFree(struct InotifyWatch *w, bool live) {
  InotifyIoDrop(w, live);
  InotifyVnodeClose(w, live);
  InotifyRenamesFree(w);
  InotifyKidsFree(w->kids, w->nkids);
  free(w->path);
  free(w->real);
  bzero(w, sizeof(*w));
}

static void InotifyFree(struct Inotify *in, bool live) {
  for (size_t i = 0; i < in->nwatches; ++i)
    InotifyWatchFree(&in->watches[i], live);
  free(in->watches);
  for (size_t i = 0; i < in->npend; ++i)
    free(in->pend[i].name);
  free(in->pend);
  while (in->head) {
    struct InotifyRec *r = in->head;
    in->head = r->next;
    free(r);
  }
  if (in->port && live)
    CloseHandle(in->port);
  if (in->kq >= 0 && live)
    sys_close(in->kq);
  pthread_mutex_destroy(&in->lock);
  pthread_cond_destroy(&in->rounded);
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
  k->birth = IsLinux() ? 0 : st->st_birthtim.tv_sec;
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

// windows: FILE_ID_BOTH_DIR_INFO
struct InotifyNtDirInfo {
  uint32_t NextEntryOffset;
  uint32_t FileIndex;
  int64_t CreationTime;
  int64_t LastAccessTime;
  int64_t LastWriteTime;
  int64_t ChangeTime;
  int64_t EndOfFile;
  int64_t AllocationSize;
  uint32_t FileAttributes;
  uint32_t FileNameLength;
  uint32_t EaSize;
  char ShortNameLength;
  char16_t ShortName[12];
  int64_t FileId;
  char16_t FileName[];
};

// the directory's entries come in batches with names, sizes, write times
// and file ids together, where a stat per entry would open each file.
// the file id is what stat() reports as the inode number
static int InotifyListNt(const char *path, struct InotifyKid **out,
                         size_t *outn) {
  int rc = -1;
  char16_t *path16;
  if (!(path16 = malloc(PATH_MAX * sizeof(char16_t) + PATH_MAX)))
    return -1;
  char *name = (char *)(path16 + PATH_MAX);
  char16_t name16[NAME_MAX + 1];
  size_t bufsize = 65536;
  char *buf = 0;
  int64_t h = -1;
  if (__mkntpath(path, path16) < 0)
    goto Done;
  h = CreateFile(path16, kNtFileListDirectory,
                 kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete, 0,
                 kNtOpenExisting, kNtFileFlagBackupSemantics, 0);
  if (h == -1 || !(buf = malloc(bufsize)))
    goto Done;
  struct InotifyKid *kids = 0;
  size_t n = 0, cap = 0;
  int class = kNtFileIdBothDirectoryRestartInfo;
  while (GetFileInformationByHandleEx(h, class, buf, bufsize)) {
    class = kNtFileIdBothDirectoryInfo;
    for (uint32_t off = 0;;) {
      struct InotifyNtDirInfo *e = (void *)(buf + off);
      uint32_t len = e->FileNameLength / 2;
      if (len <= NAME_MAX) {
        memcpy(name16, e->FileName, len * 2);
        name16[len] = 0;
        if (tprecode16to8(name, PATH_MAX, name16).ax && strcmp(name, ".") &&
            strcmp(name, "..")) {
          struct InotifyKid *k = InotifyKidNew(&kids, &n, &cap, name);
          if (!k) {
            InotifyKidsFree(kids, n);
            goto Done;
          }
          struct timespec ts = WindowsTimeToTimeSpec(e->LastWriteTime);
          k->ino = e->FileId;
          k->birth = WindowsTimeToTimeSpec(e->CreationTime).tv_sec;
          k->mtime = ts.tv_sec;
          k->mtime_ns = ts.tv_nsec;
          k->size = e->EndOfFile;
          k->isdir = !!(e->FileAttributes & kNtFileAttributeDirectory);
          if (e->FileAttributes & kNtFileAttributeReparsePoint) {
            k->mode = 0120777;
          } else {
            k->mode =
                (k->isdir ? 040000 : 0100000) |
                ((e->FileAttributes & kNtFileAttributeReadonly) ? 0555 : 0777);
          }
        }
      }
      if (!e->NextEntryOffset)
        break;
      off += e->NextEntryOffset;
    }
  }
  if (GetLastError() != kNtErrorNoMoreFiles) {
    InotifyKidsFree(kids, n);
    goto Done;
  }
  *out = kids;
  *outn = n;
  rc = 0;
Done:
  if (h != -1)
    CloseHandle(h);
  free(buf);
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

////////////////////////////////////////////////////////////////////////////////
// xnu: fsevents, reached through the ape loader's dlopen

// <sync with the xnu headers>
#define XNU_RTLD_LAZY  1
#define XNU_RTLD_LOCAL 4
#define kFSEventStreamEventIdSinceNow          0xFFFFFFFFFFFFFFFFull
#define kFSEventStreamCreateFlagNoDefer        0x00000002
#define kFSEventStreamCreateFlagFileEvents     0x00000010
#define kFSEventStreamEventFlagMustScanSubDirs 0x00000001
#define kFSEventStreamEventFlagUserDropped     0x00000002
#define kFSEventStreamEventFlagKernelDropped   0x00000004
#define kFSEventStreamEventFlagRootChanged     0x00000020
#define kFSEventStreamEventFlagItemRemoved     0x00000200
#define kFSEventStreamEventFlagItemRenamed     0x00000800
// </sync with the xnu headers>

struct CfRunLoopSourceContext {
  long version;
  void *info;
  void *retain;
  void *release;
  void *copyDescription;
  void *equal;
  void *hash;
  void *schedule;
  void *cancel;
  void (*perform)(void *);
};

struct FsEventStreamContext {
  long version;
  void *info;
  void *retain;
  void *release;
  void *copyDescription;
};

typedef void (*FsEventCallback)(void *, void *, size_t, char **,
                                const uint32_t *, const uint64_t *);

static struct {
  bool tried;
  bool ok;
  int pid;  // CoreFoundation can't be used in a child after fork()
  void *mode;
  void *arraycallbacks;
  void *(*CFRunLoopGetCurrent)(void);
  int32_t (*CFRunLoopRunInMode)(void *, double, unsigned char);
  void (*CFRunLoopWakeUp)(void *);
  void *(*CFRunLoopSourceCreate)(void *, long, struct CfRunLoopSourceContext *);
  void (*CFRunLoopAddSource)(void *, void *, void *);
  void (*CFRunLoopRemoveSource)(void *, void *, void *);
  void (*CFRunLoopSourceSignal)(void *);
  void (*CFRelease)(void *);
  void *(*CFArrayCreate)(void *, void **, long, void *);
  void *(*CFStringCreateWithFileSystemRepresentation)(void *, const char *);
  void *(*FSEventStreamCreate)(void *, FsEventCallback,
                               struct FsEventStreamContext *, void *, uint64_t,
                               double, uint32_t);
  void (*FSEventStreamScheduleWithRunLoop)(void *, void *, void *);
  unsigned char (*FSEventStreamStart)(void *);
  void (*FSEventStreamStop)(void *);
  void (*FSEventStreamInvalidate)(void *);
  void (*FSEventStreamRelease)(void *);
} g_cf;

// only arm64 has the loader's dlopen. COSMOPOLITAN_INOTIFY_KQUEUE=1 keeps
// the kqueue, which is how that path is checked on a mac
static bool InotifyCfLoad(void) {
#ifdef __aarch64__
  static pthread_mutex_t g_cf_lock = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&g_cf_lock);
  if (!g_cf.tried) {
    g_cf.tried = true;
    const char *s = __getenv(environ, "COSMOPOLITAN_INOTIFY_KQUEUE").s;
    void *cf, *cs;
    if (IsXnuSilicon() && !(s && *s) && __syslib->__version >= 6 &&
        (cf = __syslib->__dlopen("/System/Library/Frameworks/"
                                 "CoreFoundation.framework/CoreFoundation",
                                 XNU_RTLD_LAZY | XNU_RTLD_LOCAL)) &&
        (cs = __syslib->__dlopen("/System/Library/Frameworks/"
                                 "CoreServices.framework/CoreServices",
                                 XNU_RTLD_LAZY | XNU_RTLD_LOCAL))) {
      bool ok = true;
      void **mode = __syslib->__dlsym(cf, "kCFRunLoopDefaultMode");
#define CF(lib, name) ok &= !!(*(void **)&g_cf.name = __syslib->__dlsym(lib, #name))
      CF(cf, CFRunLoopGetCurrent);
      CF(cf, CFRunLoopRunInMode);
      CF(cf, CFRunLoopWakeUp);
      CF(cf, CFRunLoopSourceCreate);
      CF(cf, CFRunLoopAddSource);
      CF(cf, CFRunLoopRemoveSource);
      CF(cf, CFRunLoopSourceSignal);
      CF(cf, CFRelease);
      CF(cf, CFArrayCreate);
      CF(cf, CFStringCreateWithFileSystemRepresentation);
      CF(cs, FSEventStreamCreate);
      CF(cs, FSEventStreamScheduleWithRunLoop);
      CF(cs, FSEventStreamStart);
      CF(cs, FSEventStreamStop);
      CF(cs, FSEventStreamInvalidate);
      CF(cs, FSEventStreamRelease);
#undef CF
      g_cf.arraycallbacks = __syslib->__dlsym(cf, "kCFTypeArrayCallBacks");
      if (ok && mode && g_cf.arraycallbacks) {
        g_cf.mode = *mode;
        g_cf.pid = getpid();
        g_cf.ok = true;
      }
    }
  }
  pthread_mutex_unlock(&g_cf_lock);
  return g_cf.ok && g_cf.pid == getpid();
#else
  return false;
#endif
}

static int (*InotifyFsgetpath(void))(char *, size_t, int32_t[2], uint64_t) {
#ifdef __aarch64__
  static bool tried;
  static int (*fsgetpath)(char *, size_t, int32_t[2], uint64_t);
  if (!tried && IsXnuSilicon()) {
    fsgetpath = __syslib->__dlsym((void *)-2, "fsgetpath");
    tried = true;
  }
  return fsgetpath;
#else
  return 0;
#endif
}

// windows: turns \\?\C:\x\y into /C/x/y and \\?\UNC\h\s into //h/s
static bool InotifyNtPath(const char16_t *p16, char *buf, size_t size) {
  char tmp[PATH_MAX];
  if (!tprecode16to8(tmp, sizeof(tmp), p16).ax)
    return false;
  char *p = tmp;
  if (!strncmp(p, "\\\\?\\", 4))
    p += 4;
  char *out = buf, *end = buf + size - 1;
  if (!strncmp(p, "UNC\\", 4)) {
    p += 3;
    *out++ = '/';
  } else if (p[0] && p[1] == ':') {
    *out++ = '/';
    *out++ = p[0];
    p += 2;
  }
  for (; *p && out < end; ++p)
    *out++ = *p == '\\' ? '/' : *p;
  *out = 0;
  return !*p;
}

// where the file with this inode number lives now: xnu asks the kernel
// by volume and inode, windows opens it by file id through a handle on
// the same volume
static bool InotifyInoPath(struct InotifyWatch *w, uint64_t ino, char *buf,
                           size_t size) {
  if (!ino)
    return false;
  if (IsXnu()) {
    int (*fsgetpath)(char *, size_t, int32_t[2], uint64_t);
    int32_t fsid[2] = {(int32_t)w->vdev, 0};
    return (fsgetpath = InotifyFsgetpath()) &&
           fsgetpath(buf, size, fsid, ino) > 0;
  }
  if (IsWindows() && w->io) {
    int64_t h;
    struct NtIoStatusBlock iosb;
    struct NtUnicodeString us = {8, 8, (char16_t *)&ino};
    struct NtObjectAttributes oa = {sizeof(oa), w->io->handle, &us, 0, 0, 0};
    if (!NtSuccess(NtCreateFile(
            &h, kNtFileReadAttributes | kNtSynchronize, &oa, &iosb, 0, 0,
            kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete,
            1 /* FILE_OPEN */,
            0x2000 /* FILE_OPEN_BY_FILE_ID */ |
                0x4000 /* FILE_OPEN_FOR_BACKUP_INTENT */,
            0, 0)))
      return false;
    char16_t p16[PATH_MAX];
    uint32_t n = GetFinalPathNameByHandle(h, p16, ARRAYLEN(p16), 0);
    CloseHandle(h);
    return n && n < ARRAYLEN(p16) && InotifyNtPath(p16, buf, size);
  }
  return false;
}

static void InotifyIoOpen(struct Inotify *, struct InotifyWatch *);

// a watched file or directory that isn't at its path anymore is looked
// up by its inode number. found elsewhere, it was moved, and the watch
// follows it as it would on linux. xnu's kqueue watches do this through
// their descriptor instead
static bool InotifyRelocate(struct Inotify *in, struct InotifyWatch *w) {
  char buf[PATH_MAX];
  struct stat st;
  if (!in->fs && !IsWindows())
    return false;
  if (!InotifyInoPath(w, w->vino, buf, sizeof(buf)) || lstat(buf, &st) ||
      st.st_ino != w->vino)
    return false;
  char *path = strdup(buf);
  char *real = in->fs ? realpath(buf, 0) : 0;
  if (!path || (in->fs && !real)) {
    free(path);
    free(real);
    return false;
  }
  free(w->path);
  free(w->real);
  w->path = path;
  w->real = real;
  in->fsrebuild = in->fs;
  if (IsWindows() && w->io && w->io->name) {
    // a file's request is on the directory it was in
    InotifyIoDrop(w, true);
    InotifyIoOpen(in, w);
  }
  InotifyEmit(in, w, IN_MOVE_SELF, 0, 0);
  return true;
}

static struct InotifyWatch *InotifyWatchByWd(struct Inotify *in, int wd);

static uint32_t InotifyCookie(struct Inotify *in) {
  if (!++in->cookie)
    ++in->cookie;
  return in->cookie;
}

// xnu: where the watched file or directory is now
static bool InotifyVnodePath(struct InotifyWatch *w) {
  char buf[XNU_MAXPATHLEN];
  if (w->vfd < 0 || __sys_fcntl(w->vfd, XNU_F_GETPATH, (uintptr_t)buf) == -1)
    return false;
  if (!strcmp(buf, w->path))
    return false;
  char *p = strdup(buf);
  if (!p)
    return false;
  free(w->path);
  w->path = p;
  return true;
}

static bool InotifyHinted(struct InotifyWatch *w, const char *name) {
  for (size_t i = 0; i < w->nhints; ++i)
    if (!strcmp(w->hints[i], name))
      return true;
  return false;
}

static int InotifyPendAdd(struct Inotify *in, struct InotifyWatch *w,
                          struct InotifyKid *k, bool came) {
  bool hint = InotifyHinted(w, k->name);
  char where[PATH_MAX];
  if (hint) {
  } else if (came) {
    // xnu's kqueue watches have nothing better to go by: a file made
    // before the directory was last looked at came from somewhere else.
    // fsevents says so itself, and windows gives a name deleted and made
    // again within 15 seconds the old file's creation time back
    hint = IsXnu() && !in->fs && k->birth && w->listed &&
           k->birth < w->listed - 1;
  } else {
    // still somewhere, so it went somewhere else
    hint = InotifyInoPath(w, k->ino, where, sizeof(where));
  }
  if (!in->round) {
    uint32_t isdir = k->isdir ? IN_ISDIR : 0;
    if (hint) {
      InotifyEmit(in, w, (came ? IN_MOVED_TO : IN_MOVED_FROM) | isdir,
                  InotifyCookie(in), k->name);
    } else {
      InotifyEmit(in, w, (came ? IN_CREATE : IN_DELETE) | isdir, 0, k->name);
    }
    return -1;
  }
  if (in->npend == in->cpend) {
    size_t n = in->cpend ? in->cpend * 2 : 16;
    struct InotifyPend *p = realloc(in->pend, n * sizeof(*p));
    if (!p)
      return -1;
    in->pend = p;
    in->cpend = n;
  }
  char *name = strdup(k->name);
  if (!name)
    return -1;
  in->pend[in->npend] = (struct InotifyPend){
      w->wd, came, k->isdir, hint, false, -1, -1, k->ino, name};
  return in->npend++;
}

static void InotifyScanDir(struct Inotify *, struct InotifyWatch *);

static void InotifyRoundPair(struct Inotify *in) {
  struct InotifyPend *p = in->pend;
  size_t n = in->npend;
  for (size_t a = 0; a < n; ++a) {
    if (!p[a].came || !p[a].ino || p[a].pair >= 0)
      continue;
    for (size_t b = 0; b < n; ++b) {
      if (!p[b].came && p[b].pair < 0 && p[b].ino == p[a].ino &&
          p[b].isdir == p[a].isdir && p[b].wd != p[a].wd) {
        p[a].pair = b;
        p[b].pair = a;
        break;
      }
    }
  }
}

static bool InotifyKidsHave(struct InotifyWatch *w, uint64_t ino) {
  for (size_t i = 0; i < w->nkids; ++i)
    if (w->kids[i].ino == ino)
      return true;
  return false;
}

// the directories of a round aren't listed at once, so a move that
// happens between two of them looks like a create in one and nothing in
// the other, or a delete in one and nothing in the other. what's left
// unpaired has the directories it could have come from or gone to
// listed again before anything is reported
static void InotifyRoundRecheck(struct Inotify *in) {
  size_t n = in->npend, scanned = 0;
  bool gone = false;
  for (size_t i = 0; i < n; ++i)
    gone |= !in->pend[i].came && in->pend[i].pair < 0 && in->pend[i].ino &&
            !in->pend[i].hint;
  for (size_t i = 0; i < in->nwatches; ++i)
    scanned += in->watches[i].scanned == in->roundno;
  for (size_t i = 0; i < in->nwatches; ++i) {
    struct InotifyWatch *w = &in->watches[i];
    if (!w->isdir || w->dropped || w->scanned != in->roundno)
      continue;
    bool again = false;
    for (size_t j = 0; j < n && !again; ++j) {
      struct InotifyPend *e = &in->pend[j];
      if (e->pair >= 0 || !e->ino || e->hint || e->wd == w->wd)
        continue;
      if (e->came ? InotifyKidsHave(w, e->ino) : gone && scanned <= 64)
        again = true;
    }
    if (again)
      InotifyScanDir(in, w);
  }
}

// the round is over. a name that left one watched directory and one that
// arrived in another with the same inode are a move between the two;
// otherwise it's a delete or a create, or a move from or to somewhere
// unwatched when the host said it was renamed
static void InotifyRoundEnd(struct Inotify *in) {
  InotifyRoundPair(in);
  for (size_t i = 0; i < in->npend; ++i) {
    if (in->pend[i].pair < 0 && in->pend[i].ino && !in->pend[i].hint) {
      InotifyRoundRecheck(in);
      InotifyRoundPair(in);
      break;
    }
  }
  struct InotifyPend *p = in->pend;
  size_t n = in->npend;
  for (size_t i = 0; i < n; ++i) {
    struct InotifyPend *e = &p[i];
    if (e->done)
      continue;
    e->done = true;
    uint32_t isdir = e->isdir ? IN_ISDIR : 0;
    struct InotifyWatch *w = InotifyWatchByWd(in, e->wd);
    if (e->pair >= 0) {
      struct InotifyPend *f = e->came ? &p[e->pair] : e;
      struct InotifyPend *t = e->came ? e : &p[e->pair];
      struct InotifyWatch *fw = InotifyWatchByWd(in, f->wd);
      struct InotifyWatch *tw = InotifyWatchByWd(in, t->wd);
      uint32_t cookie = InotifyCookie(in);
      p[e->pair].done = true;
      if (fw)
        InotifyEmit(in, fw, IN_MOVED_FROM | isdir, cookie, f->name);
      if (tw)
        InotifyEmit(in, tw, IN_MOVED_TO | isdir, cookie, t->name);
    } else if (e->over >= 0 && p[e->over].pair >= 0) {
      // overwritten by a move from another directory
    } else if (w && e->hint) {
      InotifyEmit(in, w, (e->came ? IN_MOVED_TO : IN_MOVED_FROM) | isdir,
                  InotifyCookie(in), e->name);
    } else if (w) {
      InotifyEmit(in, w, (e->came ? IN_CREATE : IN_DELETE) | isdir, 0,
                  e->name);
    }
  }
  for (size_t i = 0; i < n; ++i)
    free(p[i].name);
  in->npend = 0;
}

// an entry that left the listing, or arrived in it
struct InotifyDiff {
  struct InotifyKid *kid;
  struct InotifyDiff *pair;  // the other name of a rename
  struct InotifyDiff *twin;  // the name stayed, the file behind it didn't
};

// walks the old and new listings in step. what left and what arrived are
// told apart from renames by the requests' rename pairs, or else by the
// inode number, where the listing has one
static void InotifyScanDir(struct Inotify *in, struct InotifyWatch *w) {
  struct InotifyKid *now = 0;
  size_t n = 0;
  int64_t listed = time(0);
  if (InotifyList(w->path, &now, &n)) {
    if (errno == ENOENT || errno == ENOTDIR) {
      if (InotifyRelocate(in, w)) {
        if (!InotifyList(w->path, &now, &n))
          goto Listed;
      } else if (!InotifyVnodePath(w)) {
        InotifyEmit(in, w, IN_DELETE_SELF, 0, 0);
        InotifyDrop(in, w);
      }
    }
    InotifyRenamesFree(w);
    return;
  }
Listed:;
  struct InotifyDiff *gone, *came;
  size_t ngone = 0, ncame = 0;
  if (!(gone = malloc((w->nkids + n) * 2 * sizeof(*gone) + 1))) {
    InotifyKidsFree(now, n);
    return;
  }
  came = gone + w->nkids + n;
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
      gone[ngone++] = (struct InotifyDiff){&w->kids[i++]};
    } else if (c > 0) {
      came[ncame++] = (struct InotifyDiff){&now[j++]};
    } else {
      struct InotifyKid *o = &w->kids[i++];
      struct InotifyKid *p = &now[j++];
      uint32_t isdir = p->isdir ? IN_ISDIR : 0;
      if (o->ino != p->ino || InotifyRenameTo(w, p->name)) {
        gone[ngone] = (struct InotifyDiff){o, 0, &came[ncame]};
        came[ncame] = (struct InotifyDiff){p, 0, &gone[ngone]};
        ++ngone;
        ++ncame;
      } else {
        // a directory changes its times when its entries do, which
        // linux doesn't report on the parent
        if (!p->isdir && (o->mtime != p->mtime || o->mtime_ns != p->mtime_ns ||
                          o->size != p->size))
          InotifyEmit(in, w, IN_MODIFY, 0, p->name);
        if (o->mode != p->mode)
          InotifyEmit(in, w, IN_ATTRIB | isdir, 0, p->name);
      }
    }
  }
  if (!w->nrenames) {
    for (size_t a = 0; a < ncame; ++a) {
      if (!came[a].kid->ino)
        continue;
      for (size_t b = 0; b < ngone; ++b) {
        if (!gone[b].pair && gone[b].kid->ino == came[a].kid->ino &&
            gone[b].kid->isdir == came[a].kid->isdir) {
          gone[b].pair = &came[a];
          came[a].pair = &gone[b];
          break;
        }
      }
    }
  }
  for (size_t b = 0; b < ngone; ++b) {
    struct InotifyKid *o = gone[b].kid;
    uint32_t isdir = o->isdir ? IN_ISDIR : 0;
    struct InotifyRename *r;
    if (gone[b].pair) {
      struct InotifyKid *p = gone[b].pair->kid;
      uint32_t cookie = InotifyCookie(in);
      InotifyEmit(in, w, IN_MOVED_FROM | isdir, cookie, o->name);
      InotifyEmit(in, w, IN_MOVED_TO | isdir, cookie, p->name);
    } else if ((r = InotifyRenameFrom(w, o->name))) {
      InotifyEmit(in, w, IN_MOVED_FROM | isdir, r->cookie, o->name);
    } else if (gone[b].twin &&
               (gone[b].twin->pair || InotifyRenameTo(w, o->name))) {
      // overwritten by a rename, which reports only the rename
    } else if (!gone[b].twin) {
      InotifyPendAdd(in, w, o, false);
    } else {
      // replaced: the new file may have come from another directory
      int g = InotifyPendAdd(in, w, o, false);
      int c = InotifyPendAdd(in, w, gone[b].twin->kid, true);
      gone[b].twin->pair = gone[b].twin;  // taken care of
      if (g >= 0 && c >= 0)
        in->pend[g].over = c;
    }
  }
  for (size_t a = 0; a < ncame; ++a) {
    struct InotifyKid *p = came[a].kid;
    uint32_t isdir = p->isdir ? IN_ISDIR : 0;
    struct InotifyRename *r;
    if (came[a].pair) {
    } else if ((r = InotifyRenameTo(w, p->name))) {
      InotifyEmit(in, w, IN_MOVED_TO | isdir, r->cookie, p->name);
    } else {
      InotifyPendAdd(in, w, p, true);
    }
  }
  free(gone);
  InotifyKidsFree(w->kids, w->nkids);
  w->kids = now;
  w->nkids = n;
  w->listed = listed;
  InotifyRenamesFree(w);
}

static void InotifyScanFile(struct Inotify *in, struct InotifyWatch *w) {
  struct stat st;
  int rc = (w->mask & IN_DONT_FOLLOW) ? lstat(w->path, &st)
                                      : stat(w->path, &st);
  if ((in->fs || IsWindows()) && (rc ? errno == ENOENT || errno == ENOTDIR
                                    : st.st_ino != w->self.ino)) {
    // xnu: moved, or unlinked and maybe replaced under the same name
    if (InotifyRelocate(in, w)) {
      rc = lstat(w->path, &st);
    } else {
      InotifyEmit(in, w, IN_ATTRIB, 0, 0);
      InotifyEmit(in, w, IN_DELETE_SELF, 0, 0);
      InotifyDrop(in, w);
      return;
    }
  }
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
  w->scanned = in->roundno;
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
enum { kInotifyAll = 0, kInotifyPolled = 1, kInotifyDirty = 2 };

static bool InotifyPolled(struct InotifyWatch *w) {
  return !w->io && !(w->vfd >= 0 && !w->isdir);
}

// one round: what left one directory and arrived in another is paired
// once all of them have been looked at
static void InotifyScan(struct Inotify *in, int which) {
  in->round = true;
  if (!++in->roundno)
    ++in->roundno;
  for (size_t i = 0; i < in->nwatches; ++i) {
    struct InotifyWatch *w = &in->watches[i];
    if (which && !(((which & kInotifyPolled) && InotifyPolled(w)) ||
                   ((which & kInotifyDirty) && w->dirty)))
      continue;
    InotifyScanWatch(in, w);
  }
  InotifyRoundEnd(in);
  in->round = false;
  InotifyReap(in);
}

// xnu: what fsevents reported for one path. the watch that is the path
// or the directory holding it is compared in the scan that follows; a
// name the host says was renamed can be told from a deleted or a created
// one when nothing else in the round pairs it
static void InotifyFsEvent(struct Inotify *in, const char *path,
                           uint32_t flags) {
  bool all = flags & (kFSEventStreamEventFlagMustScanSubDirs |
                      kFSEventStreamEventFlagUserDropped |
                      kFSEventStreamEventFlagKernelDropped);
  const char *slash = strrchr(path, '/');
  size_t dirlen = slash ? slash - path : 0;
  for (size_t i = 0; i < in->nwatches; ++i) {
    struct InotifyWatch *w = &in->watches[i];
    if (w->dropped || !w->real)
      continue;
    if (all || !strcmp(path, w->real)) {
      w->dirty = true;
    } else if (w->isdir && slash && strlen(w->real) == dirlen &&
               !memcmp(path, w->real, dirlen)) {
      w->dirty = true;
      // the flags of a path pile up, so a name that was renamed into
      // place once and unlinked later says both
      if ((flags & kFSEventStreamEventFlagItemRenamed) &&
          !(flags & kFSEventStreamEventFlagItemRemoved)) {
        char **p = realloc(w->hints, (w->nhints + 1) * sizeof(*p));
        if (p) {
          w->hints = p;
          if ((p[w->nhints] = strdup(slash + 1)))
            ++w->nhints;
        }
      }
    }
  }
}

static void InotifyFsCallback(void *stream, void *info, size_t n,
                              char **paths, const uint32_t *flags,
                              const uint64_t *ids) {
  struct Inotify *in = info;
  pthread_mutex_lock(&in->lock);
  for (size_t i = 0; i < n; ++i) {
    STRACE("inotify: fsevent %#x %s", flags[i], paths[i]);
    InotifyFsEvent(in, paths[i], flags[i]);
  }
  pthread_mutex_unlock(&in->lock);
}

static void InotifyFsPerform(void *info) {
}

static void InotifyFsStop(struct Inotify *in) {
  if (!in->stream)
    return;
  g_cf.FSEventStreamStop(in->stream);
  g_cf.FSEventStreamInvalidate(in->stream);
  g_cf.FSEventStreamRelease(in->stream);
  in->stream = 0;
}

// one stream covers every watch: a directory by its own path, a file by
// the directory holding it. the stream's paths can't change, so it's
// made again when the watches do. it isn't asked to watch the roots
// themselves, which would hold a descriptor open on every directory up to
// /, but a root that's renamed or removed is still reported by its path
// and found again by its inode number
static void InotifyFsRebuild(struct Inotify *in) {
  in->fsrebuild = false;
  InotifyFsStop(in);
  void **paths = malloc((in->nwatches + 1) * sizeof(*paths));
  if (!paths)
    return;
  long n = 0;
  for (size_t i = 0; i < in->nwatches; ++i) {
    struct InotifyWatch *w = &in->watches[i];
    if (w->dropped || !w->real)
      continue;
    char buf[PATH_MAX];
    const char *root = w->real;
    if (!w->isdir) {
      const char *slash = strrchr(w->real, '/');
      size_t len = slash ? MAX(slash - w->real, 1) : 0;
      if (!len || len >= sizeof(buf))
        continue;
      memcpy(buf, w->real, len);
      buf[len] = 0;
      root = buf;
    }
    if ((paths[n] = g_cf.CFStringCreateWithFileSystemRepresentation(0, root)))
      ++n;
  }
  if (n) {
    void *array = g_cf.CFArrayCreate(0, paths, n, g_cf.arraycallbacks);
    if (array) {
      struct FsEventStreamContext ctx = {0, in};
      in->stream = g_cf.FSEventStreamCreate(
          0, InotifyFsCallback, &ctx, array, kFSEventStreamEventIdSinceNow,
          0.0,
          kFSEventStreamCreateFlagNoDefer | kFSEventStreamCreateFlagFileEvents);
      g_cf.CFRelease(array);
      if (in->stream) {
        g_cf.FSEventStreamScheduleWithRunLoop(in->stream, in->rl, g_cf.mode);
        if (!g_cf.FSEventStreamStart(in->stream)) {
          g_cf.FSEventStreamInvalidate(in->stream);
          g_cf.FSEventStreamRelease(in->stream);
          in->stream = 0;
        }
      }
    }
  }
  for (long i = 0; i < n; ++i)
    g_cf.CFRelease(paths[i]);
  free(paths);
  STRACE("inotify: fsevents stream over %ld paths: %p", n, in->stream);
}

static bool InotifyAnyDirty(struct Inotify *in) {
  for (size_t i = 0; i < in->nwatches; ++i)
    if (in->watches[i].dirty)
      return true;
  return false;
}

// xnu: the scanner runs a CoreFoundation run loop, where the stream
// delivers and where the source is signaled to wake it. a watch without
// a stream behind it falls back to the interval scan; every watch gets a
// safety scan every five seconds
static void *InotifyScannerFs(struct Inotify *in) {
  int interval = InotifyIntervalMs();
  struct CfRunLoopSourceContext ctx = {.info = in, .perform = InotifyFsPerform};
  void *rl = g_cf.CFRunLoopGetCurrent();
  void *src = g_cf.CFRunLoopSourceCreate(0, 0, &ctx);
  if (src)
    g_cf.CFRunLoopAddSource(rl, src, g_cf.mode);
  pthread_mutex_lock(&in->lock);
  in->rl = rl;
  in->src = src;
  in->fsrebuild = true;
  int64_t now = InotifyNowMs();
  int64_t sweep_due = now + INOTIFY_SWEEP_MS;
  int64_t poll_due = now + interval;
  for (;;) {
    if (in->dead)
      break;
    if (in->fsrebuild)
      InotifyFsRebuild(in);
    bool polling = !in->stream || !src;
    pthread_mutex_unlock(&in->lock);
    now = InotifyNowMs();
    int64_t due = polling ? MIN(poll_due, sweep_due) : sweep_due;
    double secs = due > now ? (due - now) / 1000. : 0;
    if (src) {
      g_cf.CFRunLoopRunInMode(g_cf.mode, secs, true);
    } else {
      struct timespec ts = timespec_frommillis(secs * 1000);
      nanosleep(&ts, 0);
    }
    // the rest of a burst, like both ends of a move between two watched
    // directories, is taken in before anything is compared
    pthread_mutex_lock(&in->lock);
    for (int i = 0; i < 50 && src && !in->dead && InotifyAnyDirty(in); ++i) {
      pthread_mutex_unlock(&in->lock);
      int32_t rc = g_cf.CFRunLoopRunInMode(g_cf.mode,
                                           INOTIFY_COALESCE_MS / 1000., true);
      pthread_mutex_lock(&in->lock);
      if (rc != 4)  // kCFRunLoopRunHandledSource
        break;
    }
    if (in->dead)
      break;
    now = InotifyNowMs();
    if (now >= sweep_due || in->nudged) {
      in->nudged = false;
      InotifyScan(in, kInotifyAll);
      sweep_due = now + INOTIFY_SWEEP_MS;
      poll_due = now + interval;
    } else if (polling && now >= poll_due) {
      InotifyScan(in, kInotifyAll);
      poll_due = now + interval;
    } else {
      InotifyScan(in, kInotifyDirty);
    }
    ++in->rounds;
    pthread_cond_broadcast(&in->rounded);
  }
  InotifyFsStop(in);
  if (src) {
    g_cf.CFRunLoopRemoveSource(rl, src, g_cf.mode);
    g_cf.CFRelease(src);
  }
  in->src = 0;
  in->rl = 0;
  if (in->let_go)
    atomic_store_explicit(in->let_go, 1, memory_order_release);
  pthread_mutex_unlock(&in->lock);
  InotifyFree(in, true);
  return 0;
}

// xnu: wakes the fsevents scanner, under the instance's lock
static bool InotifyFsWake(struct Inotify *in) {
  if (!in->src)
    return false;
  g_cf.CFRunLoopSourceSignal(in->src);
  g_cf.CFRunLoopWakeUp(in->rl);
  return true;
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

// xnu: puts a vnode filter for the watch on the kqueue. a watch that
// doesn't get one is scanned on the interval
static void InotifyVnodeOpen(struct Inotify *in, struct InotifyWatch *w) {
  if (in->kq < 0 || (w->mask & IN_DONT_FOLLOW))
    return;
  int fd = __sys_openat_nc(__dirfd2host(AT_FDCWD), w->path,
                           XNU_O_EVTONLY | XNU_O_CLOEXEC, 0);
  if (fd == -1)
    return;
  union metastat st;
  struct KeventXnu k = {fd,  XNU_EVFILT_VNODE, XNU_EV_ADD | XNU_EV_ENABLE | XNU_EV_CLEAR,
                        INOTIFY_NOTES, 0, w->wd};
  if (__sys_fstat(fd, &st) == -1 || sys_kevent(in->kq, &k, 1, 0, 0, 0) == -1) {
    sys_close(fd);
    return;
  }
  w->vfd = fd;
  w->vdev = st.xnu.st_dev;
  w->vino = st.xnu.st_ino;
}

// xnu: what a vnode filter reported. a directory is compared in the scan
// that follows the batch; a file's changes are the events themselves
static void InotifyVnodeEvent(struct Inotify *in, struct InotifyWatch *w,
                              uint32_t notes) {
  if (w->dropped)
    return;
  if (notes & XNU_NOTE_RENAME) {
    InotifyVnodePath(w);
    InotifyEmit(in, w, IN_MOVE_SELF, 0, 0);
  }
  if (w->isdir) {
    if (notes & (XNU_NOTE_WRITE | XNU_NOTE_EXTEND | XNU_NOTE_LINK))
      w->dirty = true;
  } else {
    if (notes & (XNU_NOTE_WRITE | XNU_NOTE_EXTEND))
      InotifyEmit(in, w, IN_MODIFY, 0, 0);
    if (notes & (XNU_NOTE_ATTRIB | XNU_NOTE_LINK | XNU_NOTE_DELETE))
      InotifyEmit(in, w, IN_ATTRIB, 0, 0);
  }
  if (notes & XNU_NOTE_REVOKE) {
    InotifyEmit(in, w, IN_UNMOUNT, 0, 0);
    InotifyDrop(in, w);
  } else if (notes & XNU_NOTE_DELETE) {
    // unlink() of one of several links leaves the file where it was
    union metastat st;
    if (__sys_fstat(w->vfd, &st) == -1 || !st.xnu.st_nlink) {
      InotifyEmit(in, w, IN_DELETE_SELF, 0, 0);
      InotifyDrop(in, w);
    }
  }
}

// xnu: the kqueue hands over what the vnode filters saw; the timeout is
// the interval scan, which still looks at the watches without a filter
// and at what's inside the watched directories
static void *InotifyScannerKq(struct Inotify *in) {
  int interval = InotifyIntervalMs();
  int64_t poll_due = InotifyNowMs() + interval;
  for (;;) {
    struct KeventXnu evs[16];
    int64_t now = InotifyNowMs();
    int64_t ms = poll_due > now ? poll_due - now : 0;
    struct timespec ts = {ms / 1000, ms % 1000 * 1000000};
    int n = sys_kevent(in->kq, 0, 0, evs, ARRAYLEN(evs), &ts);
    int total = 0;
    pthread_mutex_lock(&in->lock);
    if (in->dead)
      break;
    // what a burst reports, like both ends of a move between two
    // watched directories, is taken in before the directories are
    // compared, so it lands in one round
    while (n > 0) {
      for (int i = 0; i < n; ++i) {
        if (evs[i].filter != XNU_EVFILT_VNODE)
          continue;
        struct InotifyWatch *w = InotifyWatchByWd(in, evs[i].udata);
        if (w && w->vfd == (int)evs[i].ident)
          InotifyVnodeEvent(in, w, evs[i].fflags);
      }
      total += n;
      if (total > 256)
        break;
      struct timespec quiet = {0, INOTIFY_COALESCE_MS * 1000000};
      pthread_mutex_unlock(&in->lock);
      n = sys_kevent(in->kq, 0, 0, evs, ARRAYLEN(evs), &quiet);
      pthread_mutex_lock(&in->lock);
      if (in->dead)
        break;
    }
    if (in->dead)
      break;
    now = InotifyNowMs();
    if (in->nudged) {
      in->nudged = false;
      InotifyScan(in, kInotifyAll);
      poll_due = now + interval;
    } else if (now >= poll_due) {
      InotifyScan(in, kInotifyPolled | kInotifyDirty);
      poll_due = now + interval;
    } else if (total) {
      InotifyScan(in, kInotifyDirty);
    } else {
      InotifyReap(in);
    }
    ++in->rounds;
    pthread_cond_broadcast(&in->rounded);
    pthread_mutex_unlock(&in->lock);
  }
  // close() waits for the descriptors to go, as linux frees them
  for (size_t i = 0; i < in->nwatches; ++i)
    InotifyVnodeClose(&in->watches[i], true);
  sys_close(in->kq);
  in->kq = -1;
  if (in->let_go)
    atomic_store_explicit(in->let_go, 1, memory_order_release);
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
  char *name = 0, dir[PATH_MAX];
  const char *path = w->path;
  if (!w->isdir) {
    // a file is watched through the directory holding it
    const char *slash = strrchr(w->path, '/');
    size_t len = slash ? slash - w->path : 0;
    if (len >= sizeof(dir) || !(name = strdup(slash ? slash + 1 : w->path)))
      return;
    memcpy(dir, w->path, len);
    strcpy(dir + len, slash ? (len ? "" : "/") : ".");
    path = dir;
  }
  if (!(path16 = malloc(PATH_MAX * sizeof(char16_t)))) {
    free(name);
    return;
  }
  if (__mkntpath(path, path16) >= 0)
    h = CreateFile(path16, kNtFileListDirectory,
                   kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete,
                   0, kNtOpenExisting,
                   kNtFileFlagBackupSemantics | kNtFileFlagOverlapped, 0);
  free(path16);
  if (h == -1) {
    free(name);
    return;
  }
  struct InotifyIo *io = calloc(1, sizeof(*io));
  if (!io || CreateIoCompletionPort(h, in->port, 0, 0) != in->port) {
    CloseHandle(h);
    free(name);
    free(io);
    return;
  }
  io->handle = h;
  io->name = name;
  io->wd = w->wd;
  io->issue = true;
  io->first = true;
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
    if (io->first) {
      // the listing was taken when the watch was added
      io->first = false;
      w->dirty = true;
    }
    STRACE("inotify: wd %d request sent", w->wd);
  } else {
    STRACE("inotify: wd %d request refused% m; scanning it instead", w->wd);
    InotifyIoFree(io);
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

// windows: whether a file's request says anything about the file
static bool InotifyIoNames(struct InotifyIo *io, uint32_t bytes) {
  char16_t name16[NAME_MAX + 1];
  char name[NAME_MAX * 3 + 1];
  for (uint32_t off = 0; off + sizeof(struct NtFileNotifyInformation) <= bytes;) {
    struct NtFileNotifyInformation *fni = (void *)(io->buf + off);
    uint32_t n = fni->FileNameLength / 2;
    if (n <= NAME_MAX && off + sizeof(*fni) + fni->FileNameLength <= bytes) {
      memcpy(name16, fni->FileName, n * 2);
      name16[n] = 0;
      if (tprecode16to8(name, sizeof(name), name16).ax &&
          !strcasecmp(name, io->name))
        return true;
    }
    if (!fni->NextEntryOffset)
      break;
    off += fni->NextEntryOffset;
  }
  return false;
}

static void InotifyIoLanded(struct Inotify *in, struct InotifyLanded *l) {
  struct InotifyIo *io = l->io;
  io->pending = false;
  --in->inflight;
  STRACE("inotify: wd %d request landed with %u bytes, error %u", io->wd,
         l->bytes, l->err);
  struct InotifyWatch *w = io->dead ? 0 : InotifyWatchByWd(in, io->wd);
  if (!w) {
    InotifyIoFree(io);
    return;
  }
  if (io->name && !l->err && l->bytes && !InotifyIoNames(io, l->bytes)) {
    // something else in the directory holding a watched file
    io->issue = true;
    return;
  }
  w->dirty = true;
  if (!l->err) {
    // zero bytes is the buffer having overflowed, and the scan covers it
    if (l->bytes && !io->name)
      InotifyIoParse(in, w, l->bytes);
    io->issue = true;
  } else if (l->err == kNtErrorNotifyEnumDir) {
    io->issue = true;
  } else {
    // the directory went away or the request stopped being answered;
    // the interval scan takes it from here
    InotifyIoFree(io);
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
    // the rest of a burst is waited for in milliseconds, which would be
    // the scheduler's 15ms tick otherwise
    bool fast = (ok || ov) && _weaken(__nt_fast_tick);
    if (fast)
      _weaken(__nt_fast_tick)(true);
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
          if (key == kInotifyNudge)
            break;  // a reader is waiting on this round
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
      if (in->dead) {
        if (fast)
          _weaken(__nt_fast_tick)(false);
        goto Dead;
      }
      for (int i = 0; i < n; ++i)
        InotifyIoLanded(in, &landed[i]);
      if (n || woke)
        InotifyIssue(in);
      pthread_mutex_unlock(&in->lock);
      total += n;
      // the gathering above ended on a quiet moment, unless it ran out
      // of room, in which case there's more to take right away
      if (n < ARRAYLEN(landed))
        break;
      ov = 0;
      ok = GetQueuedCompletionStatus(in->port, &bytes, &key, &ov, 0);
      if (!ok && !ov)
        break;
    }
    if (fast)
      _weaken(__nt_fast_tick)(false);
    pthread_mutex_lock(&in->lock);
    if (in->dead)
      goto Dead;
    now = InotifyNowMs();
    if (now >= sweep_due) {
      InotifyScan(in, kInotifyAll);
      sweep_due = now + INOTIFY_SWEEP_MS;
      poll_due = now + interval;
    } else if (now >= poll_due) {
      InotifyScan(in, kInotifyPolled | kInotifyDirty);
      poll_due = now + interval;
    } else if (total || InotifyAnyDirty(in)) {
      // including a watch whose first request just went out, whose
      // directory may have changed before it did
      InotifyScan(in, kInotifyDirty);
    }
    InotifyIssue(in);  // a watch that followed its file has a new request
    ++in->rounds;
    pthread_cond_broadcast(&in->rounded);
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
      InotifyIoFree(io);
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
  if (in->fs && InotifyCfLoad())
    return InotifyScannerFs(in);
  if (in->kq >= 0)
    return InotifyScannerKq(in);
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
  pthread_cond_init(&in->rounded, 0);
  in->fd = fd;
  in->refs = 1;
  in->next_wd = 1;
  in->tail = &in->head;
  in->kq = -1;
  if (IsXnu() && InotifyCfLoad()) {
    in->fs = true;
  } else if (IsXnu() && (in->kq = sys_kqueue()) != -1) {
    // the user event is how close() wakes the scanner
    struct KeventXnu k = {0, XNU_EVFILT_USER, XNU_EV_ADD | XNU_EV_CLEAR};
    __sys_fcntl(in->kq, F_SETFD, FD_CLOEXEC);
    if (sys_kevent(in->kq, &k, 1, 0, 0, 0) == -1) {
      sys_close(in->kq);
      in->kq = -1;
    }
  }
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
  if (isdir) {
    w->listed = time(0);
    InotifyList(path, &w->kids, &w->nkids);
  }
  w->vfd = -1;
  w->vdev = st.st_dev;
  w->vino = st.st_ino;
  if (IsWindows() && in->port)
    InotifyIoOpen(in, w);
  InotifyVnodeOpen(in, w);
  if (in->fs) {
    w->real = realpath(path, 0);
    w->vdev = st.st_dev;
    w->vino = st.st_ino;
    in->fsrebuild = true;
    InotifyFsWake(in);
  }
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
    if (in->fs) {
      in->fsrebuild = true;
      InotifyFsWake(in);
    }
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
// linux queues a change as it happens; here the scanner does it a
// little later, so a nonblocking read that finds nothing asks for a
// round and waits for it, within reason, before answering EAGAIN. on
// windows the round takes in what the requests reported; on xnu, where
// fsevents has its own latency, it's a look at every watch
static bool InotifyNudge(struct Inotify *in) {
  pthread_mutex_lock(&in->lock);
  if (!InotifyScanning(in)) {
    pthread_mutex_unlock(&in->lock);
    return false;
  }
  uint32_t round = in->rounds;
  bool woke = false;
  if (IsWindows() && in->port) {
    woke = PostQueuedCompletionStatus(in->port, 0, kInotifyNudge, 0);
  } else if (in->fs && in->src) {
    in->nudged = true;
    woke = InotifyFsWake(in);
  } else if (in->kq >= 0) {
    struct KeventXnu k = {0, XNU_EVFILT_USER, 0, XNU_NOTE_TRIGGER};
    in->nudged = true;
    woke = sys_kevent(in->kq, &k, 1, 0, 0, 0) != -1;
  }
  if (!woke) {
    pthread_mutex_unlock(&in->lock);
    return false;
  }
  struct timespec deadline =
      timespec_add(timespec_real(), timespec_frommillis(INOTIFY_NUDGE_MS));
  while (in->rounds == round && !in->dead)
    if (pthread_cond_timedwait(&in->rounded, &in->lock, &deadline))
      break;
  bool rounded = in->rounds != round;
  pthread_mutex_unlock(&in->lock);
  return rounded;
}

ssize_t __inotify_read(int fd, struct Fd *f, void *buf, size_t size) {
  ssize_t rc;
  sigset_t m = 0;
  bool nudged = false;
  struct Inotify *in = f->inotify;
  if (IsWindows())
    m = __sig_block();
  for (;;) {
    if ((rc = InotifyTake(in, fd, f, buf, size)))
      break;
    if (f->flags & O_NONBLOCK) {
      if (!nudged && (nudged = true, InotifyNudge(in)))
        continue;
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
  atomic_int let_go = 0;
  bool wait = false;
  if (scanning) {
    // the scanner frees the instance once it sees this, so it's woken
    // before the lock goes
    if (IsWindows() && in->port) {
      PostQueuedCompletionStatus(in->port, 0, 0, 0);
    } else if (in->fs && in->src) {
      in->let_go = &let_go;
      wait = InotifyFsWake(in);
    } else if (in->kq >= 0) {
      struct KeventXnu k = {0, XNU_EVFILT_USER, 0, XNU_NOTE_TRIGGER};
      in->let_go = &let_go;
      wait = sys_kevent(in->kq, &k, 1, 0, 0, 0) != -1;
    }
  }
  pthread_mutex_unlock(&in->lock);
  if (!scanning) {
    InotifyFree(in, live);
  } else if (wait) {
    // the trigger is queued, so the scanner is bound to come by; it
    // writes to let_go, which is why there's no giving up early
    struct timespec ms = {0, 1000000};
    while (!atomic_load_explicit(&let_go, memory_order_acquire))
      nanosleep(&ms, 0);
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

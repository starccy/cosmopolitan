#include "libc/calls/fifo.internal.h"
#include "libc/calls/internal.h"
#include "libc/calls/state.internal.h"
#include "libc/calls/struct/sigset.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/cosmotime.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/fds.h"
#include "libc/intrin/weaken.h"
#include "libc/nt/createfile.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/fileflagandattributes.h"
#include "libc/nt/enum/fileinfobyhandleclass.h"
#include "libc/nt/enum/fileinformationclass.h"
#include "libc/nt/enum/filemapflags.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/enum/fsctl.h"
#include "libc/nt/enum/io.h"
#include "libc/nt/enum/pageflags.h"
#include "libc/nt/enum/processaccess.h"
#include "libc/nt/errors.h"
#include "libc/nt/files.h"
#include "libc/nt/ipc.h"
#include "libc/nt/memory.h"
#include "libc/nt/nt/file.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/byhandlefileinformation.h"
#include "libc/nt/struct/fileattributetaginformation.h"
#include "libc/nt/struct/filepipelocalinformation.h"
#include "libc/nt/struct/iostatusblock.h"
#include "libc/nt/synchronization.h"
#include "libc/runtime/runtime.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#if SupportsWindows()

// A fifo on windows is a file carrying wsl's fifo reparse tag. Opening
// it hands out one end of a named pipe, so i/o, poll and native children
// see an ordinary pipe and the kernel tells end of file and broken pipe.
// Each fifo has a registry in shared memory, named after the file's
// volume and id, listing which process holds which end of which pipe
// ("generation"); an open duplicates its end from one of them. When the
// other side isn't there yet, the opener makes a new pipe and parks the
// other end in the registry, held by itself until a counterpart takes it
// over. Registry entries can go stale (a crash, an execve), so every
// duplicate is checked against the pipe's name and end before use.

#define FIFO_SLOTS  1024
#define FIFO_W      1  // a write end, else a read end
#define FIFO_PARKED 2  // held for whoever opens the other side
#define FIFO_SWAP   4  // parked for readers at end of file to move to
#define FIFO_KIND   (FIFO_W | FIFO_PARKED)

#define kNtPipeClosingState 4

#define MAKEDEV(major, minor) ((uint64_t)(major) << 32 | (minor))

struct FifoSlot {
  uint32_t pid;
  uint32_t gen;
  int64_t handle;
  uint32_t flags;
};

struct FifoReg {
  uint32_t gen;
  uint32_t rjoin;  // the last generation a reader came to
  uint32_t wjoin;  // the last generation a writer came to
  struct FifoSlot slot[FIFO_SLOTS];
};

struct Fifo {
  struct Fifo *next;
  int refs;
  uint32_t vol;
  uint64_t id;
  int64_t mutex;
  int64_t sect;
};

// fifos this process has open, in .bss so that fork() copies them
#define FIFO_OPEN 64

static struct {
  atomic_int lock;
  struct Fifo *list;
  struct Fifo pool[FIFO_OPEN];
} g_fifo;

textwindows static struct Fifo *fifo_alloc(void) {
  for (int i = 0; i < FIFO_OPEN; ++i)
    if (!g_fifo.pool[i].refs && !g_fifo.pool[i].mutex)
      return g_fifo.pool + i;
  return 0;
}

textwindows static void fifo_list_lock(void) {
  while (atomic_exchange_explicit(&g_fifo.lock, 1, memory_order_acquire))
    SleepEx(0, false);
}

textwindows static void fifo_list_unlock(void) {
  atomic_store_explicit(&g_fifo.lock, 0, memory_order_release);
}

textwindows static char16_t *fifo_hex(char16_t *p, uint64_t x, int digits) {
  for (int i = digits; i--;)
    *p++ = "0123456789abcdef"[(x >> (i * 4)) & 15];
  return p;
}

// writes `<prefix>cosmo-fifo-<vol>-<id><suffix>`, then the generation
// when it's nonzero
textwindows static void fifo_name(char16_t *buf, const char16_t *prefix, struct Fifo *fo,
                      const char16_t *suffix, uint32_t gen) {
  char16_t *p = buf;
  while (*prefix)
    *p++ = *prefix++;
  for (const char16_t *s = u"cosmo-fifo-"; *s;)
    *p++ = *s++;
  p = fifo_hex(p, fo->vol, 8);
  *p++ = '-';
  p = fifo_hex(p, fo->id, 16);
  while (*suffix)
    *p++ = *suffix++;
  if (gen) {
    *p++ = '-';
    p = fifo_hex(p, gen, 8);
  }
  *p = 0;
}

textwindows static struct Fifo *fifo_get(uint32_t vol, uint64_t id) {
  struct Fifo *fo;
  fifo_list_lock();
  for (fo = g_fifo.list; fo; fo = fo->next)
    if (fo->vol == vol && fo->id == id) {
      ++fo->refs;
      fifo_list_unlock();
      return fo;
    }
  if (!(fo = fifo_alloc())) {
    fifo_list_unlock();
    enfile();
    return 0;
  }
  fo->mutex = -1;  // claimed
  fifo_list_unlock();
  fo->vol = vol;
  fo->id = id;
  fo->refs = 1;
  char16_t name[64];
  fifo_name(name, u"Local\\", fo, u"-m", 0);
  if (!(fo->mutex = CreateMutex(&kNtIsInheritable, false, name))) {
    __winerr();
    bzero(fo, sizeof(*fo));
    return 0;
  }
  fifo_name(name, u"Local\\", fo, u"-r", 0);
  if (!(fo->sect = CreateFileMapping(-1, &kNtIsInheritable, kNtPageReadwrite, 0,
                                     sizeof(struct FifoReg), name))) {
    __winerr();
    CloseHandle(fo->mutex);
    bzero(fo, sizeof(*fo));
    return 0;
  }
  fifo_list_lock();
  struct Fifo *other;
  for (other = g_fifo.list; other; other = other->next)
    if (other->vol == vol && other->id == id)
      break;
  if (other) {
    ++other->refs;
    fifo_list_unlock();
    CloseHandle(fo->sect);
    CloseHandle(fo->mutex);
    bzero(fo, sizeof(*fo));
    return other;
  }
  fo->next = g_fifo.list;
  g_fifo.list = fo;
  fifo_list_unlock();
  return fo;
}

textwindows static struct FifoReg *fifo_lock(struct Fifo *fo) {
  uint32_t wr = WaitForSingleObject(fo->mutex, -1u);
  if (wr != 0 && wr != 0x80) {  // WAIT_ABANDONED: a holder died
    __winerr();
    return 0;
  }
  struct FifoReg *reg;
  if (!(reg = MapViewOfFileEx(fo->sect, kNtFileMapWrite, 0, 0,
                              sizeof(struct FifoReg), 0))) {
    __winerr();
    ReleaseMutex(fo->mutex);
    return 0;
  }
  return reg;
}

textwindows static void fifo_unlock(struct Fifo *fo, struct FifoReg *reg) {
  UnmapViewOfFile(reg);
  ReleaseMutex(fo->mutex);
}

// a handle's pipe generation, 0 when it isn't one of a fifo's pipes
textwindows static uint32_t fifo_gen_of(int64_t h, uint32_t *vol, uint64_t *id) {
  struct {
    uint32_t n;
    char16_t s[64];
  } ni;
  if (!GetFileInformationByHandleEx(h, kNtFileNameInfo, &ni, sizeof(ni)))
    return 0;
  static const char16_t kPrefix[] = u"\\cosmo-fifo-";
  int n = ni.n / sizeof(char16_t), k = ARRAYLEN(kPrefix) - 1;
  if (n != k + 8 + 1 + 16 + 1 + 8 || memcmp(ni.s, kPrefix, k * 2))
    return 0;
  uint64_t parts[3] = {0};
  int widths[3] = {8, 16, 8}, at = k;
  for (int j = 0; j < 3; ++j) {
    for (int i = 0; i < widths[j]; ++i) {
      int c = ni.s[at++];
      if (c >= '0' && c <= '9')
        parts[j] = parts[j] << 4 | (c - '0');
      else if (c >= 'a' && c <= 'f')
        parts[j] = parts[j] << 4 | (c - 'a' + 10);
      else
        return 0;
    }
    if (j < 2 && ni.s[at++] != '-')
      return 0;
  }
  if (vol)
    *vol = parts[0];
  if (id)
    *id = parts[1];
  return parts[2];
}

textwindows static bool fifo_is_write_end(int64_t h) {
  uint32_t fl = 0;
  GetNamedPipeInfo(h, &fl, 0, 0, 0);
  return !(fl & 1);  // PIPE_SERVER_END
}

textwindows static bool fifo_check(int64_t h, struct Fifo *fo, uint32_t gen, bool w) {
  uint32_t vol;
  uint64_t id;
  return fifo_gen_of(h, &vol, &id) == gen && vol == fo->vol && id == fo->id &&
         fifo_is_write_end(h) == w;
}

textwindows static int fifo_state(int64_t h) {
  struct NtFilePipeLocalInformation pi;
  struct NtIoStatusBlock io;
  if (NtQueryInformationFile(h, &io, &pi, sizeof(pi),
                             kNtFilePipeLocalInformation))
    return -1;
  return pi.NamedPipeState;
}

// a duplicate of the first good entry whose flags match `want` under
// `mask`, in generation `gen` or in any when it's 0. `take` moves the
// handle over, closing it in its holder. -1 when there is none
textwindows static int64_t fifo_fetch(struct FifoReg *reg, struct Fifo *fo, uint32_t gen,
                          uint32_t want, uint32_t mask, bool take) {
  uint32_t self = GetCurrentProcessId();
  for (int i = 0; i < FIFO_SLOTS; ++i) {
    struct FifoSlot *s = reg->slot + i;
    if (!s->pid || (gen && s->gen != gen) || (s->flags & mask) != want)
      continue;
    int64_t proc;
    if (s->pid == self) {
      proc = GetCurrentProcess();
    } else if (!(proc = OpenProcess(kNtProcessDupHandle, false, s->pid))) {
      if (GetLastError() != kNtErrorAccessDenied)
        s->pid = 0;
      continue;
    }
    int64_t h;
    bool ok = DuplicateHandle(proc, s->handle, GetCurrentProcess(), &h, 0, true,
                              kNtDuplicateSameAccess);
    if (ok && !fifo_check(h, fo, s->gen, s->flags & FIFO_W)) {
      CloseHandle(h);
      ok = false;
    }
    if (ok && take) {
      if (s->pid == self)
        CloseHandle(s->handle);
      else
        DuplicateHandle(proc, s->handle, 0, 0, 0, false,
                        kNtDuplicateCloseSource);
    }
    if (s->pid != self)
      CloseHandle(proc);
    if (!ok || take)
      s->pid = 0;
    if (ok)
      return h;
  }
  return -1;
}

textwindows static bool fifo_live(struct FifoReg *reg, struct Fifo *fo, uint32_t gen,
                      uint32_t want, uint32_t mask) {
  int64_t h = fifo_fetch(reg, fo, gen, want, mask, false);
  if (h == -1)
    return false;
  CloseHandle(h);
  return true;
}

textwindows static int fifo_add_for(struct FifoReg *reg, uint32_t pid,
                                    uint32_t gen, int64_t h, uint32_t flags) {
  for (int i = 0; i < FIFO_SLOTS; ++i) {
    struct FifoSlot *s = reg->slot + i;
    if (!s->pid) {
      s->gen = gen;
      s->handle = h;
      s->flags = flags;
      s->pid = pid;
      return 0;
    }
  }
  return enfile();
}

textwindows static int fifo_add(struct FifoReg *reg, uint32_t gen, int64_t h,
                                uint32_t flags) {
  return fifo_add_for(reg, GetCurrentProcessId(), gen, h, flags);
}

// parks the read end of a new pipe with one of the readers of `g`, who
// are at end of file, so that what's written meanwhile stays in the pipe
// as long as they're around, whoever wrote it
textwindows static int fifo_park_with_reader(struct FifoReg *reg,
                                             struct Fifo *fo, uint32_t g,
                                             uint32_t gen, int64_t park) {
  uint32_t self = GetCurrentProcessId();
  for (int i = 0; i < FIFO_SLOTS; ++i) {
    struct FifoSlot *s = reg->slot + i;
    if (!s->pid || s->pid == self || s->gen != g || (s->flags & FIFO_KIND))
      continue;
    int64_t proc, h;
    if (!(proc = OpenProcess(kNtProcessDupHandle, false, s->pid)))
      continue;
    bool ok = DuplicateHandle(GetCurrentProcess(), park, proc, &h, 0, false,
                              kNtDuplicateSameAccess);
    CloseHandle(proc);
    if (!ok)
      continue;
    if (fifo_add_for(reg, s->pid, gen, h, FIFO_PARKED | FIFO_SWAP) == -1)
      return -1;
    CloseHandle(park);
    return 0;
  }
  return fifo_add(reg, gen, park, FIFO_PARKED | FIFO_SWAP);
}

textwindows static void fifo_del(struct FifoReg *reg, int64_t h) {
  uint32_t self = GetCurrentProcessId();
  for (int i = 0; i < FIFO_SLOTS; ++i)
    if (reg->slot[i].pid == self && reg->slot[i].handle == h)
      reg->slot[i].pid = 0;
}

// lets go of what this process parked, then of the registry
textwindows static void fifo_put(struct Fifo *fo) {
  fifo_list_lock();
  bool last = !--fo->refs;
  if (last) {
    struct Fifo **pp;
    for (pp = &g_fifo.list; *pp != fo; pp = &(*pp)->next) {
    }
    *pp = fo->next;
  }
  fifo_list_unlock();
  if (!last)
    return;
  struct FifoReg *reg;
  if ((reg = fifo_lock(fo))) {
    uint32_t self = GetCurrentProcessId();
    for (int i = 0; i < FIFO_SLOTS; ++i) {
      struct FifoSlot *s = reg->slot + i;
      if (s->pid == self && (s->flags & FIFO_PARKED)) {
        CloseHandle(s->handle);
        s->pid = 0;
      }
    }
    fifo_unlock(fo, reg);
  }
  CloseHandle(fo->sect);
  CloseHandle(fo->mutex);
  bzero(fo, sizeof(*fo));
}

// a new generation: both ends of a new pipe, the read end in `*r` and
// the write end in `*w`, inheritable as asked
textwindows static uint32_t fifo_create(struct Fifo *fo, struct FifoReg *reg, int64_t *r,
                            int64_t *w, bool rinherit, bool winherit) {
  uint32_t gen = ++reg->gen;
  if (!gen)
    gen = ++reg->gen;
  char16_t name[96];
  fifo_name(name, u"\\\\.\\pipe\\", fo, u"", gen);
  if ((*r = CreateNamedPipe(name, kNtPipeAccessInbound | kNtFileFlagOverlapped,
                            kNtPipeTypeByte | kNtPipeReadmodeByte, 1, 65536,
                            65536, 0, rinherit ? &kNtIsInheritable : 0)) ==
      -1) {
    __winerr();
    return 0;
  }
  if ((*w = CreateFile(
           name, kNtGenericWrite | kNtFileReadAttributes,
           kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete,
           winherit ? &kNtIsInheritable : 0, kNtOpenExisting,
           kNtFileFlagOverlapped, 0)) == -1) {
    __winerr();
    CloseHandle(*r);
    return 0;
  }
  return gen;
}

textwindows static struct Fifo *fifo_adopt(struct Fd *f) {
  if (f->fifo)
    return f->fifo;
  uint32_t vol, gen;
  uint64_t id;
  if (!(gen = fifo_gen_of(f->handle, &vol, &id)))
    return 0;
  struct Fifo *fo;
  if (!(fo = fifo_get(vol, id)))
    return 0;
  struct FifoReg *reg;
  if ((reg = fifo_lock(fo))) {
    fifo_add(reg, gen, f->handle, fifo_is_write_end(f->handle) ? FIFO_W : 0);
    if (f->fifow)
      fifo_add(reg, fifo_gen_of(f->fifow, 0, 0), f->fifow, FIFO_W);
    fifo_unlock(fo, reg);
  }
  f->fifo = fo;
  return fo;
}

textwindows int __mkfifo_nt(int dirfd, const char *path, unsigned mode) {
  char16_t path16[PATH_MAX];
  if (__mkntpathat(dirfd, path, path16) == -1)
    return -1;
  int64_t h = CreateFile(path16, kNtGenericRead | kNtGenericWrite, 0, 0,
                         kNtCreateNew,
                         kNtFileAttributeNormal | kNtFileFlagOpenReparsePoint,
                         0);
  if (h == -1)
    return __fix_enotdir(__winerr(), path16);
  struct {
    uint32_t tag;
    uint16_t len, reserved;
  } rd = {kNtIoReparseTagLxFifo, 0, 0};
  uint32_t br;
  bool ok = DeviceIoControl(h, kNtFsctlSetReparsePoint, &rd, sizeof(rd), 0, 0,
                            &br, 0);
  int e = ok ? 0 : __winerr();
  CloseHandle(h);
  if (!ok) {
    DeleteFile(path16);
    return e;
  }
  return 0;
}

textwindows bool __fifo_path_nt(const char16_t *path16) {
  int64_t h = CreateFile(
      path16, kNtFileReadAttributes,
      kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete, 0,
      kNtOpenExisting, kNtFileFlagOpenReparsePoint | kNtFileFlagBackupSemantics,
      0);
  if (h == -1)
    return false;
  struct NtFileAttributeTagInformation tag;
  bool ok = GetFileInformationByHandleEx(h, kNtFileAttributeTagInfo, &tag,
                                         sizeof(tag));
  CloseHandle(h);
  return ok && (tag.FileAttributes & kNtFileAttributeReparsePoint) &&
         tag.ReparseTag == kNtIoReparseTagLxFifo;
}

// the reader waits for a writer, the writer for a reader, who may have
// come and gone already. returns 1 once one came, 2 when the parked end
// was given up instead and the open starts over
textwindows static int fifo_ready(struct FifoReg *reg, struct Fifo *fo,
                                  uint32_t gen, bool writer) {
  if ((writer ? reg->rjoin : reg->wjoin) >= gen)
    return 1;
  if (writer ? !fifo_live(reg, fo, gen, FIFO_PARKED, FIFO_KIND | FIFO_SWAP)
             : !fifo_live(reg, fo, gen, FIFO_W | FIFO_PARKED, FIFO_KIND))
    return 2;
  return 0;
}

textwindows int64_t __fifo_open_nt(const char16_t *path16, uint32_t flags,
                                   sigset_t waitmask, struct Fd *f) {
  int64_t fh = CreateFile(
      path16, kNtFileReadAttributes,
      kNtFileShareRead | kNtFileShareWrite | kNtFileShareDelete, 0,
      kNtOpenExisting, kNtFileFlagOpenReparsePoint | kNtFileFlagBackupSemantics,
      0);
  if (fh == -1)
    return __winerr();
  struct NtByHandleFileInformation wst;
  bool ok = GetFileInformationByHandle(fh, &wst);
  CloseHandle(fh);
  if (!ok)
    return __winerr();
  if (flags & O_DIRECTORY)
    return enotdir();
  struct Fifo *fo;
  if (!(fo = fifo_get(wst.dwVolumeSerialNumber,
                      (wst.nFileIndexHigh + 0ull) << 32 | wst.nFileIndexLow)))
    return -1;
  int acc = flags & O_ACCMODE;
  bool nonblock = flags & O_NONBLOCK;

Restart:;
  struct FifoReg *reg;
  if (!(reg = fifo_lock(fo))) {
    fifo_put(fo);
    return -1;
  }
  uint32_t g = reg->gen, gen = 0;
  int64_t r = -1, w = -1, park = -1;
  int wait = 0;  // 1: reader waits for a writer, 2: writer for a reader
  int rc = 0;
  if (acc == O_RDONLY) {
    if (g &&
        (r = fifo_fetch(reg, fo, g, FIFO_PARKED, FIFO_KIND, true)) != -1) {
      gen = reg->rjoin = g;  // a writer was waiting for us
    } else if (g && (r = fifo_fetch(reg, fo, g, 0, FIFO_KIND, false)) != -1 &&
               fifo_state(r) != kNtPipeClosingState) {
      gen = g;
      if (!fifo_live(reg, fo, g, FIFO_W, FIFO_KIND))
        wait = 1;  // other readers wait for a writer too
    } else {
      if (r != -1)
        CloseHandle(r);
      if ((gen = fifo_create(fo, reg, &r, &park, true, false)))
        rc = fifo_add(reg, gen, park, FIFO_W | FIFO_PARKED);
      else
        rc = -1;
      wait = 1;
    }
    if (!rc)
      rc = fifo_add(reg, gen, r, 0);
  } else if (acc == O_WRONLY) {
    if (g && (w = fifo_fetch(reg, fo, g, FIFO_W | FIFO_PARKED, FIFO_KIND,
                             true)) != -1) {
      gen = reg->wjoin = g;  // readers were waiting for us
    } else if (g && fifo_live(reg, fo, g, 0, FIFO_KIND)) {
      if ((w = fifo_fetch(reg, fo, g, FIFO_W, FIFO_KIND, false)) != -1 &&
          fifo_state(w) != kNtPipeClosingState) {
        gen = g;
      } else {
        // the readers are at end of file since the writers left. they
        // move to a new pipe on their next read, see __fifo_read_nt()
        if (w != -1)
          CloseHandle(w);
        if ((gen = fifo_create(fo, reg, &park, &w, false, true))) {
          rc = fifo_park_with_reader(reg, fo, g, gen, park);
          park = -1;
        } else {
          rc = -1;
        }
      }
    } else if (nonblock) {
      fifo_unlock(fo, reg);
      fifo_put(fo);
      return enxio();
    } else if (g && fifo_live(reg, fo, g, FIFO_PARKED,
                              FIFO_KIND | FIFO_SWAP) &&
               (w = fifo_fetch(reg, fo, g, FIFO_W, FIFO_KIND, false)) != -1) {
      gen = g;  // other writers wait for a reader too
      wait = 2;
    } else {
      if ((gen = fifo_create(fo, reg, &park, &w, false, true)))
        rc = fifo_add(reg, gen, park, FIFO_PARKED);
      else
        rc = -1;
      wait = 2;
    }
    if (!rc)
      rc = fifo_add(reg, gen, w, FIFO_W);
  } else {
    if (g) {
      if ((r = fifo_fetch(reg, fo, g, FIFO_PARKED, FIFO_KIND, true)) != -1)
        reg->rjoin = g;
      else
        r = fifo_fetch(reg, fo, g, 0, FIFO_KIND, false);
      if ((w = fifo_fetch(reg, fo, g, FIFO_W | FIFO_PARKED, FIFO_KIND,
                          true)) != -1)
        reg->wjoin = g;
      else
        w = fifo_fetch(reg, fo, g, FIFO_W, FIFO_KIND, false);
      if (r != -1 && w != -1 && fifo_state(r) != kNtPipeClosingState &&
          fifo_state(w) != kNtPipeClosingState) {
        gen = g;
      } else {
        if (r != -1)
          CloseHandle(r);
        if (w != -1)
          CloseHandle(w);
        r = w = -1;
      }
    }
    if (!gen && !(gen = fifo_create(fo, reg, &r, &w, true, true)))
      rc = -1;
    if (!rc)
      rc = fifo_add(reg, gen, r, 0);
    if (!rc)
      rc = fifo_add(reg, gen, w, FIFO_W);
  }
  if (rc == -1) {
    if (park != -1)
      fifo_del(reg, park);
    fifo_del(reg, r);
    fifo_del(reg, w);
    fifo_unlock(fo, reg);
    if (park != -1)
      CloseHandle(park);
    if (r != -1)
      CloseHandle(r);
    if (w != -1)
      CloseHandle(w);
    fifo_put(fo);
    return -1;
  }
  fifo_unlock(fo, reg);

  if (wait && !(wait == 1 && nonblock)) {
    int ms = 1;
    for (;;) {
      struct timespec deadline =
          timespec_add(timespec_real(), timespec_frommillis(ms));
      if (ms < 50)
        ms *= 2;
      if (_park_restartable(deadline, waitmask) == -1) {
        rc = -1;
        break;
      }
      if (!(reg = fifo_lock(fo))) {
        rc = -1;
        break;
      }
      rc = fifo_ready(reg, fo, gen, wait == 2);
      fifo_unlock(fo, reg);
      if (rc)
        break;
    }
    if (rc != 1) {
      // our parked end may have been taken meanwhile, which closed it
      // here, so it's only closed while its entry is still ours
      int e = errno;
      if ((reg = fifo_lock(fo))) {
        uint32_t self = GetCurrentProcessId();
        for (int i = 0; i < FIFO_SLOTS; ++i)
          if (park != -1 && reg->slot[i].pid == self &&
              reg->slot[i].handle == park) {
            reg->slot[i].pid = 0;
            CloseHandle(park);
          }
        fifo_del(reg, wait == 1 ? r : w);
        fifo_unlock(fo, reg);
      }
      CloseHandle(wait == 1 ? r : w);
      errno = e;
      if (rc == 2)
        goto Restart;
      fifo_put(fo);
      return -1;
    }
  }

  f->type = kFifoMark;
  f->fifo = fo;
  f->fifow = acc == O_RDWR ? w : 0;
  return acc == O_WRONLY ? w : r;
}

// a reader that took no writer yet: end of file, as on linux
textwindows static bool fifo_nowriter(struct Fd *f, struct Fifo *fo) {
  uint32_t avail;
  if (f->fifow || !PeekNamedPipe(f->handle, 0, 0, 0, &avail, 0) || avail)
    return false;
  uint32_t gen;
  if (!(gen = fifo_gen_of(f->handle, 0, 0)))
    return false;
  struct FifoReg *reg;
  if (!(reg = fifo_lock(fo)))
    return false;
  bool res = !fifo_live(reg, fo, gen, FIFO_W, FIFO_KIND) &&
             fifo_live(reg, fo, gen, FIFO_W | FIFO_PARKED, FIFO_KIND);
  fifo_unlock(fo, reg);
  return res;
}

// moves a reader at end of file, or a writer whose readers left, to the
// pipe a later open made
textwindows static bool fifo_swap(struct Fd *f, struct Fifo *fo, bool write) {
  int64_t old = write && f->fifow ? f->fifow : f->handle;
  uint32_t mine = fifo_gen_of(old, 0, 0);
  struct FifoReg *reg;
  if (!mine || !(reg = fifo_lock(fo)))
    return false;
  uint32_t g = reg->gen, end = write ? FIFO_W : 0;
  int64_t h = -1;
  if (g != mine) {
    if ((h = fifo_fetch(reg, fo, g, end | FIFO_PARKED, FIFO_KIND, true)) !=
        -1) {
      if (write)
        reg->wjoin = g;
      else
        reg->rjoin = g;
    } else {
      if ((h = fifo_fetch(reg, fo, g, end, FIFO_KIND, false)) != -1 &&
          fifo_state(h) == kNtPipeClosingState) {
        CloseHandle(h);
        h = -1;
      }
    }
  }
  if (h != -1) {
    fifo_del(reg, old);
    fifo_add(reg, g, h, end);
  }
  fifo_unlock(fo, reg);
  if (h == -1)
    return false;
  CloseHandle(old);
  if (write && f->fifow)
    f->fifow = h;
  else
    f->handle = h;
  return true;
}

textwindows ssize_t __fifo_read_nt(int fd, void *data, size_t size,
                                   sigset_t waitmask) {
  struct Fd *f = __get_pib()->fds.p + fd;
  struct Fifo *fo = fifo_adopt(f);
  for (;;) {
    if (fo && fifo_nowriter(f, fo))
      return 0;
    ssize_t rc =
        sys_readwrite_nt(fd, data, size, -1, f->handle, waitmask, ReadFile);
    if (rc != -2 || !fo)
      return rc;
    uint32_t e = GetLastError();
    if ((e == kNtErrorBrokenPipe || e == kNtErrorNoData) &&
        fifo_swap(f, fo, false))
      continue;
    SetLastError(e);
    return -2;
  }
}

textwindows int64_t __fifo_write_handle_nt(struct Fd *f) {
  fifo_adopt(f);
  return f->fifow ? f->fifow : f->handle;
}

textwindows bool __fifo_write_swap_nt(struct Fd *f) {
  struct Fifo *fo;
  return (fo = fifo_adopt(f)) && fifo_swap(f, fo, true);
}

textwindows void __fifo_close_nt(struct Fd *f) {
  struct Fifo *fo = f->fifo;
  struct FifoReg *reg;
  if (fo && (reg = fifo_lock(fo))) {
    bool reader = !fifo_is_write_end(f->handle);
    fifo_del(reg, f->handle);
    if (f->fifow)
      fifo_del(reg, f->fifow);
    // the last reader gone: a pipe parked for readers at end of file
    // now has none, and its writers are told so
    if ((reader || f->fifow) && !fifo_live(reg, fo, 0, 0, FIFO_KIND)) {
      int64_t h;
      while ((h = fifo_fetch(reg, fo, 0, FIFO_PARKED | FIFO_SWAP,
                             FIFO_KIND | FIFO_SWAP, true)) != -1)
        CloseHandle(h);
    }
    fifo_unlock(fo, reg);
  }
  if (f->fifow)
    CloseHandle(f->fifow);
  f->fifow = 0;
  f->fifo = 0;
  if (fo)
    fifo_put(fo);
}

textwindows void __fifo_dup_nt(struct Fd *f) {
  if (f->fifow && !DuplicateHandle(GetCurrentProcess(), f->fifow,
                                   GetCurrentProcess(), &f->fifow, 0, true,
                                   kNtDuplicateSameAccess))
    f->fifow = 0;
  struct Fifo *fo;
  if (!(fo = f->fifo))
    return;
  fifo_list_lock();
  ++fo->refs;
  fifo_list_unlock();
  struct FifoReg *reg;
  if ((reg = fifo_lock(fo))) {
    fifo_add(reg, fifo_gen_of(f->handle, 0, 0), f->handle,
             fifo_is_write_end(f->handle) ? FIFO_W : 0);
    if (f->fifow)
      fifo_add(reg, fifo_gen_of(f->fifow, 0, 0), f->fifow, FIFO_W);
    fifo_unlock(fo, reg);
  }
}

// the child holds what the parent's fifo descriptors hold
textwindows void __fifo_fork_child_nt(void) {
  struct Fds *fds = &__get_pib()->fds;
  for (unsigned fd = 0; fd < fds->n; ++fd) {
    struct Fd *f = fds->p + fd;
    if (f->kind != kFdFile || f->type != kFifoMark || !f->fifo)
      continue;
    struct FifoReg *reg;
    if ((reg = fifo_lock(f->fifo))) {
      fifo_add(reg, fifo_gen_of(f->handle, 0, 0), f->handle,
               fifo_is_write_end(f->handle) ? FIFO_W : 0);
      if (f->fifow)
        fifo_add(reg, fifo_gen_of(f->fifow, 0, 0), f->fifow, FIFO_W);
      fifo_unlock(f->fifo, reg);
    }
  }
}

textwindows void __fifo_stat_nt(struct Fd *f, struct stat *st) {
  struct Fifo *fo;
  if ((fo = fifo_adopt(f))) {
    st->st_dev = MAKEDEV(0, fo->vol);
    st->st_ino = fo->id;
  }
}

#else

// open() and mknod() call these on a build that has no windows
int __mkfifo_nt(int dirfd, const char *path, unsigned mode) {
  return enosys();
}

bool __fifo_path_nt(const char16_t *path16) {
  return false;
}

int64_t __fifo_open_nt(const char16_t *path16, uint32_t flags,
                       sigset_t waitmask, struct Fd *f) {
  return enosys();
}

#endif /* SupportsWindows() */

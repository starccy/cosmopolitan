#include "libc/intrin/pgrp.h"
#include "libc/atomic.h"
#include "libc/calls/sig.internal.h"
#include "libc/calls/state.internal.h"
#include "libc/fmt/internal.h"
#include "libc/intrin/atomic.h"
#include "libc/macros.h"
#include "libc/nt/accounting.h"
#include "libc/nt/console.h"
#include "libc/nt/enum/filemapflags.h"
#include "libc/nt/enum/pageflags.h"
#include "libc/nt/enum/processaccess.h"
#include "libc/nt/enum/th32cs.h"
#include "libc/nt/enum/wait.h"
#include "libc/nt/errors.h"
#include "libc/nt/memory.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/filetime.h"
#include "libc/nt/struct/processentry32.h"
#include "libc/nt/synchronization.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/runtime/runtime.h"
#include "libc/sysv/pib.h"
#include "libc/thread/tls.h"
#ifdef __x86_64__

/**
 * @fileoverview Process groups shared between processes on Windows.
 *
 * Each cosmo process publishes its process group in a named section
 * keyed by its pid, which execve() keeps, and a parent publishes one
 * for each child it creates, so a host program has one too, and a group
 * change made before the child runs isn't lost. A process whose win32
 * pid differs from its pid has an alias under the win32 one. Sections named after a
 * console hold who has that console in the foreground. Named sections
 * go away with the last handle, so nothing outlives its processes.
 */

__msabi extern uint32_t (*const __imp_GetConsoleProcessList)(uint32_t *,
                                                             uint32_t);
__msabi extern int64_t (*const __imp_OpenFileMappingW)(uint32_t, bool32,
                                                       const char16_t *);
__msabi extern typeof(CreateFileMapping) *const __imp_CreateFileMappingW;
__msabi extern typeof(GetLastError) *const __imp_GetLastError;

// what a console publishes as Local\cosmo.tty.<console window>
struct TtyJob {
  atomic_int fg;          // foreground process group, 0 for none
  atomic_int tostop;      // background writes stop the writer
  atomic_uint setter;     // win32 pid of whoever set fg
  atomic_ullong setborn;  // its creation time, telling a reused pid apart
};

static struct {
  struct PgrpEntry *self;
  intptr_t selfmap;
  _Atomic(struct TtyJob *) tty;
} __pgrp;

textwindows static char16_t *PgrpName(char16_t *p, const char *kind,
                                      uint64_t id) {
  char16_t *b = p;
  for (const char *s = "Local\\cosmo."; *s;)
    *p++ = *s++;
  while (*kind)
    *p++ = *kind++;
  *p++ = '.';
  *__itoa16(p, id) = 0;
  return b;
}

textwindows static void *MapNamed(const char16_t *name, size_t size,
                                  bool create, intptr_t *hand, bool *existed) {
  intptr_t h;
  if (create) {
    if (!(h = __imp_CreateFileMappingW(-1, 0, kNtPageReadwrite, 0, size,
                                       name)))
      return 0;
    *existed = __imp_GetLastError() == kNtErrorAlreadyExists;
  } else {
    if (!(h = __imp_OpenFileMappingW(kNtFileMapRead | kNtFileMapWrite, false,
                                     name)))
      return 0;
    *existed = true;
  }
  void *p = MapViewOfFileEx(h, kNtFileMapRead | kNtFileMapWrite, 0, 0, size, 0);
  if (!p) {
    CloseHandle(h);
    return 0;
  }
  *hand = h;
  return p;
}

textwindows static struct PgrpEntry *MapEntry(uint32_t id, bool create,
                                              intptr_t *h, bool *existed) {
  char16_t name[48];
  return MapNamed(PgrpName(name, "pgrp", id), sizeof(struct PgrpEntry),
                  create, h, existed);
}

textwindows static void UnmapEntry(struct PgrpEntry *e, intptr_t h) {
  UnmapViewOfFile(e);
  CloseHandle(h);
}

// the entry under a win32 pid is the process's own when the two pids
// agree, else an alias naming its cosmo pid, whose entry has the rest
textwindows static bool Lookup(uint32_t winpid, int *pid, int *pgid,
                               bool *cosmo) {
  bool existed;
  intptr_t h;
  struct PgrpEntry *e;
  if (!(e = MapEntry(winpid, false, &h, &existed)))
    return false;
  *pid = atomic_load_explicit(&e->pid, memory_order_acquire);
  if (*pid != winpid) {
    UnmapEntry(e, h);
    if (*pid <= 0 || !(e = MapEntry(*pid, false, &h, &existed)))
      return false;
  }
  *pgid = atomic_load_explicit(&e->pgid, memory_order_acquire);
  *cosmo = atomic_load_explicit(&e->self, memory_order_relaxed) == winpid;
  UnmapEntry(e, h);
  return *pgid != 0;
}

// the cosmo pid of the process whose win32 pid is `winpid`, which differs
// from it after an execve(); `winpid` itself when nothing says otherwise
textwindows int __pid_of_winpid(uint32_t winpid) {
  bool existed;
  intptr_t h;
  struct PgrpEntry *e;
  int pid = winpid;
  if (winpid && (e = MapEntry(winpid, false, &h, &existed))) {
    int p = atomic_load_explicit(&e->pid, memory_order_acquire);
    if (p > 0)
      pid = p;
    UnmapEntry(e, h);
  }
  return pid;
}

// the group of the process published as `pid`, or -1
textwindows int __pgrp_of(int pid) {
  bool existed;
  intptr_t h;
  struct PgrpEntry *e;
  int g = -1;
  if (pid > 0 && (e = MapEntry(pid, false, &h, &existed))) {
    if (atomic_load(&e->pid) == pid && atomic_load(&e->pgid))
      g = atomic_load(&e->pgid);
    UnmapEntry(e, h);
  }
  return g;
}

// publishes the calling process, or takes the group its creator gave it
// meanwhile; called at startup and in a fork()ed child
textwindows void __pgrp_own(void) {
  bool existed;
  intptr_t h;
  struct PgrpEntry *e;
  struct CosmoPib *pib = __get_pib();
  uint32_t win = GetCurrentProcessId();
  // after fork() these are the parent's views, which aren't mapped here
  __pgrp.self = 0;
  __pgrp.selfmap = 0;
  atomic_store_explicit(&__pgrp.tty, 0, memory_order_relaxed);
  if (!(e = MapEntry(pib->pid, true, &h, &existed)))
    return;
  int g;
  if (existed && atomic_load(&e->pid) == pib->pid && (g = atomic_load(&e->pgid)))
    pib->pgid = g;
  atomic_store_explicit(&e->pid, pib->pid, memory_order_relaxed);
  atomic_store_explicit(&e->self, win, memory_order_relaxed);
  atomic_store_explicit(&e->pgid, pib->pgid, memory_order_release);
  __pgrp.self = e;
  __pgrp.selfmap = h;
  if (win != pib->pid) {
    struct PgrpEntry *a;
    if ((a = MapEntry(win, true, &h, &existed))) {
      atomic_store_explicit(&a->pid, pib->pid, memory_order_release);
      UnmapViewOfFile(a);  // the handle stays open for our lifetime
    }
  }
}

// our process group, which a parent's setpgid() may have changed
textwindows int __pgrp_self(void) {
  struct CosmoPib *pib = __get_pib();
  if (__pgrp.self && !__vforked) {
    int g = atomic_load_explicit(&__pgrp.self->pgid, memory_order_acquire);
    if (g)
      pib->pgid = g;
  }
  return pib->pgid;
}

textwindows void __pgrp_self_set(int pgid) {
  __get_pib()->pgid = pgid;
  if (__pgrp.self && !__vforked)
    atomic_store_explicit(&__pgrp.self->pgid, pgid, memory_order_release);
}

// the calling process's entry handle, for execve() to pass on
textwindows intptr_t __pgrp_handle(void) {
  return __vforked ? 0 : __pgrp.selfmap;
}

// execve() has handed our pid to a new program, which may be no cosmo one
textwindows void __pgrp_disown(void) {
  if (__pgrp.self && !__vforked)
    atomic_store_explicit(&__pgrp.self->self, 0, memory_order_relaxed);
}

// publishes cosmo process `pid` in group `pgid` unless it did so itself
// already; the returned handle keeps the entry alive
textwindows intptr_t __pgrp_publish(int pid, int pgid, struct PgrpEntry **out) {
  bool existed;
  intptr_t h;
  struct PgrpEntry *e;
  if (!(e = MapEntry(pid, true, &h, &existed)))
    return 0;
  if (!existed || !atomic_load(&e->pgid)) {
    atomic_store_explicit(&e->pid, pid, memory_order_relaxed);
    atomic_store_explicit(&e->pgid, pgid, memory_order_release);
  }
  *out = e;
  return h;
}

// names cosmo pid `pid` as what win32 pid `winpid` is; the returned
// handle keeps the alias alive
textwindows intptr_t __pgrp_alias(uint32_t winpid, int pid) {
  bool existed;
  intptr_t h;
  struct PgrpEntry *e;
  if (!(e = MapEntry(winpid, true, &h, &existed)))
    return 0;
  atomic_store_explicit(&e->pid, pid, memory_order_release);
  UnmapViewOfFile(e);
  return h;
}

textwindows void __pgrp_unpublish(intptr_t h, struct PgrpEntry *e) {
  if (e)
    UnmapViewOfFile(e);
  if (h)
    CloseHandle(h);
}

struct Parent {
  uint32_t pid, ppid;
};

textwindows static int Snapshot(struct Parent **out) {
  int64_t snap;
  int n = 0, c = 0;
  struct Parent *v = 0, *v2;
  struct NtProcessEntry32 e;
  if ((snap = CreateToolhelp32Snapshot(kNtTh32csSnapprocess, 0)) == -1)
    return 0;
  e.dwSize = sizeof(e);
  for (bool32 ok = Process32First(snap, &e); ok; ok = Process32Next(snap, &e)) {
    if (n == c) {
      c = c ? c * 2 : 512;
      if (!(v2 = v ? HeapReAlloc(GetProcessHeap(), 0, v, c * sizeof(*v))
                   : HeapAlloc(GetProcessHeap(), 0, c * sizeof(*v))))
        break;
      v = v2;
    }
    v[n].pid = e.th32ProcessID;
    v[n].ppid = e.th32ParentProcessID;
    ++n;
  }
  CloseHandle(snap);
  *out = v;
  return n;
}

// the group of a host program, which is that of its nearest ancestor
// with an entry, or 0
textwindows static int InheritedGroup(uint32_t winpid, struct Parent *v,
                                      int n) {
  for (int depth = 0; depth < 32; ++depth) {
    uint32_t ppid = 0;
    for (int i = 0; i < n; ++i)
      if (v[i].pid == winpid) {
        ppid = v[i].ppid;
        break;
      }
    if (!ppid || ppid == winpid)
      return 0;
    int pid, pgid;
    bool cosmo;
    if (Lookup(ppid, &pid, &pgid, &cosmo))
      return pgid;
    winpid = ppid;
  }
  return 0;
}

// the processes on our console in group `pgid`, at most `cap`
textwindows int __pgrp_members(int pgid, struct PgrpMember *out, int cap) {
  uint32_t wins[512];
  uint32_t n = __imp_GetConsoleProcessList(wins, ARRAYLEN(wins));
  if (n > ARRAYLEN(wins))
    return 0;
  int k = 0, nsnap = -1;
  struct Parent *snap = 0;
  for (uint32_t i = 0; i < n && k < cap; ++i) {
    int pid, g;
    bool cosmo = false;
    if (!Lookup(wins[i], &pid, &g, &cosmo)) {
      if (nsnap < 0)
        nsnap = Snapshot(&snap);
      pid = wins[i];
      g = InheritedGroup(wins[i], snap, nsnap);
    }
    if (g != pgid)
      continue;
    // a process execve() replaced may linger with the same pid
    bool dup = false;
    for (int j = 0; j < k; ++j)
      if (out[j].cosmo && cosmo && out[j].pid == pid)
        dup = true;
    if (dup)
      continue;
    out[k].pid = pid;
    out[k].winpid = wins[i];
    out[k].cosmo = cosmo;
    ++k;
  }
  if (snap)
    HeapFree(GetProcessHeap(), 0, snap);
  return k;
}

// sets `sig` pending for the cosmo programs of group `pgid` on our console
textwindows void __pgrp_post(int pgid, int sig) {
  struct PgrpMember m[64];
  int n = __pgrp_members(pgid, m, ARRAYLEN(m));
  for (int i = 0; i < n; ++i) {
    bool owned;
    atomic_ulong *sigs;
    if (!m[i].cosmo)
      continue;
    if (!(sigs = __sig_map_target(m[i].pid, &owned)))
      continue;
    if (owned) {
      atomic_fetch_or_explicit(sigs, 1ull << (sig - 1), memory_order_release);
      __sig_wake_process(m[i].pid);
    }
    UnmapViewOfFile(sigs);
  }
}

textwindows static uint64_t Born(int64_t hProcess) {
  struct NtFileTime c, e, k, u;
  if (!GetProcessTimes(hProcess, &c, &e, &k, &u))
    return 0;
  return (uint64_t)c.dwHighDateTime << 32 | c.dwLowDateTime;
}

textwindows static struct TtyJob *GetTtyJob(bool create) {
  struct TtyJob *t;
  if ((t = atomic_load_explicit(&__pgrp.tty, memory_order_acquire)))
    return t;
  int64_t con;
  if (!(con = GetConsoleWindow()))
    return 0;
  bool existed;
  intptr_t h;
  char16_t name[48];
  if (!(t = MapNamed(PgrpName(name, "tty", con), sizeof(*t), create, &h,
                     &existed)))
    return 0;
  // the view stays mapped and its handle open, since both keep the
  // console's state alive for the processes still on it
  struct TtyJob *none = 0;
  if (!atomic_compare_exchange_strong_explicit(&__pgrp.tty, &none, t,
                                               memory_order_acq_rel,
                                               memory_order_acquire)) {
    UnmapViewOfFile(t);
    CloseHandle(h);
    return none;
  }
  return t;
}

// the group a tcsetpgrp() on our console gave the foreground to, or 0
// when nobody did or whoever did is gone
textwindows int __pgrp_foreground(void) {
  struct TtyJob *t;
  if (!(t = GetTtyJob(false)))
    return 0;
  int fg = atomic_load_explicit(&t->fg, memory_order_acquire);
  if (!fg)
    return 0;
  uint32_t setter = atomic_load_explicit(&t->setter, memory_order_relaxed);
  if (setter == GetCurrentProcessId())
    return fg;
  int64_t h;
  if (!(h = OpenProcess(kNtProcessQueryLimitedInformation | kNtSynchronize,
                        false, setter)))
    return 0;
  bool alive = WaitForSingleObject(h, 0) == kNtWaitTimeout &&
               Born(h) == atomic_load_explicit(&t->setborn,
                                               memory_order_relaxed);
  CloseHandle(h);
  return alive ? fg : 0;
}

textwindows void __pgrp_set_foreground(int pgid) {
  struct TtyJob *t;
  if (!(t = GetTtyJob(true)))
    return;
  atomic_store_explicit(&t->setter, GetCurrentProcessId(),
                        memory_order_relaxed);
  atomic_store_explicit(&t->setborn, Born(GetCurrentProcess()),
                        memory_order_relaxed);
  atomic_store_explicit(&t->fg, pgid, memory_order_release);
}

// whether some other group has our console in the foreground
textwindows bool __pgrp_background(void) {
  int fg = __pgrp_foreground();
  return fg && fg != __pgrp_self();
}

textwindows bool __pgrp_tostop(void) {
  struct TtyJob *t;
  return (t = GetTtyJob(false)) && atomic_load(&t->tostop);
}

textwindows void __pgrp_set_tostop(bool on) {
  struct TtyJob *t;
  if ((t = GetTtyJob(on)))
    atomic_store(&t->tostop, on);
}

#endif /* __x86_64__ */

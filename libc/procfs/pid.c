#include "libc/nt/accounting.h"
#include "libc/nt/dll.h"
#include "libc/nt/enum/accessmask.h"
#include "libc/nt/enum/processaccess.h"
#include "libc/nt/enum/processinfoclass.h"
#include "libc/nt/files.h"
#include "libc/nt/memory.h"
#include "libc/nt/nt/process.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/filetime.h"
#include "libc/nt/struct/memorybasicinformation.h"
#include "libc/nt/struct/processbasicinformation.h"
#include "libc/nt/struct/processmemorycounters.h"
#include "libc/nt/struct/psapiworkingsetexinformation.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/procfs/internal.h"
#include "libc/str/str.h"
#include "libc/procfs/xnu.internal.h"

// /proc/<pid>/* content. The facts come from three places, the shared
// toolhelp snapshot (name, parent, thread count), an OpenProcess handle with
// query rights (times, memory, io, image path, command line), and for our own
// process the C runtime itself (argv, environ, cwd), which is both cheaper
// and exact. A field NT cannot answer is emitted as 0 rather than omitted,
// since every parser of these files splits on position, and a short line
// aborts the parse where a zero merely reads as idle.

extern char **environ;

// The split the carrier materializes by. The volatile four move while a
// process runs and share one OpenProcess pass; the stable rest is fixed for
// a process's lifetime and only ever needs writing once.
const char *const pfs_pid_volatile[] = {"stat", "status", "statm", "io", 0};
const char *const pfs_pid_stable[] = {
    "cmdline",       "comm",      "environ", "limits",        "maps",
    "cgroup",        "mountinfo", "mounts",  "oom_score_adj", "oom_score",
    "smaps",         "smaps_rollup", 0};

static uint64_t ft(struct NtFileTime t) {
  return (uint64_t)t.dwHighDateTime << 32 | t.dwLowDateTime;
}

// The per-process counters, from the snapshot when it carries them, else
// what one OpenProcess handle answers, gathered in a single pass.
struct pidfacts {
  bool have;
  uint64_t utime, stime;  // jiffies
  uint64_t starttime;     // jiffies since boot
  uint64_t vsize, rss;    // bytes
  uint64_t peak_vsize, peak_rss;
  uint64_t private;  // committed private bytes
  uint64_t csw;      // context switches of all its threads
  uint32_t minflt;
  struct NtIoCounters io;
};

static void gather(uint32_t pid, struct pidfacts *f) {
  memset(f, 0, sizeof *f);
  const struct pfs_proc *p = pfs_proc_find(pid);
  if (p && p->facts) {
    f->have = true;
    f->utime = pfs_filetime_jiffies(p->utime);
    f->stime = pfs_filetime_jiffies(p->stime);
    uint64_t boot = pfs_boot_filetime();
    if (p->create > boot)
      f->starttime = pfs_filetime_jiffies(p->create - boot);
    f->vsize = p->vsize;
    f->rss = p->rss;
    f->peak_vsize = p->peak_vsize;
    f->peak_rss = p->peak_rss;
    f->private = p->private;
    f->csw = p->csw;
    f->minflt = p->minflt;
    f->io = p->io;
    return;
  }
  int64_t h = pfs_open_process(pid);
  if (!h)
    return;
  f->have = true;

  struct NtFileTime tc, tx, tk, tu;
  if (GetProcessTimes(h, &tc, &tx, &tk, &tu)) {
    f->utime = pfs_filetime_jiffies(ft(tu));
    f->stime = pfs_filetime_jiffies(ft(tk));
    uint64_t boot = pfs_boot_filetime(), created = ft(tc);
    if (created > boot)
      f->starttime = pfs_filetime_jiffies(created - boot);
  }
  struct NtProcessMemoryCountersEx mc;
  memset(&mc, 0, sizeof mc);
  mc.cb = sizeof mc;
  if (GetProcessMemoryInfo(h, &mc, sizeof mc)) {
    f->vsize = mc.PagefileUsage ? mc.PagefileUsage : mc.PrivateUsage;
    f->rss = mc.WorkingSetSize;
    f->peak_vsize = mc.PeakPagefileUsage;
    f->peak_rss = mc.PeakWorkingSetSize;
    f->private = mc.PrivateUsage;
    f->minflt = mc.PageFaultCount;
  }
  GetProcessIoCounters(h, &f->io);
  CloseHandle(h);
}

static char state_of(uint32_t pid) {
  return pid == pfs_self_pid() ? 'R' : 'S';
}

struct NtModuleInfo {
  void *lpBaseOfDll;
  uint32_t SizeOfImage;
  void *EntryPoint;
};
typedef int32_t(__msabi *EnumModsF)(int64_t, int64_t *, uint32_t, uint32_t *);
typedef int32_t(__msabi *ModInfoF)(int64_t, int64_t, struct NtModuleInfo *,
                                   uint32_t);

// the DLLs mapped into this process, in bytes, our own image left out:
// what VmLib is on Linux, where it's the shared libraries' mappings
static uint64_t self_libs(void) {
  static EnumModsF em;
  static ModInfoF mi;
  if (!em) {
    em = (EnumModsF)pfs_sym(u"kernel32.dll", "K32EnumProcessModules");
    mi = (ModInfoF)pfs_sym(u"kernel32.dll", "K32GetModuleInformation");
  }
  int64_t handles[256];
  uint32_t need = 0;
  if (!em || !mi || !em(-1, handles, sizeof handles, &need))
    return 0;
  int n = (int)(need / 8);
  if (n > 256)
    n = 256;
  int64_t self = (int64_t)GetModuleHandle(0);
  uint64_t total = 0;
  for (int i = 0; i < n; i++) {
    struct NtModuleInfo info;
    if (handles[i] != self && mi(-1, handles[i], &info, sizeof info))
      total += info.SizeOfImage;
  }
  return total;
}

// ---------------------------------------------------------------------------
// stat: "<pid> (comm) <state>" then 49 positional fields, Linux 6.x's count.

static void gen_stat(struct pfs_buf *b, uint32_t pid, const struct pfs_proc *p,
                     const struct pidfacts *f) {
  pfs_printf(b, "%u (%s) %c %u %u %u 0 -1 0 %u 0 0 0 ", pid, p->comm,
             state_of(pid), p->ppid, pid, pid, f->minflt);
  pfs_printf(b, "%llu %llu 0 0 20 0 %u 0 %llu %llu %llu ",
             (unsigned long long)f->utime, (unsigned long long)f->stime,
             p->threads, (unsigned long long)f->starttime,
             (unsigned long long)f->vsize, (unsigned long long)(f->rss / 4096));
  pfs_printf(b, "18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 "
                "0 0 0 0 0 0 0 0 0 0\n");
}

// ---------------------------------------------------------------------------
// Another process's uid, the number that process's own getuid() gives: on
// NT cosmo hashes the account name (libc/calls/getuid-nt.c), and gid is the
// same number. LocalSystem is root. A token that can't be opened, mostly
// protected system processes, reads as 0 too. Answers are cached per pid and
// creation time, and names per SID, since LookupAccountSid goes to LSA.

typedef bool32(__msabi *GetTokenInfoF)(int64_t, int, void *, uint32_t,
                                       uint32_t *);
typedef bool32(__msabi *LookupSidF)(const char16_t *, const void *, char16_t *,
                                    uint32_t *, char16_t *, uint32_t *, int *);

static struct {
  uint32_t pid;
  uint64_t create;
  unsigned uid;
} g_uidcache[256];

static struct {
  unsigned char sid[68];
  unsigned uid;
} g_sidcache[16];
static int g_sidcount;

static unsigned sid_uid(const unsigned char *sid) {
  static LookupSidF lookup;
  size_t len = 8 + 4 * (size_t)sid[1];
  if (len > sizeof(g_sidcache[0].sid))
    return 0;
  // S-1-5-18
  static const unsigned char kSystem[12] = {1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0};
  if (len == sizeof(kSystem) && !memcmp(sid, kSystem, len))
    return 0;
  for (int i = 0; i < g_sidcount; i++)
    if (!memcmp(g_sidcache[i].sid, sid, len))
      return g_sidcache[i].uid;
  if (!lookup)
    lookup = (LookupSidF)pfs_sym(u"advapi32.dll", "LookupAccountSidW");
  char16_t name[257], domain[257];
  uint32_t n = 257, dn = 257;
  int use;
  if (!lookup || !lookup(0, sid, name, &n, domain, &dn, &use))
    return 0;
  // getuid-nt.c hashes what GetUserName() gives, whose count has the NUL
  unsigned uid = __fnv(name, (n + 1) >> 1) & 32767;
  if (!uid)
    uid = 1;
  int slot = g_sidcount < 16 ? g_sidcount++ : 15;
  memcpy(g_sidcache[slot].sid, sid, len);
  g_sidcache[slot].uid = uid;
  return uid;
}

static unsigned other_uid(uint32_t pid, uint64_t create) {
  static GetTokenInfoF info;
  unsigned slot = (pid >> 2) % 256;
  if (create && g_uidcache[slot].pid == pid &&
      g_uidcache[slot].create == create)
    return g_uidcache[slot].uid;
  if (!info)
    info = (GetTokenInfoF)pfs_sym(u"advapi32.dll", "GetTokenInformation");
  if (!info)
    return 0;
  int64_t h = OpenProcess(kNtProcessQueryLimitedInformation, false, pid);
  if (!h)
    return 0;
  int64_t tok;
  bool ok = OpenProcessToken(h, kNtTokenQuery, &tok);
  CloseHandle(h);
  if (!ok)
    return 0;
  union {
    struct {
      unsigned char *sid;
      uint32_t attributes;
    } user;  // TOKEN_USER
    char buf[128];
  } u;
  uint32_t len;
  ok = info(tok, 1 /* TokenUser */, &u, sizeof(u), &len);
  CloseHandle(tok);
  if (!ok)
    return 0;
  unsigned uid = sid_uid(u.user.sid);
  g_uidcache[slot].pid = pid;
  g_uidcache[slot].create = create;
  g_uidcache[slot].uid = uid;
  return uid;
}

static void gen_status(struct pfs_buf *b, uint32_t pid,
                       const struct pfs_proc *p, const struct pidfacts *f) {
  bool self = pid == pfs_self_pid();
  unsigned uid = self ? (unsigned)getuid() : other_uid(pid, p->create);
  unsigned gid = self ? (unsigned)getgid() : uid;
  pfs_printf(b, "Name:\t%s\n", p->comm);
  pfs_printf(b, "Umask:\t0022\n");
  pfs_printf(b, "State:\t%c (%s)\n", state_of(pid),
             self ? "running" : "sleeping");
  pfs_printf(b, "Tgid:\t%u\nNgid:\t0\nPid:\t%u\nPPid:\t%u\n", pid, pid,
             p->ppid);
  pfs_printf(b, "TracerPid:\t0\n");
  pfs_printf(b, "Uid:\t%u\t%u\t%u\t%u\n", uid, uid, uid, uid);
  pfs_printf(b, "Gid:\t%u\t%u\t%u\t%u\n", gid, gid, gid, gid);
  pfs_printf(b, "FDSize:\t64\nGroups:\t%u\n", gid);
  pfs_printf(b, "VmPeak:\t%8llu kB\nVmSize:\t%8llu kB\n",
             (unsigned long long)(f->peak_vsize / 1024),
             (unsigned long long)(f->vsize / 1024));
  pfs_printf(b, "VmHWM:\t%8llu kB\nVmRSS:\t%8llu kB\n",
             (unsigned long long)(f->peak_rss / 1024),
             (unsigned long long)(f->rss / 1024));
  // VmData is NT's private commit charge: the heap, anonymous mappings
  // and the stack pages touched so far, with the program's own text
  // taken out since cosmo maps that privately too. Only our own stack,
  // text and DLLs are known; another process gets zeros there
  uint64_t stk = 0, exe = 0, lib = 0, data = f->private;
  if (self) {
    stk = pfs_self_stack();
    exe = pfs_self_text();
    lib = self_libs();
    data = data > exe ? data - exe : 0;
  }
  pfs_printf(b,
             "VmData:\t%8llu kB\nVmStk:\t%8llu kB\n"
             "VmExe:\t%8llu kB\nVmLib:\t%8llu kB\n"
             "VmSwap:\t       0 kB\n",
             (unsigned long long)(data / 1024), (unsigned long long)(stk / 1024),
             (unsigned long long)(exe / 1024), (unsigned long long)(lib / 1024));
  pfs_printf(b, "Threads:\t%u\n", p->threads);
  uint64_t blk = 0, ign = 0, cgt = 0;
  if (self)
    pfs_self_sigs(&blk, &ign, &cgt);
  pfs_printf(b,
             "SigQ:\t0/0\nSigPnd:\t0000000000000000\n"
             "ShdPnd:\t0000000000000000\nSigBlk:\t%016llx\n"
             "SigIgn:\t%016llx\nSigCgt:\t%016llx\n"
             "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
             "CapEff:\t0000000000000000\n",
             (unsigned long long)blk, (unsigned long long)ign,
             (unsigned long long)cgt);
  // NT counts switches, not why they happened
  pfs_printf(b,
             "voluntary_ctxt_switches:\t%llu\n"
             "nonvoluntary_ctxt_switches:\t0\n",
             (unsigned long long)f->csw);
}

// size resident shared text lib data dt, in pages; data is what Linux
// puts there, the data and stack segments together
static void gen_statm(struct pfs_buf *b, uint32_t pid,
                      const struct pidfacts *f) {
  uint64_t exe = 0, stk = 0, data = f->private;
  if (pid == pfs_self_pid()) {
    exe = pfs_self_text();
    stk = pfs_self_stack();
    data = data > exe ? data - exe : 0;
  }
  pfs_printf(b, "%llu %llu 0 %llu 0 %llu 0\n",
             (unsigned long long)(f->vsize / 4096),
             (unsigned long long)(f->rss / 4096),
             (unsigned long long)(exe / 4096),
             (unsigned long long)((data + stk) / 4096));
}

// ---------------------------------------------------------------------------
// cmdline: argv joined with NULs. Our own comes from the runtime verbatim.
// Anyone else's is one command-line string in their PEB, asked for with
// NtQueryInformationProcess and split the way Windows itself would split it.

#define ProcessCommandLineInformation 60

typedef char16_t **(__msabi *CommandLineToArgvF)(const char16_t *, int *);
typedef int64_t(__msabi *LocalFreeF)(int64_t);

static void put_utf8(struct pfs_buf *b, const char16_t *w, int len) {
  for (int i = 0; i < len; i++) {
    uint32_t c = w[i];
    if (c >= 0xd800 && c < 0xdc00 && i + 1 < len && w[i + 1] >= 0xdc00 &&
        w[i + 1] < 0xe000) {
      c = 0x10000 + ((c - 0xd800) << 10) + (w[++i] - 0xdc00);
    }
    char u[4];
    int n;
    if (c < 0x80)
      u[0] = c, n = 1;
    else if (c < 0x800)
      u[0] = 0xc0 | c >> 6, u[1] = 0x80 | (c & 63), n = 2;
    else if (c < 0x10000)
      u[0] = 0xe0 | c >> 12, u[1] = 0x80 | (c >> 6 & 63),
      u[2] = 0x80 | (c & 63), n = 3;
    else
      u[0] = 0xf0 | c >> 18, u[1] = 0x80 | (c >> 12 & 63),
      u[2] = 0x80 | (c >> 6 & 63), u[3] = 0x80 | (c & 63), n = 4;
    pfs_put(b, u, n);
  }
}

static size_t put_ntpath(char *, size_t, const char16_t *, size_t);

static void gen_cmdline(struct pfs_buf *b, uint32_t pid) {
  if (pid == pfs_self_pid()) {
    for (int i = 0; i < __argc; i++)
      pfs_put(b, __argv[i], strlen(__argv[i]) + 1);
    return;
  }
  int64_t h = pfs_open_process(pid);
  if (!h)
    return;
  // a UNICODE_STRING header whose Buffer points into the same allocation
  struct {
    uint16_t len, max;
    uint32_t pad;
    char16_t *buf;
  } *us;
  static _Alignas(8) char raw[32768];  // guarded by the caller's lock
  uint32_t rlen = 0;
  us = (void *)raw;
  if (!NtQueryInformationProcess(h, ProcessCommandLineInformation, raw,
                                 sizeof raw, &rlen) &&
      us->buf && us->len) {
    int nw = us->len / 2;
    static CommandLineToArgvF to_argv;
    static LocalFreeF local_free;
    if (!to_argv) {
      to_argv =
          (CommandLineToArgvF)pfs_sym(u"shell32.dll", "CommandLineToArgvW");
      local_free = (LocalFreeF)pfs_sym(u"kernel32.dll", "LocalFree");
    }
    us->buf[nw] = 0;
    char16_t **argv;
    int argc = 0;
    if (to_argv && (argv = to_argv(us->buf, &argc))) {
      for (int i = 0; i < argc; i++) {
        int n = 0;
        while (argv[i][n])
          n++;
        // argv[0] in the shape exe and cwd use. Readers with unix
        // path semantics take the basename after the last slash
        // and stop at a colon, so "C:\x\y.exe" would name the
        // process "C".
        if (i == 0 && n >= 3 && argv[0][1] == ':' &&
            (argv[0][2] == '\\' || argv[0][2] == '/')) {
          char path[PATH_MAX];
          size_t m = put_ntpath(path, sizeof path, argv[0], n);
          pfs_put(b, path, m);
        } else {
          put_utf8(b, argv[i], n);
        }
        pfs_put(b, "", 1);
      }
      if (local_free)
        local_free((int64_t)argv);
    } else {
      put_utf8(b, us->buf, nw);
      pfs_put(b, "", 1);
    }
  }
  CloseHandle(h);
}

// ---------------------------------------------------------------------------
// Another process's cwd and environment. NT keeps both only in the target's
// own user-mode memory (PEB -> RTL_USER_PROCESS_PARAMETERS), so they are
// read out with ReadProcessMemory the way Process Explorer does it. Needs
// PROCESS_VM_READ, which the same user's ordinary processes grant and
// system/protected/other users' ones refuse; those fall back to what a
// plain read could say before (cwd ENOENT, environ empty, the closest a
// read comes to the EACCES Linux answers for other users). A WOW64 process
// has a 32-bit PEB and parameter block, with 4 byte pointers and other
// offsets; ProcessWow64Information gives that PEB's address.

typedef bool32(__msabi *ReadMemF)(int64_t, uint64_t, void *, uint64_t,
                                  uint64_t *);

static bool read_mem(int64_t h, uint64_t addr, void *out, size_t n) {
  static ReadMemF read;
  if (!read)
    read = (ReadMemF)pfs_sym(u"kernel32.dll", "ReadProcessMemory");
  uint64_t got = 0;
  return read && read(h, addr, out, n, &got) && got == n;
}

// Opens `pid` for memory reads and returns its process parameters block,
// setting *is32 for a WOW64 target; 0 with no handle when either is not to
// be had.
static uint64_t open_params(uint32_t pid, int64_t *hout, bool *is32) {
  int64_t h =
      OpenProcess(kNtProcessQueryInformation | kNtProcessVmRead, false, pid);
  if (!h)
    return 0;
  struct NtProcessBasicInformation pbi;
  uint32_t rlen = 0, params32 = 0;
  uint64_t wow64 = 0, params = 0;
  if (!NtQueryInformationProcess(h, kNtProcessWow64Information, &wow64,
                                 sizeof wow64, &rlen) &&
      wow64) {
    *is32 = true;
    if (read_mem(h, wow64 + 0x10, &params32, 4))
      params = params32;
  } else {
    *is32 = false;
    if (!NtQueryInformationProcess(h, kNtProcessBasicInformation, &pbi,
                                   sizeof pbi, &rlen))
      read_mem(h, (uint64_t)(uintptr_t)pbi.PebBaseAddress + 0x20, &params, 8);
  }
  if (!params) {
    CloseHandle(h);
    return 0;
  }
  *hout = h;
  return params;
}

// A UNICODE_STRING at `addr` in the target, as chars into w[cap]; -1 if it
// cannot be read whole. The 32-bit layout is two counts and a 4 byte pointer.
static int read_ustring(int64_t h, uint64_t addr, char16_t *w, size_t cap,
                        bool is32) {
  struct {
    uint16_t len, max;
    uint32_t buf32;
    uint64_t buf;
  } us;
  if (!read_mem(h, addr, &us, is32 ? 8 : sizeof us))
    return -1;
  if (is32)
    us.buf = us.buf32;
  size_t n = us.len / 2;
  if (!us.buf || n > cap)
    return -1;
  if (n && !read_mem(h, us.buf, w, n * 2))
    return -1;
  return (int)n;
}

// libc/calls/mkunixpath.c: cosmo's own spelling of a win32 path, the one
// getcwd() and GetProgramExecutableName() answer with
int __mkunixpath(const char16_t *, char *);

// A win32 path in the shape cosmo spells absolute paths in ("C:\x\y" is
// "/C/x/y", or "/x/y" when C: is the cosmos drive), so what /proc says
// about a process compares equal to what that process says about itself.
// A bare drive form is not absolute to a caller with unix Path semantics
// (fish asserts on exactly that). Returns the byte count written, no
// terminator.
static size_t put_ntpath(char *buf, size_t n, const char16_t *w, size_t len) {
  // heap, not stack: this runs on whatever thread asks, some with small
  // stacks, and __mkunixpath wants a PATH_MAX (1024) byte output
  if (len < 4096) {
    char16_t *w0 = malloc((len + 1) * sizeof(char16_t));
    char *u8 = malloc(1024);
    int m = -1;
    if (w0 && u8) {
      memcpy(w0, w, len * sizeof(char16_t));
      w0[len] = 0;
      m = __mkunixpath(w0, u8);
    }
    if (m >= 0) {
      if ((size_t)m > n)
        m = (int)n;
      memcpy(buf, u8, (size_t)m);
    }
    free(w0);
    free(u8);
    if (m >= 0)
      return (size_t)m;
  }
  size_t k = 0;
  for (size_t i = 0; i < len && k < n; i++)
    buf[k++] = w[i] == '\\' ? '/' : (w[i] < 128 ? (char)w[i] : '_');
  if (k >= 2 && buf[1] == ':') {
    buf[1] = buf[0];
    buf[0] = '/';
  }
  return k;
}

static long other_cwd(uint32_t pid, char *buf, size_t n) {
  int64_t h;
  bool is32;
  uint64_t params = open_params(pid, &h, &is32);
  if (!params)
    return -1;
  char16_t w[600];
  // CurrentDirectory.DosPath
  int len = read_ustring(h, params + (is32 ? 0x24 : 0x38), w, 600, is32);
  CloseHandle(h);
  if (len <= 0)
    return -1;
  if (len > 3 && w[len - 1] == '\\')
    len--;  // NT keeps a trailing slash
  return (long)put_ntpath(buf, n, w, (size_t)len);
}

static void gen_environ(struct pfs_buf *b, uint32_t pid) {
  if (pid == pfs_self_pid()) {
    for (char **e = environ; *e; e++)
      pfs_put(b, *e, strlen(*e) + 1);
    return;
  }
  int64_t h;
  bool is32;
  uint64_t params = open_params(pid, &h, &is32);
  if (!params)
    return;
  uint64_t env = 0, size = 0;
  if (read_mem(h, params + (is32 ? 0x48 : 0x80), &env, is32 ? 4 : 8) && env) {
    // EnvironmentSize (Vista+) bounds the block; without it, walk pages
    // until the double NUL or the mapping ends
    if (!read_mem(h, params + (is32 ? 0x290 : 0x3f0), &size, is32 ? 4 : 8) ||
        size > (1u << 20))
      size = 1u << 20;

    static char16_t page[2048];  // guarded by the caller's lock
    uint64_t off = 0;
    char16_t carry = 0;  // high surrogate a page edge split
    bool bound = true;   // at a string boundary, block start or past a NUL
    bool done = false;
    while (!done && off < size) {
      size_t want = sizeof page;
      if (size - off < want)
        want = (size_t)(size - off);
      if (!read_mem(h, env + off, page, want))
        break;
      size_t nw = want / 2, i = 0;
      if (carry) {
        if (nw && page[0] >= 0xdc00 && page[0] < 0xe000) {
          char16_t pair[2] = {carry, page[0]};
          put_utf8(b, pair, 2);
          i = 1;
        } else {
          put_utf8(b, &carry, 1);
        }
        carry = 0;
      }
      while (i < nw) {
        if (!page[i]) {
          if (bound) {
            done = true;
            break;
          }  // double NUL: the end
          pfs_put(b, "", 1);
          bound = true;
          i++;
          continue;
        }
        size_t j = i;
        while (j < nw && page[j])
          j++;
        size_t end = j;
        if (j == nw && page[j - 1] >= 0xd800 && page[j - 1] < 0xdc00)
          carry = page[--end];
        put_utf8(b, page + i, (int)(end - i));
        bound = false;
        i = j;
      }
      off += want;
    }
    if (carry)
      put_utf8(b, &carry, 1);
    if (!done && !bound)
      pfs_put(b, "", 1);  // terminate a truncated tail
  }
  CloseHandle(h);
}

static void gen_io(struct pfs_buf *b, const struct pidfacts *f) {
  pfs_printf(b,
             "rchar: %llu\nwchar: %llu\nsyscr: %llu\nsyscw: %llu\n"
             "read_bytes: %llu\nwrite_bytes: %llu\n"
             "cancelled_write_bytes: 0\n",
             (unsigned long long)f->io.ReadTransferCount,
             (unsigned long long)f->io.WriteTransferCount,
             (unsigned long long)f->io.ReadOperationCount,
             (unsigned long long)f->io.WriteOperationCount,
             (unsigned long long)f->io.ReadTransferCount,
             (unsigned long long)f->io.WriteTransferCount);
}

static void gen_limits(struct pfs_buf *b) {
  static const struct {
    const char *name, *unit;
  } rows[] = {
      {"Max cpu time", "seconds"},     {"Max file size", "bytes"},
      {"Max data size", "bytes"},      {"Max stack size", "bytes"},
      {"Max core file size", "bytes"}, {"Max resident set", "bytes"},
      {"Max processes", "processes"},  {"Max open files", "files"},
      {"Max locked memory", "bytes"},  {"Max address space", "bytes"},
      {"Max file locks", "locks"},     {"Max pending signals", "signals"},
      {"Max msgqueue size", "bytes"},  {"Max nice priority", ""},
      {"Max realtime priority", ""},   {"Max realtime timeout", "us"},
  };
  pfs_printf(b, "%-25s %20s %20s %-10s\n", "Limit", "Soft Limit", "Hard Limit",
             "Units");
  for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
    pfs_printf(b, "%-25s %20s %20s %-10s\n", rows[i].name, "unlimited",
               "unlimited", rows[i].unit);
}

// ---------------------------------------------------------------------------
// maps and smaps. Our own address space out of VirtualQuery, image regions
// attributed to the module whose allocation they are. Served only for
// ourselves, since backtrace symbolization and memory profilers read their
// own; everyone else keeps the empty file, like environ.

typedef int32_t(__msabi *EnumModsF)(int64_t, int64_t *, uint32_t, uint32_t *);
typedef uint32_t(__msabi *ModNameF)(int64_t, int64_t, char16_t *, uint32_t);

struct ntregion {
  uint64_t base, next, off;
  char perms[5];
  const char *name;  // a path, "[stack]", or 0
  uint32_t type;     // MEM_PRIVATE, MEM_MAPPED or MEM_IMAGE
};

typedef void (*region_fn)(void *ctx, const struct ntregion *r);

static void walk_regions(region_fn fn, void *ctx) {
  static struct {
    uint64_t base;
    char path[512];
  } mods[64];
  int nmods = 0;  // statics guarded by the caller's lock
  static EnumModsF em;
  static ModNameF mn;
  if (!em) {
    em = (EnumModsF)pfs_sym(u"kernel32.dll", "K32EnumProcessModules");
    mn = (ModNameF)pfs_sym(u"kernel32.dll", "K32GetModuleFileNameExW");
  }
  int64_t handles[64];
  uint32_t need = 0;
  if (em && mn && em(-1 /* ourselves */, handles, sizeof handles, &need)) {
    nmods = (int)(need / 8);
    if (nmods > 64)
      nmods = 64;
    for (int i = 0; i < nmods; i++) {
      mods[i].base = (uint64_t)handles[i];
      char16_t w[512];
      uint32_t len = mn(-1, handles[i], w, 512);
      size_t k = put_ntpath(mods[i].path, sizeof mods[i].path - 1, w, len);
      mods[i].path[k] = 0;
    }
  }

  struct NtMemoryBasicInformation mbi;
  uint64_t addr = 0;
  uint64_t stackmark = (uint64_t)(uintptr_t)&mbi;
  while (addr < 0x7fffffff0000ull &&
         VirtualQuery((void *)addr, &mbi, sizeof mbi) == sizeof mbi) {
    uint64_t base = (uint64_t)mbi.BaseAddress, size = mbi.RegionSize;
    uint64_t next = base + size;
    if (next <= addr)
      break;
    addr = next;
    if (mbi.State != 0x1000 /* MEM_COMMIT */)
      continue;

    struct ntregion r = {.base = base, .next = next, .type = mbi.Type};
    uint32_t pr = mbi.Protect & 0xff;
    memcpy(r.perms, "---p", 5);
    if (pr & 0xee)
      r.perms[0] = 'r';  // every readable protection
    if (pr & 0xcc)
      r.perms[1] = 'w';  // RW, WRITECOPY and their X kin
    if (pr & 0xf0)
      r.perms[2] = 'x';  // the EXECUTE_* four
    if (mbi.Type == 0x40000 /* MEM_MAPPED */)
      r.perms[3] = 's';

    if (mbi.Type == 0x1000000 /* MEM_IMAGE */) {
      for (int i = 0; i < nmods; i++) {
        if (mods[i].base == (uint64_t)mbi.AllocationBase) {
          r.name = mods[i].path;
          r.off = base - mods[i].base;
          break;
        }
      }
    }
    if (!r.name && stackmark >= base && stackmark < next)
      r.name = "[stack]";
    fn(ctx, &r);
  }
}

static void put_maps_line(struct pfs_buf *b, const struct ntregion *r) {
  if (r->name && r->name[0] == '/') {
    uint64_t ino = 0xcbf29ce484222325ull;
    for (const char *c = r->name; *c; c++)
      ino = (ino ^ (uint8_t)*c) * 0x100000001b3ull;
    pfs_printf(b, "%08llx-%08llx %s %08llx 08:01 %llu %s\n",
               (unsigned long long)r->base, (unsigned long long)r->next,
               r->perms, (unsigned long long)r->off,
               (unsigned long long)(ino & 0xffffff), r->name);
  } else {
    // the kernel prints a space after the inode even with no
    // pathname; parsers count on that sixth column existing
    pfs_printf(b, "%08llx-%08llx %s %08llx 00:00 0 %s\n",
               (unsigned long long)r->base, (unsigned long long)r->next,
               r->perms, (unsigned long long)r->off, r->name ? r->name : "");
  }
}

static void maps_cb(void *ctx, const struct ntregion *r) {
  put_maps_line(ctx, r);
}

static void gen_maps(struct pfs_buf *b, uint32_t pid) {
  if (pid != pfs_self_pid())
    return;
  walk_regions(maps_cb, b);
}

// What the working set says about one region's pages, in bytes, asked in
// batches of 1024. A resident page is shared when its attributes say so,
// and then counts toward Pss divided by its share count; a page that is
// out of the working set and in the pagefile is Swap.
struct wsum {
  uint64_t rss, shared, private, pss, swap, locked;
  uint64_t dirty, anon;  // the parts of the above that are anonymous
};

static void region_ws(const struct ntregion *r, struct wsum *w) {
  static struct NtPsapiWorkingSetExInformation ws[1024];  // under pc_lock
  memset(w, 0, sizeof *w);
  for (uint64_t addr = r->base; addr < r->next;) {
    uint64_t n = (r->next - addr) / 4096;
    if (n > 1024)
      n = 1024;
    if (!n)
      break;
    for (uint64_t i = 0; i < n; i++)
      ws[i].VirtualAddress = (void *)(uintptr_t)(addr + i * 4096);
    if (!K32QueryWorkingSetEx(GetCurrentProcess(), ws,
                              (uint32_t)(n * sizeof *ws)))
      return;
    for (uint64_t i = 0; i < n; i++) {
      uint64_t a = ws[i].VirtualAttributes;
      if (a & 1) {
        w->rss += 4096;
        unsigned sc = (a >> 1) & 7;
        if (a >> 15 & 1) {
          w->shared += 4096;
          w->pss += 4096 / (sc ? sc : 1);
        } else {
          w->private += 4096;
          w->pss += 4096;
        }
        if (a >> 22 & 1)
          w->locked += 4096;
      } else if (((a >> 22) & 3) == 2) {
        w->swap += 4096;
      }
    }
    addr += n * 4096;
  }
  // the pages of a private allocation have no file behind them: every
  // resident one is anonymous and, in Linux's sense, dirty
  if (r->type == 0x20000 /* MEM_PRIVATE */) {
    w->dirty = w->rss;
    w->anon = w->rss;
  }
}

static void put_smaps_fields(struct pfs_buf *b, const struct wsum *w,
                             uint64_t size, bool rollup) {
  if (!rollup)
    pfs_printf(b, "%-16s%8llu kB\n%-16s%8llu kB\n%-16s%8llu kB\n", "Size:",
               (unsigned long long)(size / 1024), "KernelPageSize:", 4ull,
               "MMUPageSize:", 4ull);
  const struct {
    const char *name;
    uint64_t v;
  } f[] = {
      {"Rss:", w->rss},
      {"Pss:", w->pss},
      {"Pss_Dirty:", w->dirty ? w->pss : 0},
      {"Shared_Clean:", w->dirty ? 0 : w->shared},
      {"Shared_Dirty:", w->dirty ? w->shared : 0},
      {"Private_Clean:", w->dirty ? 0 : w->private},
      {"Private_Dirty:", w->dirty ? w->private : 0},
      {"Referenced:", w->rss},
      {"Anonymous:", w->anon},
      {"LazyFree:", 0},
      {"AnonHugePages:", 0},
      {"ShmemPmdMapped:", 0},
      {"FilePmdMapped:", 0},
      {"Shared_Hugetlb:", 0},
      {"Private_Hugetlb:", 0},
      {"Swap:", w->swap},
      {"SwapPss:", w->swap},
      {"Locked:", w->locked},
  };
  for (size_t i = 0; i < sizeof f / sizeof f[0]; i++)
    pfs_printf(b, "%-16s%8llu kB\n", f[i].name,
               (unsigned long long)(f[i].v / 1024));
}

static void smaps_cb(void *ctx, const struct ntregion *r) {
  struct pfs_buf *b = ctx;
  struct wsum w;
  put_maps_line(b, r);
  region_ws(r, &w);
  put_smaps_fields(b, &w, r->next - r->base, false);
  pfs_printf(b, "THPeligible:    0\nVmFlags: rd%s%s mr mw me%s\n",
             r->perms[1] == 'w' ? " wr" : "", r->perms[2] == 'x' ? " ex" : "",
             r->perms[3] == 's' ? " sh ms" : " sd");
}

static void gen_smaps(struct pfs_buf *b, uint32_t pid) {
  if (pid != pfs_self_pid())
    return;
  walk_regions(smaps_cb, b);
}

struct rollup {
  struct wsum sum;
  uint64_t lo, hi;
};

static void rollup_cb(void *ctx, const struct ntregion *r) {
  struct rollup *ru = ctx;
  struct wsum w;
  region_ws(r, &w);
  ru->sum.rss += w.rss;
  ru->sum.shared += w.shared;
  ru->sum.private += w.private;
  ru->sum.pss += w.pss;
  ru->sum.swap += w.swap;
  ru->sum.locked += w.locked;
  ru->sum.dirty += w.dirty;
  ru->sum.anon += w.anon;
  if (!ru->lo || r->base < ru->lo)
    ru->lo = r->base;
  if (r->next > ru->hi)
    ru->hi = r->next;
}

// smaps_rollup: the totals over the whole space. Dirty and clean are
// split by whether the pages came from private allocations, so the
// rollup's Shared/Private lines carry both kinds.
static void gen_smaps_rollup(struct pfs_buf *b, uint32_t pid) {
  if (pid != pfs_self_pid())
    return;
  struct rollup ru = {0};
  walk_regions(rollup_cb, &ru);
  pfs_printf(b, "%08llx-%08llx ---p 00000000 00:00 0 [rollup]\n",
             (unsigned long long)ru.lo, (unsigned long long)ru.hi);
  const struct {
    const char *name;
    uint64_t v;
  } f[] = {
      {"Rss:", ru.sum.rss},
      {"Pss:", ru.sum.pss},
      {"Pss_Dirty:", ru.sum.anon},
      {"Pss_Anon:", ru.sum.anon},
      {"Pss_File:", ru.sum.pss > ru.sum.anon ? ru.sum.pss - ru.sum.anon : 0},
      {"Pss_Shmem:", 0},
      {"Shared_Clean:", ru.sum.shared},
      {"Shared_Dirty:", 0},
      {"Private_Clean:", ru.sum.private > ru.sum.anon
                             ? ru.sum.private - ru.sum.anon
                             : 0},
      {"Private_Dirty:", ru.sum.anon},
      {"Referenced:", ru.sum.rss},
      {"Anonymous:", ru.sum.anon},
      {"LazyFree:", 0},
      {"AnonHugePages:", 0},
      {"ShmemPmdMapped:", 0},
      {"FilePmdMapped:", 0},
      {"Shared_Hugetlb:", 0},
      {"Private_Hugetlb:", 0},
      {"Swap:", ru.sum.swap},
      {"SwapPss:", ru.sum.swap},
      {"Locked:", ru.sum.locked},
  };
  for (size_t i = 0; i < sizeof f / sizeof f[0]; i++)
    pfs_printf(b, "%-16s%8llu kB\n", f[i].name,
               (unsigned long long)(f[i].v / 1024));
}

// mountinfo: the same facts as /proc/mounts in the richer per-process
// format (std's available_parallelism and friends walk it hunting cgroup
// mounts; other readers look drive roots up in it).
static void gen_mountinfo(struct pfs_buf *b) {
  pfs_printf(b, "1 1 0:1 / / rw - rootfs rootfs rw\n");
  pfs_printf(b, "2 1 0:5 / /proc rw - proc proc rw\n");
  pfs_printf(b, "3 1 0:6 / /sys rw - sysfs sysfs rw\n");
  uint32_t drives = GetLogicalDrives();
  int id = 4;
  for (int i = 0; i < 26; i++) {
    if (!(drives & 1u << i))
      continue;
    pfs_printf(b, "%d 1 8:%d / /%c rw - ntfs %c: rw\n", id++, i * 16, 'A' + i,
               'A' + i);
  }
}

bool pfs_gen_pid_file(struct pfs_buf *b, uint32_t pid, const char *name) {
  if (IsXnuSilicon())
    return pfs_xnu_gen_pid_file(b, pid, name);
  const struct pfs_proc *p = pfs_proc_find(pid);
  if (!p)
    return false;

  if (!strcmp(name, "cmdline"))
    return gen_cmdline(b, pid), true;
  if (!strcmp(name, "comm"))
    return pfs_printf(b, "%s\n", p->comm), true;
  if (!strcmp(name, "environ"))
    return gen_environ(b, pid), true;
  if (!strcmp(name, "limits"))
    return gen_limits(b), true;
  if (!strcmp(name, "maps"))
    return gen_maps(b, pid), true;
  if (!strcmp(name, "smaps"))
    return gen_smaps(b, pid), true;
  if (!strcmp(name, "smaps_rollup"))
    return gen_smaps_rollup(b, pid), true;
  if (!strcmp(name, "cgroup"))
    return pfs_printf(b, "0::/\n"), true;
  if (!strcmp(name, "mountinfo"))
    return gen_mountinfo(b), true;
  // per-process mounts: /proc/mounts is really self/mounts on Linux, and
  // plenty of callers spell out the real thing
  if (!strcmp(name, "mounts"))
    return pfs_gen_top_file(b, "mounts");
  if (!strcmp(name, "oom_score_adj") || !strcmp(name, "oom_score"))
    return pfs_printf(b, "0\n"), true;

  struct pidfacts f;
  gather(pid, &f);
  if (!strcmp(name, "stat"))
    return gen_stat(b, pid, p, &f), true;
  if (!strcmp(name, "status"))
    return gen_status(b, pid, p, &f), true;
  if (!strcmp(name, "statm"))
    return gen_statm(b, pid, &f), true;
  if (!strcmp(name, "io"))
    return gen_io(b, &f), true;
  return false;
}

bool pfs_gen_pid_volatile(uint32_t pid, struct pfs_buf out[4],
                          uint64_t *starttime) {
  if (IsXnuSilicon())
    return pfs_xnu_gen_pid_volatile(pid, out, starttime);
  const struct pfs_proc *p = pfs_proc_find(pid);
  if (!p)
    return false;
  struct pidfacts f;
  gather(pid, &f);
  if (starttime)
    *starttime = f.starttime;
  gen_stat(&out[0], pid, p, &f);
  gen_status(&out[1], pid, p, &f);
  gen_statm(&out[2], pid, &f);
  gen_io(&out[3], &f);
  return true;
}

// ---------------------------------------------------------------------------
// Links

typedef bool32(__msabi *QueryImageF)(int64_t, uint32_t, char16_t *, uint32_t *);

long pfs_pid_link(uint32_t pid, const char *name, char *buf, size_t n) {
  if (IsXnuSilicon())
    return pfs_xnu_pid_link(pid, name, buf, n);
  if (!strcmp(name, "root")) {  // no chroot to see through here
    if (n < 1)
      return -1;
    buf[0] = '/';
    return 1;
  }
  if (!strcmp(name, "cwd")) {
    if (pid != pfs_self_pid())
      return other_cwd(pid, buf, n);
    return getcwd(buf, n) ? (long)strlen(buf) : -1;
  }
  if (strcmp(name, "exe"))
    return -1;

  int64_t h = pfs_open_process(pid);
  if (!h)
    return -1;
  static QueryImageF query;
  if (!query)
    query = (QueryImageF)pfs_sym(u"kernel32.dll", "QueryFullProcessImageNameW");
  char16_t w[600];
  uint32_t len = 600;
  long r = -1;
  if (query && query(h, 0, w, &len))
    r = (long)put_ntpath(buf, n, w, len);
  CloseHandle(h);
  return r;
}

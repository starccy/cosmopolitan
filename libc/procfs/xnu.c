#include "libc/procfs/internal.h"
#include "libc/procfs/xnu.internal.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/sock/struct/sockaddr6.h"
#include "libc/sysv/consts/af.h"
#include "libc/sysv/consts/so.h"
#include "libc/sysv/consts/sock.h"
#include "libc/sysv/consts/sol.h"

// The XNU generators: the same files the NT ones emit, out of what
// libSystem answers. Shapes and field positions mirror pid.c and
// sysinfo.c so every parser sees one dialect; a fact XNU cannot answer is
// emitted as 0, never omitted.

extern char **environ;

#define NCPU_MAX 64

static uint64_t ns_jiffies(uint64_t ns) {
  return ns * (uint64_t)pfs_xnu_hz() / 1000000000ull;
}

// ---------------------------------------------------------------------------
// /proc/<pid>/*

struct facts {
  bool have_bsd, have_task, have_ru, have_vm;
  struct xnu_proc_bsdinfo bi;
  struct xnu_proc_taskinfo ti;
  struct xnu_rusage_info_v2 ru;
  // our own address space, summed the way Linux sums its VMAs: writable
  // private mappings that aren't the stack, executable read-only ones,
  // and pages the compressor or swap holds
  uint64_t data, exec, swap;
};

// one pass over our regions, the walk gen_maps makes
static void self_regions(struct facts *f) {
  uint64_t pg = (uint64_t)pfs_xnu_pagesize();
  uint64_t addr = 0;
  uint32_t depth = 0;
  for (int guard = 0; guard < 100000; guard++) {
    uint64_t a = addr, size = 0;
    struct xnu_vm_region_submap_info_64 info;
    memset(&info, 0, sizeof info);
    if (!pfs_xnu_region(&a, &size, &depth, &info))
      break;
    if (info.is_submap) {
      depth++;
      continue;
    }
    bool shared = info.share_mode == 4 /* SM_SHARED */ ||
                  info.share_mode == 5 /* SM_TRUESHARED */ ||
                  info.share_mode == 7 /* SM_SHARED_ALIASED */;
    bool stack = info.user_tag == 30; /* VM_MEMORY_STACK */
    bool w = info.protection & 2, x = info.protection & 4;
    if (x && !w)
      f->exec += size;
    else if (w && !shared && !stack)
      f->data += size;
    f->swap += (uint64_t)info.pages_swapped_out * pg;
    addr = a + size;
  }
  f->have_vm = true;
}

static void gather(uint32_t pid, struct facts *f) {
  memset(f, 0, sizeof *f);
  f->have_bsd = pfs_xnu_bsdinfo(pid, &f->bi);
  f->have_task = pfs_xnu_taskinfo(pid, &f->ti);
  f->have_ru = pfs_xnu_rusage(pid, &f->ru);
  if (pid == pfs_self_pid())
    self_regions(f);
}

static char state_of(const struct facts *f) {
  if (!f->have_bsd)
    return 'S';
  switch (f->bi.pbi_status) {  // SRUN..SZOMB, <sys/proc.h>
    case 2:
      return 'R';
    case 4:
      return 'T';
    case 5:
      return 'Z';
    default:
      return 'S';
  }
}

static uint64_t start_jiffies(const struct facts *f) {
  uint64_t boot = pfs_xnu_boottime();
  int hz = pfs_xnu_hz();
  if (!f->have_bsd || !boot || f->bi.pbi_start_tvsec < boot)
    return 0;
  return (f->bi.pbi_start_tvsec - boot) * (uint64_t)hz +
         f->bi.pbi_start_tvusec * (uint64_t)hz / 1000000;
}

static void gen_stat(struct pfs_buf *b, uint32_t pid, const struct pfs_proc *p,
                     const struct facts *f) {
  uint64_t pg = (uint64_t)pfs_xnu_pagesize();
  uint64_t utime =
      f->have_task ? ns_jiffies(pfs_xnu_mach_ns(f->ti.pti_total_user)) : 0;
  uint64_t stime =
      f->have_task ? ns_jiffies(pfs_xnu_mach_ns(f->ti.pti_total_system)) : 0;
  uint32_t threads = f->have_task && f->ti.pti_threadnum > 0
                         ? (uint32_t)f->ti.pti_threadnum
                         : 1;
  uint64_t vsize = f->have_task ? f->ti.pti_virtual_size : 0;
  uint64_t rss = f->have_task ? f->ti.pti_resident_size : 0;
  uint32_t minflt =
      f->have_task && f->ti.pti_faults > 0 ? (uint32_t)f->ti.pti_faults : 0;
  uint32_t pgid = f->have_bsd ? f->bi.pbi_pgid : pid;
  pfs_printf(b, "%u (%s) %c %u %u %u 0 -1 0 %u 0 0 0 ", pid, p->comm,
             state_of(f), p->ppid, pgid, pid, minflt);
  pfs_printf(b, "%llu %llu 0 0 20 0 %u 0 %llu %llu %llu ",
             (unsigned long long)utime, (unsigned long long)stime, threads,
             (unsigned long long)start_jiffies(f), (unsigned long long)vsize,
             (unsigned long long)(rss / pg));
  pfs_printf(b, "18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 "
                "0 0 0 0 0 0 0 0 0 0\n");
}

static void gen_status(struct pfs_buf *b, uint32_t pid,
                       const struct pfs_proc *p, const struct facts *f) {
  unsigned uid = f->have_bsd ? f->bi.pbi_uid : 0;
  unsigned gid = f->have_bsd ? f->bi.pbi_gid : 0;
  uint64_t vsize = f->have_task ? f->ti.pti_virtual_size : 0;
  uint64_t rss = f->have_task ? f->ti.pti_resident_size : 0;
  char st = state_of(f);
  pfs_printf(b, "Name:\t%s\n", p->comm);
  pfs_printf(b, "Umask:\t0022\n");
  pfs_printf(b, "State:\t%c (%s)\n", st,
             st == 'R'   ? "running"
             : st == 'Z' ? "zombie"
                         : "sleeping");
  pfs_printf(b, "Tgid:\t%u\nNgid:\t0\nPid:\t%u\nPPid:\t%u\n", pid, pid,
             p->ppid);
  pfs_printf(b, "TracerPid:\t0\n");
  pfs_printf(b, "Uid:\t%u\t%u\t%u\t%u\n", uid, uid, uid, uid);
  pfs_printf(b, "Gid:\t%u\t%u\t%u\t%u\n", gid, gid, gid, gid);
  pfs_printf(b, "FDSize:\t64\nGroups:\t%u\n", gid);
  pfs_printf(b, "VmPeak:\t%8llu kB\nVmSize:\t%8llu kB\n",
             (unsigned long long)(vsize / 1024),
             (unsigned long long)(vsize / 1024));
  pfs_printf(b, "VmHWM:\t%8llu kB\nVmRSS:\t%8llu kB\n",
             (unsigned long long)(rss / 1024),
             (unsigned long long)(rss / 1024));
  // the Vm breakdown is our own only; VmExe is the program's text and
  // VmLib the rest of what's mapped executable, as Linux splits them
  uint64_t stk = 0, exe = 0, lib = 0, data = 0, swap = 0;
  if (f->have_vm) {
    stk = pfs_self_stack();
    exe = pfs_self_text();
    if (exe > f->exec)
      exe = f->exec;
    lib = f->exec - exe;
    data = f->data;
    swap = f->swap;
  }
  pfs_printf(b,
             "VmData:\t%8llu kB\nVmStk:\t%8llu kB\n"
             "VmExe:\t%8llu kB\nVmLib:\t%8llu kB\n"
             "VmSwap:\t%8llu kB\n",
             (unsigned long long)(data / 1024), (unsigned long long)(stk / 1024),
             (unsigned long long)(exe / 1024), (unsigned long long)(lib / 1024),
             (unsigned long long)(swap / 1024));
  pfs_printf(b, "Threads:\t%u\n",
             f->have_task && f->ti.pti_threadnum > 0
                 ? (unsigned)f->ti.pti_threadnum
                 : 1);
  uint64_t blk = 0, ign = 0, cgt = 0;
  if (f->have_vm)
    pfs_self_sigs(&blk, &ign, &cgt);
  pfs_printf(b,
             "SigQ:\t0/0\nSigPnd:\t0000000000000000\n"
             "ShdPnd:\t0000000000000000\nSigBlk:\t%016llx\n"
             "SigIgn:\t%016llx\nSigCgt:\t%016llx\n"
             "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
             "CapEff:\t0000000000000000\n",
             (unsigned long long)blk, (unsigned long long)ign,
             (unsigned long long)cgt);
  // XNU counts switches, not why they happened
  pfs_printf(b,
             "voluntary_ctxt_switches:\t%llu\n"
             "nonvoluntary_ctxt_switches:\t0\n",
             (unsigned long long)(f->have_task && f->ti.pti_csw > 0
                                      ? (uint64_t)f->ti.pti_csw
                                      : 0));
}

// size resident shared text lib data dt, in pages; data is what Linux
// puts there, the data and stack segments together
static void gen_statm(struct pfs_buf *b, const struct facts *f) {
  uint64_t pg = (uint64_t)pfs_xnu_pagesize();
  uint64_t exe = 0, data = 0;
  if (f->have_vm) {
    exe = pfs_self_text();
    if (exe > f->exec)
      exe = f->exec;
    data = f->data + pfs_self_stack();
  }
  pfs_printf(
      b, "%llu %llu 0 %llu 0 %llu 0\n",
      (unsigned long long)((f->have_task ? f->ti.pti_virtual_size : 0) / pg),
      (unsigned long long)((f->have_task ? f->ti.pti_resident_size : 0) / pg),
      (unsigned long long)(exe / pg), (unsigned long long)(data / pg));
}

static void gen_io(struct pfs_buf *b, const struct facts *f) {
  uint64_t rd = f->have_ru ? f->ru.ri_diskio_bytesread : 0;
  uint64_t wr = f->have_ru ? f->ru.ri_diskio_byteswritten : 0;
  pfs_printf(b,
             "rchar: %llu\nwchar: %llu\nsyscr: 0\nsyscw: 0\n"
             "read_bytes: %llu\nwrite_bytes: %llu\n"
             "cancelled_write_bytes: 0\n",
             (unsigned long long)rd, (unsigned long long)wr,
             (unsigned long long)rd, (unsigned long long)wr);
}

// argv joined with NULs. Our own comes from the runtime verbatim; anyone
// else's is the KERN_PROCARGS2 block, which the kernel only shows for
// processes the caller could ptrace, so the rest stay empty like other
// users' files effectively do on a hardened Linux.
static void gen_cmdline(struct pfs_buf *b, uint32_t pid) {
  if (pid == pfs_self_pid()) {
    for (int i = 0; i < __argc; i++)
      pfs_put(b, __argv[i], strlen(__argv[i]) + 1);
    return;
  }
  char *raw;
  size_t len;
  if (!pfs_xnu_procargs(pid, &raw, &len))
    return;
  if (len > 4) {
    int argc;
    memcpy(&argc, raw, 4);
    const char *p = raw + 4, *end = raw + len;
    while (p < end && *p)
      p++;  // the exec path
    while (p < end && !*p)
      p++;
    // a loader-run process's first argument is the loader itself; the
    // program's own argv is what Linux would show. Only trust that when
    // argv[0] is also spelled as the loader; an exec that names the
    // program keeps its argv whole.
    int skip = 0;
    char path[1024];
    long pl = pfs_xnu_pidpath(pid, path, sizeof path - 1);
    if (pl > 0) {
      path[pl] = 0;
      if (pfs_xnu_is_loader(path) && argc > 1 && p < end &&
          pfs_xnu_is_loader(p))
        skip = 1;
    }
    for (int i = 0; i < argc && p < end; i++) {
      size_t l = strnlen(p, (size_t)(end - p));
      if (skip && i == skip && l == 1 && *p == '-')
        skip++;  // the "ape - prog" spelling
      if (i >= skip) {
        pfs_put(b, p, l);
        pfs_put(b, "", 1);
      }
      p += l + 1;
    }
  }
  free(raw);
}

// The KERN_PROCARGS2 block carries the environment after the argv strings,
// under the same may-ptrace visibility rule as the argv itself.
static void gen_environ(struct pfs_buf *b, uint32_t pid) {
  if (pid == pfs_self_pid()) {
    for (char **e = environ; *e; e++)
      pfs_put(b, *e, strlen(*e) + 1);
    return;
  }
  char *raw;
  size_t len;
  if (!pfs_xnu_procargs(pid, &raw, &len))
    return;
  if (len > 4) {
    int argc;
    memcpy(&argc, raw, 4);
    const char *p = raw + 4, *end = raw + len;
    while (p < end && *p)
      p++;  // the exec path
    while (p < end && !*p)
      p++;
    for (int i = 0; i < argc && p < end; i++) {  // past the argv
      p += strnlen(p, (size_t)(end - p));
      if (p < end)
        p++;
    }
    while (p < end && !*p)
      p++;
    while (p < end && *p) {  // env strings, until the empty one
      size_t l = strnlen(p, (size_t)(end - p));
      pfs_put(b, p, l);
      pfs_put(b, "", 1);
      p += l;
      if (p < end)
        p++;
    }
  }
  free(raw);
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

static void gen_mountinfo(struct pfs_buf *b) {
  pfs_printf(b, "1 1 0:1 / / rw - rootfs rootfs rw\n");
  pfs_printf(b, "2 1 0:5 / /proc rw - proc proc rw\n");
  pfs_printf(b, "3 1 0:6 / /sys rw - sysfs sysfs rw\n");
}

// maps and smaps. Our own address space out of the region walk, served
// only for ourselves like on NT; everyone else keeps the empty file. The
// sixth column must exist even for anonymous rows, parsers split on it.

struct xregion {
  uint64_t a, size;
  char perms[5];
  char path[512];  // empty for anonymous memory
  uint64_t ino;
  bool shared;     // mapped shared: the 's' of the perms column
  bool objshared;  // backed by an object others may map too (a file, a
                   // copy-on-write parent), whose page counts are theirs
                   // as much as ours
  struct xnu_vm_region_submap_info_64 info;
};

typedef void (*xregion_fn)(void *ctx, const struct xregion *r);

static void walk_regions(xregion_fn fn, void *ctx) {
  static struct xregion r;  // 600 bytes, under pc_lock
  uint64_t addr = 0;
  uint32_t depth = 0;
  for (int guard = 0; guard < 100000; guard++) {
    uint64_t a = addr, size = 0;
    memset(&r.info, 0, sizeof r.info);
    if (!pfs_xnu_region(&a, &size, &depth, &r.info))
      break;
    if (r.info.is_submap) {
      depth++;
      continue;
    }
    r.a = a;
    r.size = size;
    memcpy(r.perms, "---p", 5);
    if (r.info.protection & 1)
      r.perms[0] = 'r';
    if (r.info.protection & 2)
      r.perms[1] = 'w';
    if (r.info.protection & 4)
      r.perms[2] = 'x';
    r.shared = r.info.share_mode == 4 /* SM_SHARED */ ||
               r.info.share_mode == 5 /* SM_TRUESHARED */ ||
               r.info.share_mode == 7 /* SM_SHARED_ALIASED */;
    if (r.shared)
      r.perms[3] = 's';
    r.objshared = r.shared || r.info.external_pager ||
                  r.info.share_mode == 3 /* SM_COW */;
    long pl = pfs_xnu_regionfile(a, r.path, sizeof r.path - 1);
    r.path[pl > 0 ? pl : 0] = 0;
    r.ino = 0;
    if (pl > 0) {
      uint64_t ino = 0xcbf29ce484222325ull;
      for (const char *c = r.path; *c; c++)
        ino = (ino ^ (uint8_t)*c) * 0x100000001b3ull;
      r.ino = ino & 0xffffff;
    }
    fn(ctx, &r);
    addr = a + size;
  }
}

static void put_maps_line(struct pfs_buf *b, const struct xregion *r) {
  if (r->path[0]) {
    pfs_printf(b, "%08llx-%08llx %s %08llx 08:01 %llu %s\n",
               (unsigned long long)r->a, (unsigned long long)(r->a + r->size),
               r->perms, (unsigned long long)r->info.offset,
               (unsigned long long)r->ino, r->path);
  } else {
    pfs_printf(b, "%08llx-%08llx %s %08llx 00:00 0 \n",
               (unsigned long long)r->a, (unsigned long long)(r->a + r->size),
               r->perms, (unsigned long long)r->info.offset);
  }
}

static void maps_cb(void *ctx, const struct xregion *r) {
  put_maps_line(ctx, r);
}

static void gen_maps(struct pfs_buf *b, uint32_t pid) {
  if (pid != pfs_self_pid())
    return;
  walk_regions(maps_cb, b);
}

// The per-region page counts the kernel keeps, in bytes: resident,
// dirtied and swapped pages; a shared region's resident pages count toward
// Pss divided by its reference count.
//
// The kernel's resident count is per object, not per map: a region of the
// dyld shared cache (mapped copy-on-write off a file) reports every page
// of the cache that is in memory, whoever faulted it in, so summing it
// over a process's regions gives a gigabyte where the task holds a few
// megabytes. The task's own resident size (what status prints as VmRSS)
// says how much of such objects this task really maps, and the regions
// backed by them get that spread over them in proportion to their
// object-level counts; anonymous private memory is counted as is.
struct wsum {
  uint64_t rss, pss, shared, private, dirty, anon, swap, locked;
};

struct shared_scale {
  uint64_t num, den;  // shared bytes to report, over shared bytes seen
};

static void scale_cb(void *ctx, const struct xregion *r) {
  uint64_t *sum = ctx;  // [0] private resident, [1] shared resident
  uint64_t pg = (uint64_t)pfs_xnu_pagesize();
  sum[r->objshared ? 1 : 0] += (uint64_t)r->info.pages_resident * pg;
}

static struct shared_scale shared_scale(void) {
  uint64_t sum[2] = {0, 0};
  walk_regions(scale_cb, sum);
  struct xnu_proc_taskinfo ti;
  uint64_t task_rss = pfs_xnu_taskinfo(pfs_self_pid(), &ti) ? ti.pti_resident_size : 0;
  struct shared_scale s = {sum[1], sum[1]};
  if (!sum[1])
    return s;
  s.num = task_rss > sum[0] ? task_rss - sum[0] : 0;
  if (s.num > sum[1])
    s.num = sum[1];
  return s;
}

static void region_ws(const struct xregion *r, const struct shared_scale *sc,
                      struct wsum *w) {
  uint64_t pg = (uint64_t)pfs_xnu_pagesize();
  memset(w, 0, sizeof *w);
  w->rss = (uint64_t)r->info.pages_resident * pg;
  if (r->objshared && sc->den)
    w->rss = (uint64_t)((unsigned __int128)w->rss * sc->num / sc->den) &
             ~(pg - 1);
  w->dirty = (uint64_t)r->info.pages_dirtied * pg;
  if (w->dirty > w->rss)
    w->dirty = w->rss;
  w->swap = (uint64_t)r->info.pages_swapped_out * pg;
  // pages others map too are shared in Linux's sense whatever the
  // mapping's own sharing mode
  if (r->shared || (r->objshared && r->info.ref_count > 1)) {
    w->shared = w->rss;
    w->pss = w->rss / (r->info.ref_count > 1 ? r->info.ref_count : 1);
  } else {
    w->private = w->rss;
    w->pss = w->rss;
    if (!r->path[0])
      w->anon = w->rss;
  }
  if (r->info.user_wired_count)
    w->locked = r->size;
}

static void put_smaps_fields(struct pfs_buf *b, const struct wsum *w,
                             uint64_t size, bool rollup) {
  if (!rollup)
    pfs_printf(b, "%-16s%8llu kB\n%-16s%8llu kB\n%-16s%8llu kB\n", "Size:",
               (unsigned long long)(size / 1024), "KernelPageSize:",
               (unsigned long long)(pfs_xnu_pagesize() / 1024),
               "MMUPageSize:", (unsigned long long)(pfs_xnu_pagesize() / 1024));
  uint64_t clean = w->rss - w->dirty;
  const struct {
    const char *name;
    uint64_t v;
  } f[] = {
      {"Rss:", w->rss},
      {"Pss:", w->pss},
      {"Pss_Dirty:", w->shared ? 0 : w->dirty},
      {"Shared_Clean:", w->shared ? clean : 0},
      {"Shared_Dirty:", w->shared ? w->dirty : 0},
      {"Private_Clean:", w->shared ? 0 : clean},
      {"Private_Dirty:", w->shared ? 0 : w->dirty},
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

struct smaps_ctx {
  struct pfs_buf *b;
  struct shared_scale sc;
};

static void smaps_cb(void *ctx, const struct xregion *r) {
  struct smaps_ctx *c = ctx;
  struct pfs_buf *b = c->b;
  struct wsum w;
  put_maps_line(b, r);
  region_ws(r, &c->sc, &w);
  put_smaps_fields(b, &w, r->size, false);
  pfs_printf(b, "THPeligible:    0\nVmFlags: rd%s%s mr mw me%s\n",
             r->perms[1] == 'w' ? " wr" : "", r->perms[2] == 'x' ? " ex" : "",
             r->shared ? " sh ms" : " sd");
}

static void gen_smaps(struct pfs_buf *b, uint32_t pid) {
  if (pid != pfs_self_pid())
    return;
  struct smaps_ctx c = {b, shared_scale()};
  walk_regions(smaps_cb, &c);
}

struct rollup {
  struct wsum sum;
  struct shared_scale sc;
  uint64_t sdirty, pdirty, lo, hi;
};

static void rollup_cb(void *ctx, const struct xregion *r) {
  struct rollup *ru = ctx;
  struct wsum w;
  region_ws(r, &ru->sc, &w);
  ru->sum.rss += w.rss;
  ru->sum.pss += w.pss;
  ru->sum.shared += w.shared;
  ru->sum.private += w.private;
  ru->sum.anon += w.anon;
  ru->sum.swap += w.swap;
  ru->sum.locked += w.locked;
  if (r->shared || (r->objshared && r->info.ref_count > 1))
    ru->sdirty += w.dirty;
  else
    ru->pdirty += w.dirty;
  if (!ru->lo || r->a < ru->lo)
    ru->lo = r->a;
  if (r->a + r->size > ru->hi)
    ru->hi = r->a + r->size;
}

static void gen_smaps_rollup(struct pfs_buf *b, uint32_t pid) {
  if (pid != pfs_self_pid())
    return;
  struct rollup ru = {0};
  ru.sc = shared_scale();
  walk_regions(rollup_cb, &ru);
  pfs_printf(b, "%08llx-%08llx ---p 00000000 00:00 0 [rollup]\n",
             (unsigned long long)ru.lo, (unsigned long long)ru.hi);
  const struct {
    const char *name;
    uint64_t v;
  } f[] = {
      {"Rss:", ru.sum.rss},
      {"Pss:", ru.sum.pss},
      {"Pss_Dirty:", ru.pdirty},
      {"Pss_Anon:", ru.sum.anon},
      {"Pss_File:", ru.sum.pss > ru.sum.anon ? ru.sum.pss - ru.sum.anon : 0},
      {"Pss_Shmem:", 0},
      {"Shared_Clean:", ru.sum.shared - ru.sdirty},
      {"Shared_Dirty:", ru.sdirty},
      {"Private_Clean:", ru.sum.private - ru.pdirty},
      {"Private_Dirty:", ru.pdirty},
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

bool pfs_xnu_gen_pid_file(struct pfs_buf *b, uint32_t pid, const char *name) {
  const struct pfs_proc *p = pfs_xnu_proc_find(pid);
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
  if (!strcmp(name, "mounts"))
    return pfs_xnu_gen_top_file(b, "mounts");
  if (!strcmp(name, "oom_score_adj") || !strcmp(name, "oom_score"))
    return pfs_printf(b, "0\n"), true;

  struct facts f;
  gather(pid, &f);
  if (!strcmp(name, "stat"))
    return gen_stat(b, pid, p, &f), true;
  if (!strcmp(name, "status"))
    return gen_status(b, pid, p, &f), true;
  if (!strcmp(name, "statm"))
    return gen_statm(b, &f), true;
  if (!strcmp(name, "io"))
    return gen_io(b, &f), true;
  return false;
}

bool pfs_xnu_gen_pid_volatile(uint32_t pid, struct pfs_buf out[4],
                              uint64_t *starttime) {
  const struct pfs_proc *p = pfs_xnu_proc_find(pid);
  if (!p)
    return false;
  struct facts f;
  gather(pid, &f);
  if (starttime)
    *starttime = start_jiffies(&f);
  gen_stat(&out[0], pid, p, &f);
  gen_status(&out[1], pid, p, &f);
  gen_statm(&out[2], &f);
  gen_io(&out[3], &f);
  return true;
}

long pfs_xnu_pid_link(uint32_t pid, const char *name, char *buf, size_t n) {
  if (!strcmp(name, "root")) {  // no chroot to see through here
    if (n < 1)
      return -1;
    buf[0] = '/';
    return 1;
  }
  if (!strcmp(name, "cwd")) {
    if (pid == pfs_self_pid())
      return getcwd(buf, n) ? (long)strlen(buf) : -1;
    return pfs_xnu_cwd(pid, buf, n);
  }
  if (strcmp(name, "exe"))
    return -1;
  if (pid == pfs_self_pid()) {
    // the kernel would name the ape loader; the program is the answer
    const char *exe = GetProgramExecutableName();
    if (!exe || exe[0] != '/')
      return -1;
    size_t l = strlen(exe);
    if (l > n)
      l = n;
    memcpy(buf, exe, l);
    return (long)l;
  }
  // the kernel names the loader for other ape processes too; answer with
  // the program, absolutized against their cwd when spelled relative
  char tmp[1024];
  long r = pfs_xnu_pidpath(pid, tmp, sizeof tmp - 1);
  if (r <= 0)
    return -1;
  tmp[r] = 0;
  if (pfs_xnu_is_loader(tmp)) {
    char prog[512];
    long pr = pfs_xnu_ape_program(pid, prog, sizeof prog - 1);
    if (pr > 0) {
      prog[pr] = 0;
      const char *rel = prog;
      if (rel[0] == '.' && rel[1] == '/')
        rel += 2;
      if (rel[0] == '/') {
        snprintf(tmp, sizeof tmp, "%s", rel);
      } else {
        char cwd[512];
        long cl = pfs_xnu_cwd(pid, cwd, sizeof cwd - 1);
        if (cl > 0) {
          cwd[cl] = 0;
          snprintf(tmp, sizeof tmp, "%s/%s", cwd, rel);
        }
      }
    }
  }
  size_t l = strlen(tmp);
  if (l > n)
    l = n;
  memcpy(buf, tmp, l);
  return (long)l;
}

// ---------------------------------------------------------------------------
// The top-level files.

static void gen_meminfo(struct pfs_buf *b) {
  uint64_t pg = (uint64_t)pfs_xnu_pagesize();
  uint64_t mem = 0;
  size_t l = sizeof mem;
  pfs_xnu_sysctl("hw.memsize", &mem, &l);
  struct xnu_vm_statistics64 vm;
  bool have_vm = pfs_xnu_vmstat(&vm);
  struct xnu_xsw_usage sw = {0};
  l = sizeof sw;
  pfs_xnu_sysctl("vm.swapusage", &sw, &l);
  uint64_t freeb = have_vm ? (uint64_t)vm.free_count * pg : 0;
  uint64_t avail =
      have_vm
          ? ((uint64_t)vm.free_count + vm.inactive_count + vm.purgeable_count) *
                pg
          : 0;
  pfs_printf(b, "MemTotal:       %8llu kB\n", (unsigned long long)(mem / 1024));
  pfs_printf(b, "MemFree:        %8llu kB\n",
             (unsigned long long)(freeb / 1024));
  pfs_printf(b, "MemAvailable:   %8llu kB\n",
             (unsigned long long)(avail / 1024));
  pfs_printf(b, "Buffers:               0 kB\n");
  pfs_printf(b, "Cached:         %8llu kB\n",
             (unsigned long long)(have_vm ? (uint64_t)vm.external_page_count *
                                                pg / 1024
                                          : 0));
  pfs_printf(b, "SwapCached:            0 kB\n");
  pfs_printf(
      b, "Active:         %8llu kB\n",
      (unsigned long long)(have_vm ? (uint64_t)vm.active_count * pg / 1024
                                   : 0));
  pfs_printf(
      b, "Inactive:       %8llu kB\n",
      (unsigned long long)(have_vm ? (uint64_t)vm.inactive_count * pg / 1024
                                   : 0));
  pfs_printf(b, "SwapTotal:      %8llu kB\n",
             (unsigned long long)(sw.xsu_total / 1024));
  pfs_printf(b, "SwapFree:       %8llu kB\n",
             (unsigned long long)(sw.xsu_avail / 1024));
  pfs_printf(b, "Dirty:                 0 kB\nWriteback:             0 kB\n"
                "Mapped:                0 kB\nShmem:                 0 kB\n"
                "Slab:                  0 kB\n");
  pfs_printf(b, "CommitLimit:    %8llu kB\n",
             (unsigned long long)((mem + sw.xsu_total) / 1024));
  pfs_printf(b, "Committed_AS:   %8llu kB\n",
             (unsigned long long)(have_vm ? ((uint64_t)vm.active_count +
                                             vm.wire_count) *
                                                pg / 1024
                                          : 0));
  pfs_printf(b, "VmallocTotal:          0 kB\nVmallocUsed:           0 kB\n"
                "VmallocChunk:          0 kB\n");
}

static void gen_uptime(struct pfs_buf *b) {
  uint64_t boot = pfs_xnu_boottime();
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  uint64_t up =
      boot && (uint64_t)now.tv_sec > boot ? (uint64_t)now.tv_sec - boot : 0;
  struct xnu_cpu_ticks t[NCPU_MAX];
  int n = pfs_xnu_cpu_ticks(t, NCPU_MAX);
  uint64_t idle = 0;
  for (int i = 0; i < n; i++)
    idle += t[i].idle;
  idle /= (uint64_t)pfs_xnu_hz();
  pfs_printf(b, "%llu.00 %llu.00\n", (unsigned long long)up,
             (unsigned long long)idle);
}

static void gen_stat_top(struct pfs_buf *b) {
  struct xnu_cpu_ticks t[NCPU_MAX];
  int n = pfs_xnu_cpu_ticks(t, NCPU_MAX);
  struct xnu_cpu_ticks sum = {0};
  for (int i = 0; i < n; i++) {
    sum.user += t[i].user;
    sum.nice += t[i].nice;
    sum.system += t[i].system;
    sum.idle += t[i].idle;
  }
  pfs_printf(b, "cpu  %llu %llu %llu %llu 0 0 0 0 0 0\n",
             (unsigned long long)sum.user, (unsigned long long)sum.nice,
             (unsigned long long)sum.system, (unsigned long long)sum.idle);
  for (int i = 0; i < n; i++)
    pfs_printf(b, "cpu%d %llu %llu %llu %llu 0 0 0 0 0 0\n", i,
               (unsigned long long)t[i].user, (unsigned long long)t[i].nice,
               (unsigned long long)t[i].system, (unsigned long long)t[i].idle);
  const struct pfs_proc *p;
  int nproc = pfs_xnu_procs(&p);
  pfs_printf(b,
             "intr 0\nctxt 0\nbtime %llu\nprocesses %d\n"
             "procs_running 1\nprocs_blocked 0\n",
             (unsigned long long)pfs_xnu_boottime(), nproc > 0 ? nproc : 1);
}

static void gen_loadavg(struct pfs_buf *b) {
  struct {  // <sys/sysctl.h> struct loadavg
    uint32_t ldavg[3];
    uint32_t pad;
    int64_t fscale;
  } la = {{0, 0, 0}, 0, 1};
  size_t l = sizeof la;
  pfs_xnu_sysctl("vm.loadavg", &la, &l);
  double fs = la.fscale > 0 ? (double)la.fscale : 1.0;
  const struct pfs_proc *p;
  int nproc = pfs_xnu_procs(&p);
  pfs_printf(b, "%.2f %.2f %.2f 1/%d %d\n", la.ldavg[0] / fs, la.ldavg[1] / fs,
             la.ldavg[2] / fs, nproc > 0 ? nproc : 1, (int)pfs_self_pid());
}

// the Features line of /proc/cpuinfo, with linux's hwcap names, from the
// hw.optional.arm.FEAT_* sysctls
static const struct {
  const char *sysctl;
  const char *name;
} pfs_xnu_hwcaps[] = {
    {"hw.optional.arm.FEAT_AES", "aes"},
    {"hw.optional.arm.FEAT_PMULL", "pmull"},
    {"hw.optional.arm.FEAT_SHA1", "sha1"},
    {"hw.optional.arm.FEAT_SHA256", "sha2"},
    {"hw.optional.arm.FEAT_CRC32", "crc32"},
    {"hw.optional.arm.FEAT_LSE", "atomics"},
    {"hw.optional.arm.FEAT_FP16", "fphp"},
    {"hw.optional.arm.FEAT_FP16", "asimdhp"},
    {"hw.optional.arm.FEAT_RDM", "asimdrdm"},
    {"hw.optional.arm.FEAT_JSCVT", "jscvt"},
    {"hw.optional.arm.FEAT_FCMA", "fcma"},
    {"hw.optional.arm.FEAT_LRCPC", "lrcpc"},
    {"hw.optional.arm.FEAT_DPB", "dcpop"},
    {"hw.optional.arm.FEAT_SHA3", "sha3"},
    {"hw.optional.arm.FEAT_DotProd", "asimddp"},
    {"hw.optional.arm.FEAT_SHA512", "sha512"},
    {"hw.optional.arm.FEAT_SVE", "sve"},
    {"hw.optional.arm.FEAT_FHM", "asimdfhm"},
    {"hw.optional.arm.FEAT_DIT", "dit"},
    {"hw.optional.arm.FEAT_LSE2", "uscat"},
    {"hw.optional.arm.FEAT_LRCPC2", "ilrcpc"},
    {"hw.optional.arm.FEAT_FlagM", "flagm"},
    {"hw.optional.arm.FEAT_SSBS", "ssbs"},
    {"hw.optional.arm.FEAT_SB", "sb"},
    {"hw.optional.arm.FEAT_PAuth", "paca"},
    {"hw.optional.arm.FEAT_PAuth", "pacg"},
    {"hw.optional.arm.FEAT_DPB2", "dcpodp"},
    {"hw.optional.arm.FEAT_FlagM2", "flagm2"},
    {"hw.optional.arm.FEAT_FRINTTS", "frint"},
    {"hw.optional.arm.FEAT_I8MM", "i8mm"},
    {"hw.optional.arm.FEAT_BF16", "bf16"},
    {"hw.optional.arm.FEAT_BTI", "bti"},
    {"hw.optional.arm.FEAT_ECV", "ecv"},
    {"hw.optional.arm.FEAT_AFP", "afp"},
    {"hw.optional.arm.FEAT_RPRES", "rpres"},
    {"hw.optional.arm.FEAT_MTE2", "mte"},
    {"hw.optional.arm.FEAT_MTE3", "mte3"},
    {"hw.optional.arm.FEAT_SME", "sme"},
    {"hw.optional.arm.FEAT_EBF16", "ebf16"},
    {"hw.optional.arm.FEAT_WFxT", "wfxt"},
    {"hw.optional.arm.FEAT_SME2", "sme2"},
    {"hw.optional.arm.FEAT_CSSC", "cssc"},
    {"hw.optional.arm.FEAT_HBC", "hbc"},
};

static void pfs_xnu_features(struct pfs_buf *b) {
  pfs_printf(b, "Features\t: fp asimd");
  for (size_t i = 0; i < ARRAYLEN(pfs_xnu_hwcaps); i++) {
    int v = 0;
    size_t l = sizeof v;
    if (!pfs_xnu_sysctl(pfs_xnu_hwcaps[i].sysctl, &v, &l) && v)
      pfs_printf(b, " %s", pfs_xnu_hwcaps[i].name);
  }
  pfs_printf(b, "\n");
}

static void gen_cpuinfo(struct pfs_buf *b) {
  int n = 0;
  size_t l = sizeof n;
  pfs_xnu_sysctl("hw.ncpu", &n, &l);
  if (n <= 0)
    n = 1;
  char brand[128] = "unknown";
  l = sizeof brand - 1;
  if (pfs_xnu_sysctl("machdep.cpu.brand_string", brand, &l) == 0)
    brand[l < sizeof brand ? l : sizeof brand - 1] = 0;
  for (int c = 0; c < n; c++) {
    pfs_printf(b, "processor\t: %d\n", c);
    pfs_printf(b, "model name\t: %s\n", brand);
    pfs_printf(b, "BogoMIPS\t: 0.00\n");
    pfs_xnu_features(b);
    pfs_printf(b, "CPU implementer\t: 0x61\n");  // Apple
    pfs_printf(b, "CPU architecture: 8\n\n");
  }
}

static void gen_mounts(struct pfs_buf *b) {
  pfs_printf(b, "rootfs / rootfs rw 0 0\n");
  pfs_printf(b, "proc /proc proc rw 0 0\n");
  pfs_printf(b, "sysfs /sys sysfs rw 0 0\n");
  pfs_printf(b, "apfs / apfs rw 0 0\n");
}

static void gen_cmdline_top(struct pfs_buf *b) {
  char args[1024] = "";
  size_t l = sizeof args - 1;
  if (pfs_xnu_sysctl("kern.bootargs", args, &l) == 0 && l < sizeof args)
    args[l] = 0;
  pfs_printf(b, "%s\n", args);
}

bool pfs_xnu_gen_top_file(struct pfs_buf *b, const char *name) {
  if (!strcmp(name, "meminfo"))
    return gen_meminfo(b), true;
  if (!strcmp(name, "uptime"))
    return gen_uptime(b), true;
  if (!strcmp(name, "stat"))
    return gen_stat_top(b), true;
  if (!strcmp(name, "loadavg"))
    return gen_loadavg(b), true;
  if (!strcmp(name, "cpuinfo"))
    return gen_cpuinfo(b), true;
  if (!strcmp(name, "mounts"))
    return gen_mounts(b), true;
  if (!strcmp(name, "diskstats"))
    return pfs_xnu_diskstats(b), true;
  if (!strcmp(name, "partitions"))
    return pfs_xnu_partitions(b), true;
  if (!strcmp(name, "cmdline"))
    return gen_cmdline_top(b), true;
  if (!strcmp(name, "version"))
    return pfs_printf(b, "%s version %s (%s)\n", pfs_kernel_sysname(),
                      pfs_kernel_release(), pfs_kernel_version()),
           true;
  if (!strcmp(name, "filesystems"))
    return pfs_printf(b, "nodev\tsysfs\nnodev\tproc\nnodev\ttmpfs\n"
                         "\tapfs\n\thfs\n"),
           true;
  if (!strcmp(name, "swaps"))
    return pfs_printf(b, "Filename\t\t\t\tType\t\tSize\t\tUsed\t\t"
                         "Priority\n"),
           true;
  return false;
}

// ---------------------------------------------------------------------------
// /proc/net/*. The socket tables come from pcblist64 and the interface
// counters from NET_RT_IFLIST2, the same sources netstat reads. A row's
// inode is the shared identity hash with pid 0, since the tables do not
// name the owner; the self fd/ links hash the same way so the join holds.

// The Linux table states, from XNU's TCPS_* order.
static int tcp_state_of(int t_state) {
  static const int map[] = {7, 10, 2, 3, 1, 8, 4, 11, 9, 5, 6};
  return t_state >= 0 && t_state < 11 ? map[t_state] : 7;
}

static void put_addr(struct pfs_buf *b, bool v6, const uint8_t *a,
                     uint16_t port) {
  if (v6) {
    uint32_t w[4];
    memcpy(w, a, 16);
    pfs_printf(b, "%08X%08X%08X%08X:%04X", w[0], w[1], w[2], w[3], port);
  } else {
    uint32_t w;
    memcpy(&w, a, 4);
    pfs_printf(b, "%08X:%04X", w, port);
  }
}

// Every socket of one protocol's pcb list, with its Linux state.
typedef void (*pcb_fn)(void *ctx, const struct xnu_xinpcb64 *inp, int state);

static void pcb_walk(bool tcp, pcb_fn fn, void *ctx) {
  char *raw;
  size_t len;
  if (!pfs_xnu_pcblist(
          tcp ? "net.inet.tcp.pcblist64" : "net.inet.udp.pcblist64", &raw,
          &len))
    return;
  const char *p = raw, *end = raw + len;
  if ((size_t)(end - p) < sizeof(struct xnu_xinpgen)) {
    free(raw);
    return;
  }
  const struct xnu_xinpgen *gen = (const void *)p;
  if (!gen->xig_len || gen->xig_len > (size_t)(end - p)) {
    free(raw);
    return;
  }
  p += gen->xig_len;
  while (p + sizeof(struct xnu_xinpgen) <= end) {
    uint32_t rlen;
    memcpy(&rlen, p, 4);  // xt_len and the low half of xi_len lead both
    if (rlen < sizeof(struct xnu_xinpgen) || rlen > (size_t)(end - p))
      break;
    const struct xnu_xinpcb64 *inp;
    int state = 7;  // Linux TCP_CLOSE, what UDP rows show
    if (tcp) {
      if (rlen < sizeof(struct xnu_xtcpcb64))
        break;
      const struct xnu_xtcpcb64 *tp = (const void *)p;
      inp = &tp->xt_inpcb;
      state = tcp_state_of(tp->t_state);
    } else {
      if (rlen < sizeof(struct xnu_xinpcb64))
        break;
      inp = (const void *)p;
    }
    p += rlen;
    fn(ctx, inp, state);
  }
  free(raw);
}

struct table_ctx {
  struct pfs_buf *b;
  bool tcp, v6;
  int sl;
};

static void table_row(void *ctx, const struct xnu_xinpcb64 *inp, int state) {
  struct table_ctx *t = ctx;
  struct pfs_buf *b = t->b;
  bool tcp = t->tcp, v6 = t->v6;
  {
    bool row6 = (inp->inp_vflag & 2) != 0;  // INP_IPV6
    if (row6 != v6)
      return;
    uint16_t lport = __builtin_bswap16(inp->inp_lport);
    uint16_t rport = __builtin_bswap16(inp->inp_fport);
    uint8_t laddr[16] = {0}, raddr[16] = {0};
    if (v6) {
      memcpy(laddr, inp->inp_dependladdr.a6, 16);
      memcpy(raddr, inp->inp_dependfaddr.a6, 16);
    } else {
      memcpy(laddr, &inp->inp_dependladdr.a4.addr4, 4);
      memcpy(raddr, &inp->inp_dependfaddr.a4.addr4, 4);
    }
    uint64_t inode =
        pfs_net_inode(tcp ? 0 : 1, v6 ? 6 : 4, 0, lport, rport, laddr, raddr);
    pfs_printf(b, "%4d: ", t->sl++);
    put_addr(b, v6, laddr, lport);
    pfs_put(b, " ", 1);
    put_addr(b, v6, raddr, rport);
    pfs_printf(b,
               " %02X %08X:%08X 00:00000000 00000000 %5u        0 "
               "%llu 1 0000000000000000 0 0 0 0 0\n",
               state, inp->xi_socket.so_snd.sb_cc, inp->xi_socket.so_rcv.sb_cc,
               inp->xi_socket.so_uid, (unsigned long long)inode);
  }
}

static void net_table(struct pfs_buf *b, const char *name) {
  struct table_ctx t = {b, name[0] == 't', strchr(name, '6') != 0, 0};
  pfs_printf(b, "  sl  local_address rem_address   st tx_queue rx_queue "
                "tr tm->when retrnsmt   uid  timeout inode\n");
  pcb_walk(t.tcp, table_row, &t);
}

static void count_estab(void *ctx, const struct xnu_xinpcb64 *inp, int state) {
  (void)inp;
  if (state == 1)
    (*(int *)ctx)++;
}

// ---------------------------------------------------------------------------
// /proc/net/route and arp out of the routing socket's dump: rt_msghdr
// records (92 bytes: index at 4, flags at 8, addrs at 12, the 56-byte
// metrics at 36 with the hop count at 44) each followed by the sockaddrs
// its addrs bits name, every one rounded up to 4 bytes and a length of 0
// taking 4. A netmask sockaddr is cut short after its last nonzero byte.
// Offsets checked against the SDK's <net/route.h> on macOS 26.

#define XNU_RTM_HDR     92
#define XNU_RTA_DST     0x1
#define XNU_RTA_GATEWAY 0x2
#define XNU_RTA_NETMASK 0x4
#define XNU_RTF_UP      0x1
#define XNU_RTF_GATEWAY 0x2
#define XNU_RTF_HOST    0x4
#define XNU_RTF_STATIC  0x800
#define XNU_RTF_LLINFO  0x400
#define XNU_RTF_CLONED  0x20000
#define XNU_RTF_BCAST   0x400000
#define XNU_RTF_MCAST   0x800000
#define XNU_AF_INET     2
#define XNU_AF_LINK     18
#define XNU_NET_RT_DUMP 1
#define XNU_NET_RT_FLAGS 2

struct rtrec {
  uint16_t index;
  int32_t flags, addrs;
  uint32_t hopcount;
  const uint8_t *sa[8];  // by RTA bit, 0 when absent
};

static bool rt_parse(const uint8_t *p, size_t m, struct rtrec *r) {
  memset(r, 0, sizeof *r);
  if (m < XNU_RTM_HDR)
    return false;
  memcpy(&r->index, p + 4, 2);
  memcpy(&r->flags, p + 8, 4);
  memcpy(&r->addrs, p + 12, 4);
  memcpy(&r->hopcount, p + 44, 4);
  const uint8_t *sa = p + XNU_RTM_HDR, *end = p + m;
  for (int bit = 0; bit < 8 && sa < end; bit++) {
    if (!(r->addrs & 1 << bit))
      continue;
    r->sa[bit] = sa;
    size_t len = sa[0] ? (sa[0] + 3) & ~3u : 4;
    sa += len;
  }
  return true;
}

// an AF_INET sockaddr's address as the network-order word Linux prints;
// a shortened netmask reads as zeros past its length
static uint32_t sa_inet(const uint8_t *sa) {
  uint8_t a[4] = {0};
  if (!sa)
    return 0;
  size_t len = sa[0];
  for (size_t i = 4; i < 8 && i < len; i++)
    a[i - 4] = sa[i];
  uint32_t w;
  memcpy(&w, a, 4);
  return w;
}

static void xnu_if_name_of(uint32_t index, char *out, size_t n) {
  struct pfs_ifstat ifs[32];
  int k = pfs_xnu_ifstats(ifs, 32);
  for (int i = 0; i < k; i++) {
    if (ifs[i].index == index) {
      snprintf(out, n, "%s", ifs[i].name);
      return;
    }
  }
  snprintf(out, n, "if%u", index);
}

// the kernel pads every line of this file to 127 columns
static void pad_line(struct pfs_buf *b, size_t from) {
  size_t len = b->n - from;
  while (len++ < 127)
    pfs_put(b, " ", 1);
  pfs_put(b, "\n", 1);
}

// Cloned host routes, neighbor entries and the multicast and broadcast
// rows are what BSD keeps in its table and Linux keeps elsewhere.
static void net_route(struct pfs_buf *b) {
  size_t from = b->n;
  pfs_printf(b, "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\t"
                "Mask\t\tMTU\tWindow\tIRTT");
  pad_line(b, from);
  char *raw;
  size_t len;
  if (!pfs_xnu_rtdump(XNU_AF_INET, XNU_NET_RT_DUMP, 0, &raw, &len))
    return;
  const uint8_t *p = (const uint8_t *)raw, *end = p + len;
  while (p + XNU_RTM_HDR <= end) {
    uint16_t m;
    memcpy(&m, p, 2);
    if (m < XNU_RTM_HDR || m > end - p)
      break;
    struct rtrec r;
    rt_parse(p, m, &r);
    p += m;
    if (!(r.flags & XNU_RTF_UP) ||
        (r.flags & (XNU_RTF_LLINFO | XNU_RTF_CLONED | XNU_RTF_BCAST |
                    XNU_RTF_MCAST)))
      continue;
    const uint8_t *dst = r.sa[0], *gw = r.sa[1], *mask = r.sa[2];
    if (!dst || dst[1] != XNU_AF_INET)
      continue;
    uint32_t gateway = 0;
    unsigned flags = 1;
    if (r.flags & XNU_RTF_GATEWAY) {
      flags |= 2;
      if (gw && gw[1] == XNU_AF_INET)
        gateway = sa_inet(gw);
    }
    uint32_t netmask = mask ? sa_inet(mask) : 0;
    if (r.flags & XNU_RTF_HOST) {
      flags |= 4;
      netmask = 0xffffffffu;
    }
    char name[16];
    xnu_if_name_of(r.index, name, sizeof name);
    from = b->n;
    pfs_printf(b, "%s\t%08X\t%08X\t%04X\t0\t0\t%u\t%08X\t0\t0\t0", name,
               sa_inet(dst), gateway, flags, r.hopcount, netmask);
    pad_line(b, from);
  }
  free(raw);
}

static void net_arp(struct pfs_buf *b) {
  pfs_printf(b, "IP address       HW type     Flags       HW address       "
                "     Mask     Device\n");
  char *raw;
  size_t len;
  if (!pfs_xnu_rtdump(XNU_AF_INET, XNU_NET_RT_FLAGS, XNU_RTF_LLINFO, &raw,
                      &len))
    return;
  const uint8_t *p = (const uint8_t *)raw, *end = p + len;
  while (p + XNU_RTM_HDR <= end) {
    uint16_t m;
    memcpy(&m, p, 2);
    if (m < XNU_RTM_HDR || m > end - p)
      break;
    struct rtrec r;
    rt_parse(p, m, &r);
    p += m;
    const uint8_t *dst = r.sa[0], *gw = r.sa[1];
    if (!dst || dst[1] != XNU_AF_INET || !gw || gw[1] != XNU_AF_LINK)
      continue;
    const uint8_t *ip = dst + 4;
    if ((ip[0] & 0xf0) == 0xe0)
      continue;
    uint8_t nlen = gw[5], alen = gw[6];
    const uint8_t *mac = gw + 8 + nlen;
    if (alen == 6 && mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff &&
        mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff)
      continue;
    unsigned flags = alen ? 0x2 : 0;
    if (r.flags & XNU_RTF_STATIC)
      flags |= 0x4;
    char ipstr[16], hw[18], name[16];
    snprintf(ipstr, sizeof ipstr, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    snprintf(hw, sizeof hw, "%02x:%02x:%02x:%02x:%02x:%02x",
             alen > 0 ? mac[0] : 0, alen > 1 ? mac[1] : 0, alen > 2 ? mac[2] : 0,
             alen > 3 ? mac[3] : 0, alen > 4 ? mac[4] : 0,
             alen > 5 ? mac[5] : 0);
    uint16_t ifindex;
    memcpy(&ifindex, gw + 2, 2);
    xnu_if_name_of(ifindex ? ifindex : r.index, name, sizeof name);
    pfs_printf(b, "%-16s 0x%-10x0x%-10x%s     *        %s\n", ipstr, 1, flags,
               hw, name);
  }
  free(raw);
}

// /proc/net/snmp out of the protocol counter blocks. The structures are
// private to xnu (bsd/netinet/{ip,udp,icmp}_var.h); only fields appended
// over the years, so the leading u32s read here are stable, and the
// sizes the sysctls answer were checked against the headers. TCP's block
// reads as zeros on current macOS, as the host's own netstat shows, so
// the established count comes from the pcb list instead.
static uint32_t stat_u32(const uint32_t *v, size_t n, size_t i) {
  return i < n ? v[i] : 0;
}

static void net_snmp(struct pfs_buf *b) {
  static uint32_t ip[64], tcp[256], udp[32], icmp[128];  // under pc_lock
  size_t lip = sizeof ip, ltcp = sizeof tcp, ludp = sizeof udp,
         licmp = sizeof icmp;
  memset(ip, 0, sizeof ip);
  memset(tcp, 0, sizeof tcp);
  memset(udp, 0, sizeof udp);
  memset(icmp, 0, sizeof icmp);
  if (pfs_xnu_sysctl("net.inet.ip.stats", ip, &lip))
    lip = 0;
  if (pfs_xnu_sysctl("net.inet.tcp.stats", tcp, &ltcp))
    ltcp = 0;
  if (pfs_xnu_sysctl("net.inet.udp.stats", udp, &ludp))
    ludp = 0;
  if (pfs_xnu_sysctl("net.inet.icmp.stats", icmp, &licmp))
    licmp = 0;
  size_t nip = lip / 4, ntcp = ltcp / 4, nudp = ludp / 4, nicmp = licmp / 4;
#define IP(i)   stat_u32(ip, nip, i)
#define TCP(i)  stat_u32(tcp, ntcp, i)
#define UDP(i)  stat_u32(udp, nudp, i)
#define ICMP(i) stat_u32(icmp, nicmp, i)
  int fwd = 0, ttl = 64;
  size_t l = sizeof fwd;
  pfs_xnu_sysctl("net.inet.ip.forwarding", &fwd, &l);
  l = sizeof ttl;
  pfs_xnu_sysctl("net.inet.ip.ttl", &ttl, &l);

  // ipstat: total badsum tooshort toosmall badhlen badlen fragments
  // fragdropped fragtimeout forward fastforward cantforward redirectsent
  // noproto delivered localout odropped reassembled fragmented ofragments
  // cantfrag badoptions noroute badvers rawout toolong notmember nogif
  // badaddr
  pfs_printf(b, "Ip: Forwarding DefaultTTL InReceives InHdrErrors "
                "InAddrErrors ForwDatagrams InUnknownProtos InDiscards "
                "InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout "
                "ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates "
                "OutTransmits\n");
  pfs_printf(b, "Ip: %d %d %u %u %u %u %u 0 %u %u %u %u %u %u %u %u %u %u %u "
                "%u\n",
             fwd ? 1 : 2, ttl, IP(0),
             IP(1) + IP(2) + IP(3) + IP(4) + IP(5) + IP(23) + IP(25),
             IP(11) + IP(28), IP(9), IP(13), IP(14), IP(15), IP(16), IP(22),
             IP(8), IP(6), IP(17), IP(7) + IP(8), IP(18), IP(20), IP(19),
             IP(15) + IP(9));

  // icmpstat: error oldshort oldicmp outhist[41] badcode tooshort checksum
  // badlen reflect inhist[41] ...
  uint32_t inmsgs = 0, outmsgs = 0;
  for (int t = 0; t <= 40; t++) {
    inmsgs += ICMP(49 + t);
    outmsgs += ICMP(3 + t);
  }
  uint32_t inerr = ICMP(44) + ICMP(45) + ICMP(46) + ICMP(47);
  pfs_printf(b, "Icmp: InMsgs InErrors InCsumErrors InDestUnreachs "
                "InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos "
                "InEchoReps InTimestamps InTimestampReps InAddrMasks "
                "InAddrMaskReps OutMsgs OutErrors OutRateLimitGlobal "
                "OutRateLimitHost OutDestUnreachs OutTimeExcds OutParmProbs "
                "OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps "
                "OutTimestampReps OutAddrMasks OutAddrMaskReps\n");
  pfs_printf(b, "Icmp: %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u 0 0 0 %u "
                "%u %u %u %u %u %u %u %u %u %u\n",
             inmsgs + inerr, inerr, ICMP(46), ICMP(49 + 3), ICMP(49 + 11),
             ICMP(49 + 12), ICMP(49 + 4), ICMP(49 + 5), ICMP(49 + 8),
             ICMP(49 + 0), ICMP(49 + 13), ICMP(49 + 14), ICMP(49 + 17),
             ICMP(49 + 18), outmsgs, ICMP(3 + 3), ICMP(3 + 11), ICMP(3 + 12),
             ICMP(3 + 4), ICMP(3 + 5), ICMP(3 + 8), ICMP(3 + 0), ICMP(3 + 13),
             ICMP(3 + 14), ICMP(3 + 17), ICMP(3 + 18));
  bool any = false;
  for (int t = 0; t <= 40; t++)
    any |= ICMP(49 + t) || ICMP(3 + t);
  if (any) {
    pfs_printf(b, "IcmpMsg:");
    for (int t = 0; t <= 40; t++) {
      if (ICMP(49 + t))
        pfs_printf(b, " InType%d", t);
      if (ICMP(3 + t))
        pfs_printf(b, " OutType%d", t);
    }
    pfs_printf(b, "\nIcmpMsg:");
    for (int t = 0; t <= 40; t++) {
      if (ICMP(49 + t))
        pfs_printf(b, " %u", ICMP(49 + t));
      if (ICMP(3 + t))
        pfs_printf(b, " %u", ICMP(3 + t));
    }
    pfs_printf(b, "\n");
  }

  // tcpstat: connattempt accepts connects drops conndrops closed segstimed
  // rttupdated delack timeoutdrop rexmttimeo persisttimeo keeptimeo
  // keepprobe keepdrops sndtotal sndpack sndbyte sndrexmitpack
  // sndrexmitbyte sndacks sndprobe sndurg sndwinup sndctrl rcvtotal
  // rcvpack rcvbyte rcvbadsum rcvbadoff rcvmemdrop rcvshort ...
  int estab = 0;
  pcb_walk(true, count_estab, &estab);
  pfs_printf(b, "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens "
                "PassiveOpens AttemptFails EstabResets CurrEstab InSegs "
                "OutSegs RetransSegs InErrs OutRsts InCsumErrors\n");
  pfs_printf(b, "Tcp: 1 200 120000 -1 %u %u %u %u %d %u %u %u %u 0 %u\n",
             TCP(0), TCP(1), TCP(4), TCP(3), estab, TCP(25), TCP(15), TCP(18),
             TCP(28) + TCP(29) + TCP(31), TCP(28));

  // udpstat: ipackets hdrops badsum badlen noport noportbcast fullsock
  // pcbcachemiss pcbhashmiss opackets ...
  uint32_t inerrs = UDP(1) + UDP(2) + UDP(3) + UDP(6);
  uint32_t noports = UDP(4) + UDP(5);
  uint32_t delivered = UDP(0) > inerrs + noports ? UDP(0) - inerrs - noports
                                                 : 0;
  pfs_printf(b, "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors "
                "SndbufErrors InCsumErrors IgnoredMulti MemErrors\n");
  pfs_printf(b, "Udp: %u %u %u %u %u 0 %u 0 0\n", delivered, noports, inerrs,
             UDP(9), UDP(6), UDP(2));
  pfs_printf(b, "UdpLite: InDatagrams NoPorts InErrors OutDatagrams "
                "RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti "
                "MemErrors\nUdpLite: 0 0 0 0 0 0 0 0 0\n");
#undef IP
#undef TCP
#undef UDP
#undef ICMP
}

#define XNU_RTM_IFINFO2 0x12
#define XNU_RTA_IFP     0x10
#define XNU_IFF_UP      0x1
#define XNU_IFF_RUNNING 0x40

// The interface list parsed once per second, shared by /proc/net/dev and
// the /sys/class/net slice.
int pfs_xnu_ifstats(struct pfs_ifstat *out, int cap) {
  static struct pfs_ifstat cache[32];
  static int ncache;
  static int64_t ms;
  int64_t t = pfs_now_ms();
  if (!ms || t - ms >= 1000) {
    ncache = 0;
    char *raw;
    size_t len;
    if (pfs_xnu_iflist2(&raw, &len)) {
      const char *p = raw, *end = raw + len;
      while (p + 4 <= end && ncache < 32) {
        uint16_t mlen;
        memcpy(&mlen, p, 2);
        uint8_t type = (uint8_t)p[3];
        if (!mlen || mlen > (size_t)(end - p))
          break;
        if (type == XNU_RTM_IFINFO2 && mlen >= sizeof(struct xnu_if_msghdr2)) {
          const struct xnu_if_msghdr2 *m = (const void *)p;
          struct pfs_ifstat *o = &cache[ncache];
          memset(o, 0, sizeof *o);
          snprintf(o->name, sizeof o->name, "if%u", m->ifm_index);
          o->index = m->ifm_index;
          if (m->ifm_addrs & XNU_RTA_IFP) {
            const struct xnu_sockaddr_dl *dl = (const void *)(p + sizeof *m);
            size_t nl = dl->sdl_nlen;
            if (nl > sizeof o->name - 1)
              nl = sizeof o->name - 1;
            if ((const char *)dl->sdl_data + nl <= end) {
              memcpy(o->name, dl->sdl_data, nl);
              o->name[nl] = 0;
            }
            if (dl->sdl_alen && dl->sdl_alen <= 8 &&
                (const char *)dl->sdl_data + dl->sdl_nlen + dl->sdl_alen <=
                    end) {
              memcpy(o->mac, dl->sdl_data + dl->sdl_nlen, dl->sdl_alen);
              o->maclen = dl->sdl_alen;
            }
          }
          const struct xnu_if_data64 *d = &m->ifm_data;
          o->rx_bytes = d->ifi_ibytes;
          o->tx_bytes = d->ifi_obytes;
          o->rx_pkts = d->ifi_ipackets;
          o->tx_pkts = d->ifi_opackets;
          o->rx_errs = d->ifi_ierrors;
          o->tx_errs = d->ifi_oerrors;
          o->rx_drop = d->ifi_iqdrops;
          o->tx_drop = 0;
          o->mtu = d->ifi_mtu;
          o->up =
              (m->ifm_flags & XNU_IFF_UP) && (m->ifm_flags & XNU_IFF_RUNNING);
          o->speed_mbps = d->ifi_baudrate / 1000000;
          ncache++;
        }
        p += mlen;
      }
      free(raw);
    }
    ms = t;
  }
  int n = ncache < cap ? ncache : cap;
  memcpy(out, cache, (size_t)n * sizeof *out);
  return n;
}

static void net_dev(struct pfs_buf *b) {
  pfs_printf(b, "Inter-|   Receive                                       "
                "         |  Transmit\n"
                " face |bytes    packets errs drop fifo frame compressed "
                "multicast|bytes    packets errs drop fifo colls carrier "
                "compressed\n");
  struct pfs_ifstat ifs[32];
  int n = pfs_xnu_ifstats(ifs, 32);
  for (int i = 0; i < n; i++)
    pfs_printf(
        b,
        "%6s: %7llu %7llu %4llu %4llu %5u %5u %10u %9u "
        "%8llu %7llu %4llu %4llu %5u %7u %10u %10u\n",
        ifs[i].name, (unsigned long long)ifs[i].rx_bytes,
        (unsigned long long)ifs[i].rx_pkts, (unsigned long long)ifs[i].rx_errs,
        (unsigned long long)ifs[i].rx_drop, 0, 0, 0, 0,
        (unsigned long long)ifs[i].tx_bytes, (unsigned long long)ifs[i].tx_pkts,
        (unsigned long long)ifs[i].tx_errs, (unsigned long long)ifs[i].tx_drop,
        0, 0, 0, 0);
}

bool pfs_xnu_gen_net_file(struct pfs_buf *b, const char *name) {
  if (!strcmp(name, "tcp") || !strcmp(name, "tcp6") || !strcmp(name, "udp") ||
      !strcmp(name, "udp6"))
    return net_table(b, name), true;
  if (!strcmp(name, "unix"))
    return pfs_printf(b, "Num       RefCount Protocol Flags    Type St "
                         "Inode Path\n"),
           true;
  if (!strcmp(name, "dev"))
    return net_dev(b), true;
  if (!strcmp(name, "route"))
    return net_route(b), true;
  if (!strcmp(name, "arp"))
    return net_arp(b), true;
  if (!strcmp(name, "snmp"))
    return net_snmp(b), true;
  return false;
}

// ---------------------------------------------------------------------------
// /proc/self/fd, out of the kernel's own list. The entries carry the real
// descriptor numbers; a socket hashes to the same inode its table row does
// (pid 0 on both sides, the tables do not name owners here).

#define XNU_FDTYPE_VNODE  1
#define XNU_FDTYPE_SOCKET 2
#define XNU_FDTYPE_KQUEUE 5
#define XNU_FDTYPE_PIPE   6

static void xnu_socket_text(int fd, char *out, size_t n) {
  uint8_t laddr[16] = {0}, raddr[16] = {0};
  uint16_t lport = 0, rport = 0;
  uint8_t family = 4;
  uint8_t proto = 0;
  struct sockaddr_storage ss;
  uint32_t sl = sizeof ss;
  if (!getsockname(fd, (struct sockaddr *)&ss, &sl)) {
    if (ss.ss_family == AF_INET) {
      const struct sockaddr_in *a = (const void *)&ss;
      memcpy(laddr, &a->sin_addr, 4);
      lport = ntohs(a->sin_port);
    } else if (ss.ss_family == AF_INET6) {
      const struct sockaddr_in6 *a = (const void *)&ss;
      memcpy(laddr, &a->sin6_addr, 16);
      lport = ntohs(a->sin6_port);
      family = 6;
    }
  }
  sl = sizeof ss;
  if (!getpeername(fd, (struct sockaddr *)&ss, &sl)) {
    if (ss.ss_family == AF_INET) {
      const struct sockaddr_in *a = (const void *)&ss;
      memcpy(raddr, &a->sin_addr, 4);
      rport = ntohs(a->sin_port);
    } else if (ss.ss_family == AF_INET6) {
      const struct sockaddr_in6 *a = (const void *)&ss;
      memcpy(raddr, &a->sin6_addr, 16);
      rport = ntohs(a->sin6_port);
    }
  }
  int type = 0;
  sl = sizeof type;
  getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &sl);
  if (type == SOCK_DGRAM)
    proto = 1;
  uint64_t inode = pfs_net_inode(proto, family, 0, lport, rport, laddr, raddr);
  snprintf(out, n, "socket:[%llu]", (unsigned long long)inode);
}

// A socket in another process, through the kernel's per-descriptor answer;
// hashed with pid 0 like the table rows so the join with /proc/net holds.
static void other_socket_text(uint32_t pid, int fd, char *out, size_t n) {
  struct xnu_sock_id id;
  if (pfs_xnu_fdsock(pid, fd, &id)) {
    uint64_t inode = pfs_net_inode(id.proto, id.family, 0, id.lport, id.rport,
                                   id.laddr, id.raddr);
    snprintf(out, n, "socket:[%llu]", (unsigned long long)inode);
    return;
  }
  // not an inet socket, or not visible; a stable distinct number will do
  snprintf(out, n, "socket:[%llu]",
           (unsigned long long)((uint64_t)pid << 20 | (uint32_t)fd));
}

int pfs_xnu_fds_of(uint32_t pid, struct pfs_fdent **out) {
  *out = 0;
  struct xnu_proc_fdinfo *fds;
  int nfd = pfs_xnu_listfds(pid, &fds);
  if (nfd <= 0)
    return 0;
  struct pfs_fdent *ents = malloc(nfd * sizeof *ents);
  if (!ents) {
    free(fds);
    return 0;
  }
  bool self = pid == pfs_self_pid();
  int n = 0;
  for (int i = 0; i < nfd; i++) {
    struct pfs_fdent *e = &ents[n];
    long r;
    switch (fds[i].proc_fdtype) {
      case XNU_FDTYPE_VNODE:
        r = pfs_xnu_fdpath(pid, fds[i].proc_fd, e->text, sizeof e->text - 1);
        if (r > 0)
          e->text[r] = 0;
        else
          snprintf(e->text, sizeof e->text, "anon_inode:[vnode]");
        break;
      case XNU_FDTYPE_SOCKET:
        // our own descriptors answer getsockname directly; anyone
        // else's go through the kernel's fdinfo
        if (self)
          xnu_socket_text(fds[i].proc_fd, e->text, sizeof e->text);
        else
          other_socket_text(pid, fds[i].proc_fd, e->text, sizeof e->text);
        break;
      case XNU_FDTYPE_PIPE:
        snprintf(e->text, sizeof e->text, "pipe:[%d]",
                 1000000 + fds[i].proc_fd);
        break;
      case XNU_FDTYPE_KQUEUE:
        snprintf(e->text, sizeof e->text, "anon_inode:[kqueue]");
        break;
      default:
        snprintf(e->text, sizeof e->text, "anon_inode:[type%u]",
                 fds[i].proc_fdtype);
        break;
    }
    e->fd = fds[i].proc_fd;
    n++;
  }
  free(fds);
  *out = ents;
  return n;
}

#include "libc/nt/accounting.h"
#include "libc/nt/createfile.h"
#include "libc/nt/enum/creationdisposition.h"
#include "libc/nt/enum/filesharemode.h"
#include "libc/nt/enum/reggetvalueflags.h"
#include "libc/nt/files.h"
#include "libc/nt/ntdll.h"
#include "libc/nt/registry.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/filetime.h"
#include "libc/nt/struct/memorystatusex.h"
#include "libc/nt/struct/systeminfo.h"
#include "libc/nt/systeminfo.h"
#include "libc/procfs/internal.h"
#include "libc/procfs/xnu.internal.h"

// The top-level files: /proc/{meminfo,uptime,stat,loadavg,cpuinfo,version,
// filesystems,mounts,swaps}. Memory and cpu time have exact NT equivalents;
// the load average does not exist on NT at all, so it is an EMA of cpu
// utilization computed here, the shape a monitor expects fed by the
// closest fact the host has.

const char *const pfs_top_files[] = {
    "meminfo", "uptime",    "stat",  "loadavg", "cpuinfo",    "version",
    "filesystems", "mounts", "diskstats", "swaps", "cmdline", "partitions", 0};

static uint64_t ft(struct NtFileTime t) {
  return (uint64_t)t.dwHighDateTime << 32 | t.dwLowDateTime;
}

static int ncpus(void) {
  struct NtSystemInfo si;
  GetSystemInfo(&si);
  return si.dwNumberOfProcessors ? (int)si.dwNumberOfProcessors : 1;
}

// ---------------------------------------------------------------------------

static void gen_meminfo(struct pfs_buf *b) {
  struct NtMemoryStatusEx ms;
  memset(&ms, 0, sizeof ms);
  ms.dwLength = sizeof ms;
  GlobalMemoryStatusEx(&ms);
  // ullTotalPageFile is the commit limit (physical + pagefile), so the
  // pagefile alone, which is Linux's swap, is the excess over physical.
  uint64_t swap_total = ms.ullTotalPageFile > ms.ullTotalPhys
                            ? ms.ullTotalPageFile - ms.ullTotalPhys
                            : 0;
  uint64_t swap_free = ms.ullAvailPageFile > ms.ullAvailPhys
                           ? ms.ullAvailPageFile - ms.ullAvailPhys
                           : 0;
  if (swap_free > swap_total)
    swap_free = swap_total;
  pfs_printf(b, "MemTotal:       %8llu kB\n",
             (unsigned long long)(ms.ullTotalPhys / 1024));
  pfs_printf(b, "MemFree:        %8llu kB\n",
             (unsigned long long)(ms.ullAvailPhys / 1024));
  pfs_printf(b, "MemAvailable:   %8llu kB\n",
             (unsigned long long)(ms.ullAvailPhys / 1024));
  pfs_printf(b, "Buffers:               0 kB\nCached:                0 kB\n"
                "SwapCached:            0 kB\nActive:                0 kB\n"
                "Inactive:              0 kB\n");
  pfs_printf(b, "SwapTotal:      %8llu kB\n",
             (unsigned long long)(swap_total / 1024));
  pfs_printf(b, "SwapFree:       %8llu kB\n",
             (unsigned long long)(swap_free / 1024));
  pfs_printf(b, "Dirty:                 0 kB\nWriteback:             0 kB\n"
                "Mapped:                0 kB\nShmem:                 0 kB\n"
                "Slab:                  0 kB\n");
  pfs_printf(b, "CommitLimit:    %8llu kB\n",
             (unsigned long long)(ms.ullTotalPageFile / 1024));
  pfs_printf(
      b, "Committed_AS:   %8llu kB\n",
      (unsigned long long)((ms.ullTotalPageFile - ms.ullAvailPageFile) / 1024));
  pfs_printf(b, "VmallocTotal:          0 kB\nVmallocUsed:           0 kB\n"
                "VmallocChunk:          0 kB\n");
}

static void gen_uptime(struct pfs_buf *b) {
  uint64_t up100ns = pfs_now_filetime() - pfs_boot_filetime();
  struct NtFileTime i, k, u;
  uint64_t idle100ns = 0;
  if (GetSystemTimes(&i, &k, &u))
    idle100ns = ft(i);
  pfs_printf(b, "%llu.%02llu %llu.%02llu\n",
             (unsigned long long)(up100ns / 10000000),
             (unsigned long long)(up100ns / 100000 % 100),
             (unsigned long long)(idle100ns / 10000000),
             (unsigned long long)(idle100ns / 100000 % 100));
}

// SystemProcessorPerformanceInformation, one entry per cpu
struct cputimes {
  int64_t idle, kernel, user, dpc, intr;
  uint32_t nintr, pad;
};

static void gen_stat(struct pfs_buf *b) {
  struct NtFileTime i, k, u;
  uint64_t idle = 0, kern = 0, user = 0;
  if (GetSystemTimes(&i, &k, &u))
    idle = ft(i), kern = ft(k), user = ft(u);
  // NT's kernel time includes idle; Linux's system time does not
  uint64_t sys = kern > idle ? kern - idle : 0;
  pfs_printf(b, "cpu  %llu 0 %llu %llu 0 0 0 0 0 0\n",
             (unsigned long long)pfs_filetime_jiffies(user),
             (unsigned long long)pfs_filetime_jiffies(sys),
             (unsigned long long)pfs_filetime_jiffies(idle));
  int n = ncpus();
  struct cputimes per[64];
  if (n > 64)
    n = 64;
  if (!NtQuerySystemInformation(8, per, (uint32_t)(n * sizeof per[0]), 0)) {
    for (int c = 0; c < n; c++) {
      uint64_t ci = per[c].idle, ck = per[c].kernel, cu = per[c].user;
      uint64_t cs = ck > ci ? ck - ci : 0;
      pfs_printf(b, "cpu%d %llu 0 %llu %llu 0 0 0 0 0 0\n", c,
                 (unsigned long long)pfs_filetime_jiffies(cu),
                 (unsigned long long)pfs_filetime_jiffies(cs),
                 (unsigned long long)pfs_filetime_jiffies(ci));
    }
  }
  uint64_t btime = (pfs_boot_filetime() - 116444736000000000ull) / 10000000;
  pfs_printf(b,
             "intr 0\nctxt 0\nbtime %llu\nprocesses 1\n"
             "procs_running 1\nprocs_blocked 0\n",
             (unsigned long long)btime);
}

static void gen_loadavg(struct pfs_buf *b) {
  // NT has no run-queue average, so approximate what a load average
  // reports for a cpu-bound box: busy cpus, smoothed over 1/5/15 minutes.
  static uint64_t last_busy, last_total;
  static double avg1, avg5, avg15;
  struct NtFileTime i, k, u;
  if (GetSystemTimes(&i, &k, &u)) {
    uint64_t idle = ft(i), total = ft(k) + ft(u);
    uint64_t busy = total > idle ? total - idle : 0;
    if (last_total && total > last_total) {
      double dt = (double)(total - last_total) / ncpus() / 10000000.0;
      double inst =
          (double)(busy - last_busy) / (double)(total - last_total) * ncpus();
      if (inst < 0)
        inst = 0;
      // dt/(dt+tau) in place of 1-exp(-dt/tau); same limits, no libm
      avg1 += (inst - avg1) * (dt / (dt + 60.0));
      avg5 += (inst - avg5) * (dt / (dt + 300.0));
      avg15 += (inst - avg15) * (dt / (dt + 900.0));
    }
    last_busy = busy;
    last_total = total;
  }
  const struct pfs_proc *p;
  int nproc = pfs_procs(&p);
  pfs_printf(b, "%.2f %.2f %.2f 1/%d %d\n", avg1, avg5, avg15,
             nproc > 0 ? nproc : 1, (int)pfs_self_pid());
}

// ---------------------------------------------------------------------------

#ifdef __x86_64__
static void cpuid(uint32_t leaf, uint32_t sub, uint32_t o[4]) {
  asm volatile("cpuid"
               : "=a"(o[0]), "=b"(o[1]), "=c"(o[2]), "=d"(o[3])
               : "a"(leaf), "c"(sub));
}
#endif

#ifdef __x86_64__
// the flags line of /proc/cpuinfo, named as linux names them, from cpuid.
// the avx and avx-512 ones are left out when the os doesn't save their
// registers, which is what linux does too
struct pfs_x86_flag {
  uint32_t leaf;
  uint8_t sub, reg, bit, os;  // reg: 0 eax 1 ebx 2 ecx 3 edx
  const char name[19];
};
enum { OS_NONE, OS_AVX, OS_AVX512 };
static const struct pfs_x86_flag pfs_x86_flags[] = {
    {1, 0, 3, 0, 0, "fpu"},
    {1, 0, 3, 1, 0, "vme"},
    {1, 0, 3, 2, 0, "de"},
    {1, 0, 3, 3, 0, "pse"},
    {1, 0, 3, 4, 0, "tsc"},
    {1, 0, 3, 5, 0, "msr"},
    {1, 0, 3, 6, 0, "pae"},
    {1, 0, 3, 7, 0, "mce"},
    {1, 0, 3, 8, 0, "cx8"},
    {1, 0, 3, 9, 0, "apic"},
    {1, 0, 3, 11, 0, "sep"},
    {1, 0, 3, 12, 0, "mtrr"},
    {1, 0, 3, 13, 0, "pge"},
    {1, 0, 3, 14, 0, "mca"},
    {1, 0, 3, 15, 0, "cmov"},
    {1, 0, 3, 16, 0, "pat"},
    {1, 0, 3, 17, 0, "pse36"},
    {1, 0, 3, 19, 0, "clflush"},
    {1, 0, 3, 23, 0, "mmx"},
    {1, 0, 3, 24, 0, "fxsr"},
    {1, 0, 3, 25, 0, "sse"},
    {1, 0, 3, 26, 0, "sse2"},
    {1, 0, 3, 27, 0, "ss"},
    {1, 0, 3, 28, 0, "ht"},
    {1, 0, 3, 29, 0, "tm"},
    {1, 0, 3, 31, 0, "pbe"},
    {0x80000001, 0, 3, 11, 0, "syscall"},
    {0x80000001, 0, 3, 20, 0, "nx"},
    {0x80000001, 0, 3, 22, 0, "mmxext"},
    {0x80000001, 0, 3, 25, 0, "fxsr_opt"},
    {0x80000001, 0, 3, 26, 0, "pdpe1gb"},
    {0x80000001, 0, 3, 27, 0, "rdtscp"},
    {0x80000001, 0, 3, 29, 0, "lm"},
    {1, 0, 2, 0, 0, "pni"},
    {1, 0, 2, 1, 0, "pclmulqdq"},
    {1, 0, 2, 2, 0, "dtes64"},
    {1, 0, 2, 3, 0, "monitor"},
    {1, 0, 2, 4, 0, "ds_cpl"},
    {1, 0, 2, 5, 0, "vmx"},
    {1, 0, 2, 6, 0, "smx"},
    {1, 0, 2, 7, 0, "est"},
    {1, 0, 2, 8, 0, "tm2"},
    {1, 0, 2, 9, 0, "ssse3"},
    {1, 0, 2, 11, 0, "sdbg"},
    {1, 0, 2, 12, OS_AVX, "fma"},
    {1, 0, 2, 13, 0, "cx16"},
    {1, 0, 2, 14, 0, "xtpr"},
    {1, 0, 2, 15, 0, "pdcm"},
    {1, 0, 2, 17, 0, "pcid"},
    {1, 0, 2, 18, 0, "dca"},
    {1, 0, 2, 19, 0, "sse4_1"},
    {1, 0, 2, 20, 0, "sse4_2"},
    {1, 0, 2, 21, 0, "x2apic"},
    {1, 0, 2, 22, 0, "movbe"},
    {1, 0, 2, 23, 0, "popcnt"},
    {1, 0, 2, 24, 0, "tsc_deadline_timer"},
    {1, 0, 2, 25, 0, "aes"},
    {1, 0, 2, 26, 0, "xsave"},
    {1, 0, 2, 28, OS_AVX, "avx"},
    {1, 0, 2, 29, OS_AVX, "f16c"},
    {1, 0, 2, 30, 0, "rdrand"},
    {1, 0, 2, 31, 0, "hypervisor"},
    {0x80000001, 0, 2, 0, 0, "lahf_lm"},
    {0x80000001, 0, 2, 1, 0, "cmp_legacy"},
    {0x80000001, 0, 2, 2, 0, "svm"},
    {0x80000001, 0, 2, 3, 0, "extapic"},
    {0x80000001, 0, 2, 4, 0, "cr8_legacy"},
    {0x80000001, 0, 2, 5, 0, "abm"},
    {0x80000001, 0, 2, 6, 0, "sse4a"},
    {0x80000001, 0, 2, 7, 0, "misalignsse"},
    {0x80000001, 0, 2, 8, 0, "3dnowprefetch"},
    {0x80000001, 0, 2, 11, OS_AVX, "xop"},
    {0x80000001, 0, 2, 16, OS_AVX, "fma4"},
    {0x80000001, 0, 2, 21, 0, "tbm"},
    {0x80000001, 0, 2, 22, 0, "topoext"},
    {7, 0, 1, 0, 0, "fsgsbase"},
    {7, 0, 1, 1, 0, "tsc_adjust"},
    {7, 0, 1, 2, 0, "sgx"},
    {7, 0, 1, 3, 0, "bmi1"},
    {7, 0, 1, 4, 0, "hle"},
    {7, 0, 1, 5, OS_AVX, "avx2"},
    {7, 0, 1, 7, 0, "smep"},
    {7, 0, 1, 8, 0, "bmi2"},
    {7, 0, 1, 9, 0, "erms"},
    {7, 0, 1, 10, 0, "invpcid"},
    {7, 0, 1, 11, 0, "rtm"},
    {7, 0, 1, 16, OS_AVX512, "avx512f"},
    {7, 0, 1, 17, OS_AVX512, "avx512dq"},
    {7, 0, 1, 18, 0, "rdseed"},
    {7, 0, 1, 19, 0, "adx"},
    {7, 0, 1, 20, 0, "smap"},
    {7, 0, 1, 21, OS_AVX512, "avx512ifma"},
    {7, 0, 1, 23, 0, "clflushopt"},
    {7, 0, 1, 24, 0, "clwb"},
    {7, 0, 1, 26, OS_AVX512, "avx512pf"},
    {7, 0, 1, 27, OS_AVX512, "avx512er"},
    {7, 0, 1, 28, OS_AVX512, "avx512cd"},
    {7, 0, 1, 29, 0, "sha_ni"},
    {7, 0, 1, 30, OS_AVX512, "avx512bw"},
    {7, 0, 1, 31, OS_AVX512, "avx512vl"},
    {7, 0, 2, 1, OS_AVX512, "avx512vbmi"},
    {7, 0, 2, 2, 0, "umip"},
    {7, 0, 2, 3, 0, "pku"},
    {7, 0, 2, 5, 0, "waitpkg"},
    {7, 0, 2, 6, OS_AVX512, "avx512_vbmi2"},
    {7, 0, 2, 8, 0, "gfni"},
    {7, 0, 2, 9, OS_AVX, "vaes"},
    {7, 0, 2, 10, OS_AVX, "vpclmulqdq"},
    {7, 0, 2, 11, OS_AVX512, "avx512_vnni"},
    {7, 0, 2, 12, OS_AVX512, "avx512_bitalg"},
    {7, 0, 2, 14, OS_AVX512, "avx512_vpopcntdq"},
    {7, 0, 2, 16, 0, "la57"},
    {7, 0, 2, 22, 0, "rdpid"},
    {7, 0, 2, 25, 0, "cldemote"},
    {7, 0, 2, 27, 0, "movdiri"},
    {7, 0, 2, 28, 0, "movdir64b"},
    {7, 0, 3, 2, OS_AVX512, "avx512_4vnniw"},
    {7, 0, 3, 3, OS_AVX512, "avx512_4fmaps"},
    {7, 0, 3, 4, 0, "fsrm"},
    {7, 0, 3, 8, OS_AVX512, "avx512_vp2intersect"},
    {7, 0, 3, 10, 0, "md_clear"},
    {7, 0, 3, 14, 0, "serialize"},
    {7, 0, 3, 16, 0, "tsxldtrk"},
    {7, 0, 3, 20, 0, "ibt"},
    {7, 0, 3, 22, 0, "amx_bf16"},
    {7, 0, 3, 23, OS_AVX512, "avx512_fp16"},
    {7, 0, 3, 24, 0, "amx_tile"},
    {7, 0, 3, 25, 0, "amx_int8"},
    {7, 0, 3, 28, 0, "flush_l1d"},
    {7, 0, 3, 29, 0, "arch_capabilities"},
    {7, 1, 0, 4, OS_AVX, "avx_vnni"},
    {7, 1, 0, 5, OS_AVX512, "avx512_bf16"},
    {0xd, 1, 0, 0, 0, "xsaveopt"},
    {0xd, 1, 0, 1, 0, "xsavec"},
    {0xd, 1, 0, 2, 0, "xgetbv1"},
    {0xd, 1, 0, 3, 0, "xsaves"},
};

static void pfs_x86_flags_line(struct pfs_buf *b) {
  uint32_t r[4], max, maxext, xcr0 = 0;
  cpuid(0, 0, r);
  max = r[0];
  cpuid(0x80000000u, 0, r);
  maxext = r[0];
  cpuid(1, 0, r);
  if (r[2] >> 27 & 1) {  // osxsave
    uint32_t lo, hi;
    asm volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    xcr0 = lo;
  }
  bool avx = (xcr0 & 6) == 6;
  bool avx512 = avx && (xcr0 & 0xe0) == 0xe0;
  pfs_printf(b, "flags\t\t:");
  for (size_t i = 0; i < ARRAYLEN(pfs_x86_flags); i++) {
    const struct pfs_x86_flag *f = pfs_x86_flags + i;
    if (f->leaf >= 0x80000000u ? f->leaf > maxext : f->leaf > max)
      continue;
    if ((f->os == OS_AVX && !avx) || (f->os == OS_AVX512 && !avx512))
      continue;
    cpuid(f->leaf, f->sub, r);
    if (r[f->reg] >> f->bit & 1)
      pfs_printf(b, " %s", f->name);
  }
  pfs_printf(b, "\n");
}
#endif

static void gen_cpuinfo(struct pfs_buf *b) {
  int n = ncpus();
  uint32_t mhz_cur[64] = {0}, mhz_max[64] = {0};
  pfs_cpu_mhz(mhz_cur, mhz_max, 64);
  // Real core/package identity when the host answers; the fallback (every
  // cpu its own core) is only wrong about hyperthreads. Physical core
  // counters (sysinfo) count distinct (physical id, core id) pairs here.
  uint8_t core[64] = {0}, pkg[64] = {0};
  int topo = pfs_cpu_topology(core, pkg, 64);
  (void)topo;
#ifdef __x86_64__
  uint32_t r[4];
  char vendor[13] = "unknown";
  cpuid(0, 0, r);
  memcpy(vendor, &r[1], 4);
  memcpy(vendor + 4, &r[3], 4);
  memcpy(vendor + 8, &r[2], 4);
  vendor[12] = 0;
  cpuid(1, 0, r);
  uint32_t fam = (r[0] >> 8 & 15) + (r[0] >> 20 & 255);
  uint32_t model = (r[0] >> 4 & 15) | (r[0] >> 12 & 0xf0);
  uint32_t step = r[0] & 15;
  char brand[49] = "unknown";
  cpuid(0x80000000u, 0, r);
  if (r[0] >= 0x80000004u) {
    for (int i = 0; i < 3; i++) {
      cpuid(0x80000002u + i, 0, r);
      memcpy(brand + i * 16, r, 16);
    }
    brand[48] = 0;
  }
  char *bp = brand;
  while (*bp == ' ')
    bp++;
  for (int c = 0; c < n; c++) {
    pfs_printf(b, "processor\t: %d\n", c);
    pfs_printf(b, "vendor_id\t: %s\n", vendor);
    pfs_printf(b, "cpu family\t: %u\nmodel\t\t: %u\n", fam, model);
    pfs_printf(b, "model name\t: %s\n", bp);
    pfs_printf(b, "stepping\t: %u\n", step);
    pfs_printf(b, "cpu MHz\t\t: %u.000\ncache size\t: 0 KB\n",
               c < 64 ? mhz_cur[c] : 0);
    int phys = topo && c < topo ? pkg[c] : 0;
    int cid = topo && c < topo ? core[c] : c;
    int sib = 0, cores = 0;
    if (topo) {
      uint64_t seen = 0;
      for (int k = 0; k < topo; k++) {
        if (pkg[k] != phys)
          continue;
        sib++;
        if (!(seen >> core[k] & 1))
          cores++;
        seen |= 1ull << core[k];
      }
    } else {
      sib = cores = n;
    }
    pfs_printf(b, "physical id\t: %d\nsiblings\t: %d\n", phys, sib);
    pfs_printf(b, "core id\t\t: %d\ncpu cores\t: %d\n", cid, cores);
    pfs_printf(b, "fpu\t\t: yes\nfpu_exception\t: yes\n");
    pfs_x86_flags_line(b);
    pfs_printf(b, "bogomips\t: 0.00\naddress sizes\t: 48 bits physical, "
                  "48 bits virtual\n\n");
  }
#else
  for (int c = 0; c < n; c++)
    pfs_printf(b, "processor\t: %d\nBogoMIPS\t: 0.00\n\n", c);
#endif
}

// /proc/diskstats out of IOCTL_DISK_PERFORMANCE (works with a 0-access
// open; a probe confirmed the 88-byte struct and that no diskperf filter
// arming is needed on this vintage of NT). Drives are named in the sd*
// convention monitors expect. Fields with no NT equivalent (merges, the
// weighted-time refinement) read as their nearest neighbor or 0; sectors
// are the 512-byte units Linux reports regardless of hardware.
static void gen_diskstats(struct pfs_buf *b) {
  int misses = 0;
  for (int d = 0; d < 16 && misses < 2; d++) {
    char16_t path[24] = u"\\\\.\\PhysicalDrive0";
    path[17] = (char16_t)('0' + d);
    int64_t h = CreateFile(path, 0, kNtFileShareRead | kNtFileShareWrite, 0,
                           kNtOpenExisting, 0, 0);
    if (h == -1) {
      misses++;
      continue;
    }
    struct {
      int64_t BytesRead, BytesWritten, ReadTime, WriteTime, IdleTime;
      uint32_t ReadCount, WriteCount, QueueDepth, SplitCount;
      int64_t QueryTime;
      uint32_t StorageDeviceNumber;
      char16_t StorageManagerName[8];
    } p;
    uint32_t got = 0;
    if (DeviceIoControl(h, 0x70020 /* IOCTL_DISK_PERFORMANCE */, 0, 0, &p,
                        sizeof p, &got, 0) &&
        got >= 72) {
      unsigned long long rd_ms = (unsigned long long)(p.ReadTime / 10000);
      unsigned long long wr_ms = (unsigned long long)(p.WriteTime / 10000);
      pfs_printf(b,
                 "   8 %7d sd%c %u 0 %llu %llu %u 0 %llu %llu %u %llu "
                 "%llu\n",
                 d * 16, 'a' + d, p.ReadCount,
                 (unsigned long long)(p.BytesRead / 512), rd_ms, p.WriteCount,
                 (unsigned long long)(p.BytesWritten / 512), wr_ms,
                 p.QueueDepth, rd_ms + wr_ms, rd_ms + wr_ms);
    }
    CloseHandle(h);
  }
}

// /proc/partitions: every physical drive, then its partitions, in the
// sd* naming diskstats uses and the 8:N numbering mountinfo uses for
// drives. The disk size comes from IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
// (DiskSize is the i64 at offset 24 of its answer) and the partitions
// from IOCTL_DISK_GET_DRIVE_LAYOUT_EX, whose entries start at offset 48
// and are 144 bytes each with the length at 16 and the number at 24;
// both work with a 0-access open. The 144-byte stride was checked by
// dumping the raw answer on a real machine.
static void gen_partitions(struct pfs_buf *b) {
  pfs_printf(b, "major minor  #blocks  name\n\n");
  int misses = 0;
  for (int d = 0; d < 16 && misses < 2; d++) {
    char16_t path[24] = u"\\\\.\\PhysicalDrive0";
    path[17] = (char16_t)('0' + d);
    int64_t h = CreateFile(path, 0, kNtFileShareRead | kNtFileShareWrite, 0,
                           kNtOpenExisting, 0, 0);
    if (h == -1) {
      misses++;
      continue;
    }
    uint32_t got = 0;
    _Alignas(8) uint8_t geo[1024];
    if (DeviceIoControl(h, 0x700A0 /* IOCTL_DISK_GET_DRIVE_GEOMETRY_EX */, 0,
                        0, geo, sizeof geo, &got, 0) &&
        got >= 32) {
      int64_t size;
      memcpy(&size, geo + 24, 8);
      pfs_printf(b, "%4d  %7d %10llu sd%c\n", 8, d * 16,
                 (unsigned long long)(size / 1024), 'a' + d);
    }
    uint32_t cap = 48 + 144 * 32;
    for (int tries = 0; tries < 4; tries++) {
      uint8_t *lay = malloc(cap);
      if (!lay)
        break;
      got = 0;
      if (DeviceIoControl(h, 0x70050 /* IOCTL_DISK_GET_DRIVE_LAYOUT_EX */, 0,
                          0, lay, cap, &got, 0) &&
          got >= 48) {
        uint32_t style, count;
        memcpy(&style, lay, 4);
        memcpy(&count, lay + 4, 4);
        for (uint32_t i = 0; i < count && 48 + (i + 1) * 144 <= got; i++) {
          const uint8_t *e = lay + 48 + i * 144;
          uint32_t estyle, num;
          int64_t len;
          memcpy(&estyle, e, 4);
          memcpy(&len, e + 16, 8);
          memcpy(&num, e + 24, 4);
          if (estyle != style)
            break;  // the stride is wrong on this vintage: say nothing
          if (len <= 0 || !num)
            continue;  // an unused MBR slot
          pfs_printf(b, "%4d  %7d %10llu sd%c%u\n", 8, d * 16 + (int)num,
                     (unsigned long long)(len / 1024), 'a' + d, num);
        }
        free(lay);
        break;
      }
      uint32_t err = GetLastError();
      free(lay);
      if (err != 122 && err != 234)  // insufficient buffer, more data
        break;
      cap *= 4;
    }
    CloseHandle(h);
  }
}

static void gen_mounts(struct pfs_buf *b) {
  pfs_printf(b, "rootfs / rootfs rw 0 0\n");
  pfs_printf(b, "proc /proc proc rw 0 0\n");
  pfs_printf(b, "sysfs /sys sysfs rw 0 0\n");
  uint32_t drives = GetLogicalDrives();
  for (int i = 0; i < 26; i++) {
    if (!(drives & 1u << i))
      continue;
    // uppercase, the case NT itself answers paths in, so a mount
    // point here prefixes what /proc/self/exe and friends return
    pfs_printf(b, "%c: /%c ntfs rw 0 0\n", 'A' + i, 'A' + i);
  }
}

// The NT kernel's boot options, HKLM\SYSTEM\CurrentControlSet\Control
// \SystemStartOptions (" NOEXECUTE=OPTIN  NOVGA" and the like, from the
// BCD); empty when it cannot be read. Nothing is made up here.
static void gen_cmdline(struct pfs_buf *b) {
  char16_t w[1024];
  uint32_t cb = sizeof w;
  if (RegGetValue(kNtHkeyLocalMachine, u"SYSTEM\\CurrentControlSet\\Control",
                  u"SystemStartOptions", kNtRrfRtRegSz, 0, w, &cb))
    return;
  size_t n = cb / 2;
  while (n && (!w[n - 1] || w[n - 1] == ' '))
    n--;
  size_t i = 0;
  while (i < n && w[i] == ' ')
    i++;
  for (; i < n; i++) {
    char c = w[i] < 128 ? (char)w[i] : '?';
    pfs_put(b, &c, 1);
  }
  pfs_put(b, "\n", 1);
}

bool pfs_gen_top_file(struct pfs_buf *b, const char *name) {
  if (IsXnuSilicon())
    return pfs_xnu_gen_top_file(b, name);
  if (!strcmp(name, "meminfo"))
    return gen_meminfo(b), true;
  if (!strcmp(name, "uptime"))
    return gen_uptime(b), true;
  if (!strcmp(name, "stat"))
    return gen_stat(b), true;
  if (!strcmp(name, "loadavg"))
    return gen_loadavg(b), true;
  if (!strcmp(name, "cpuinfo"))
    return gen_cpuinfo(b), true;
  if (!strcmp(name, "mounts"))
    return gen_mounts(b), true;
  if (!strcmp(name, "diskstats"))
    return gen_diskstats(b), true;
  if (!strcmp(name, "partitions"))
    return gen_partitions(b), true;
  if (!strcmp(name, "cmdline"))
    return gen_cmdline(b), true;
  if (!strcmp(name, "version"))  // the shape of Linux's, the facts uname's
    return pfs_printf(b, "%s version %s (%s)\n", pfs_kernel_sysname(),
                      pfs_kernel_release(), pfs_kernel_version()),
           true;
  if (!strcmp(name, "filesystems"))
    return pfs_printf(b, "nodev\tsysfs\nnodev\tproc\nnodev\ttmpfs\n"
                         "\text4\n\tntfs\n\tvfat\n"),
           true;
  if (!strcmp(name, "swaps"))
    return pfs_printf(b, "Filename\t\t\t\tType\t\tSize\t\tUsed\t\t"
                         "Priority\n"),
           true;
  return false;
}

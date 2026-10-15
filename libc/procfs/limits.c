#include "libc/calls/calls.h"
#include "libc/calls/struct/rlimit.h"
#include "libc/procfs/internal.h"

// /proc/<pid>/limits: our own from getrlimit(), whose resource numbers
// are the file's row order; another process gets no limits at all

static const struct {
  const char *name, *unit;
} kRows[] = {
    {"Max cpu time", "seconds"},     {"Max file size", "bytes"},
    {"Max data size", "bytes"},      {"Max stack size", "bytes"},
    {"Max core file size", "bytes"}, {"Max resident set", "bytes"},
    {"Max processes", "processes"},  {"Max open files", "files"},
    {"Max locked memory", "bytes"},  {"Max address space", "bytes"},
    {"Max file locks", "locks"},     {"Max pending signals", "signals"},
    {"Max msgqueue size", "bytes"},  {"Max nice priority", ""},
    {"Max realtime priority", ""},   {"Max realtime timeout", "us"},
};

static void put_limit(struct pfs_buf *b, uint64_t v) {
  if (v == RLIM_INFINITY) {
    pfs_printf(b, " %20s", "unlimited");
  } else {
    pfs_printf(b, " %20llu", (unsigned long long)v);
  }
}

void pfs_gen_limits(struct pfs_buf *b, uint32_t pid) {
  bool self = pid == pfs_self_pid();
  pfs_printf(b, "%-25s %20s %20s %-10s\n", "Limit", "Soft Limit", "Hard Limit",
             "Units");
  for (size_t i = 0; i < sizeof kRows / sizeof kRows[0]; i++) {
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    if (self && getrlimit(i, &rl) == -1) {
      rl.rlim_cur = RLIM_INFINITY;
      rl.rlim_max = RLIM_INFINITY;
    }
    pfs_printf(b, "%-25s", kRows[i].name);
    put_limit(b, rl.rlim_cur);
    put_limit(b, rl.rlim_max);
    pfs_printf(b, " %-10s\n", kRows[i].unit);
  }
}

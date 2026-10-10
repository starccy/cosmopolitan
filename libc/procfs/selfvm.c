#include "ape/sections.internal.h"
#include "libc/calls/internal.h"
#include "libc/intrin/maps.h"
#include "libc/procfs/internal.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/pib.h"
#include "libc/calls/calls.h"
#include "libc/calls/struct/sigset.h"

// The parts of /proc/self/status the C runtime itself knows: the main
// thread's stack, the program's text, and the signal state, which the
// host either keeps per thread or in a form of its own.

uint64_t pfs_self_stack(void) {
  return __get_main_stack().size;
}

uint64_t pfs_self_text(void) {
  if (!_etext || !__executable_start)
    return 0;
  return (uint64_t)(_etext - __executable_start);
}

// the calling thread's blocked set, and the dispositions the process
// installed: a bit per signal, bit 0 being signal 1
void pfs_self_sigs(uint64_t *blk, uint64_t *ign, uint64_t *cgt) {
  struct CosmoPib *pib = __get_pib();
  sigset_t blocked = 0;
  sigprocmask(SIG_BLOCK, 0, &blocked);  // the kernel's on unix, ours on nt
  *blk = blocked;
  *ign = 0;
  *cgt = 0;
  for (int sig = 1; sig < 64 && sig <= NSIG; ++sig) {
    unsigned rva = pib->sighandrvas[sig - 1];
    if (rva == (unsigned)(uintptr_t)SIG_IGN)
      *ign |= 1ull << (sig - 1);
    else if (rva >= kSigactionMinRva)
      *cgt |= 1ull << (sig - 1);
  }
}

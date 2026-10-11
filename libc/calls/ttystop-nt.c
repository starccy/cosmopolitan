#include "libc/calls/internal.h"
#include "libc/calls/sig.internal.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/pgrp.h"
#include "libc/sysv/consts/sig.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"
#ifdef __x86_64__

// a console read (SIGTTIN) or write or setting (SIGTTOU) from a group
// other than the foreground one: the group is stopped and the caller
// goes on once continued and in the foreground. a read that can't stop
// fails with EIO, a write or setting goes ahead. -1 w/ EINTR when a
// handler without SA_RESTART ran
textwindows int __ttystop_nt(int sig, sigset_t waitmask) {
  for (;;) {
    if (!__pgrp_background())
      return 0;
    if (__sig_ignored(sig) || (waitmask & (1ull << (sig - 1))))
      return sig == SIGTTIN ? eio() : 0;
    __pgrp_post(__pgrp_self(), sig);
    atomic_fetch_or_explicit(__get_pib()->sigpending, 1ull << (sig - 1),
                             memory_order_release);
    if (__sigcheck(waitmask, true) == -1)
      return -1;
  }
}

#endif /* __x86_64__ */

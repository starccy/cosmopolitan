// SIGRTMIN and SIGRTMAX the way glibc and musl publish them: a pair of
// functions, with the first three real-time numbers held back for the
// threading library. Signal numbers are Linux's throughout, so the range
// is Linux's too; whether a host can deliver a real-time signal is a
// separate matter.
#include "libc/sysv/consts/sig.h"

int __libc_current_sigrtmin(void) {
  return 35;
}

int __libc_current_sigrtmax(void) {
  return 64;
}

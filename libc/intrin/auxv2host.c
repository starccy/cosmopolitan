#include "libc/dce.h"
#include "libc/sysv/consts/auxv.h"
#include "libc/sysv/consts/host.internal.h"

#define KEYS(X)          \
  X(AT_EXECFD)           \
  X(AT_NOTELF)           \
  X(AT_UID)              \
  X(AT_EUID)             \
  X(AT_GID)              \
  X(AT_EGID)             \
  X(AT_PLATFORM)         \
  X(AT_HWCAP)            \
  X(AT_CLKTCK)           \
  X(AT_DCACHEBSIZE)      \
  X(AT_ICACHEBSIZE)      \
  X(AT_UCACHEBSIZE)      \
  X(AT_SECURE)           \
  X(AT_BASE_PLATFORM)    \
  X(AT_RANDOM)           \
  X(AT_HWCAP2)           \
  X(AT_EXECFN)           \
  X(AT_SYSINFO_EHDR)     \
  X(AT_MINSIGSTKSZ)      \
  X(AT_OSRELDATE)        \
  X(AT_CANARY)           \
  X(AT_CANARYLEN)        \
  X(AT_NCPUS)            \
  X(AT_PAGESIZES)        \
  X(AT_PAGESIZESLEN)     \
  X(AT_TIMEKEEP)         \
  X(AT_STACKPROT)        \
  X(AT_EHDRFLAGS)        \
  X(AT_STACKBASE)

#define DECL(NAME) extern const unsigned long __host_##NAME __asm__(#NAME);
KEYS(DECL)
#undef DECL

/**
 * Turns a getauxval() key into the number the host's vector uses.
 *
 * The keys below AT_NOTELF are the same everywhere. Returns 0 for a key
 * the host has no entry for, which no lookup can match.
 */
unsigned long __auxv2host(unsigned long key) {
  if (IsLinux())
    return key;
#define X(NAME) \
  if (key == NAME) \
    return __host_##NAME;
  KEYS(X)
#undef X
  return key;
}

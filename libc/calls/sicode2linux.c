#include "libc/dce.h"
#include "libc/limits.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/sicode.h"
#include "libc/sysv/consts/sig.h"

#define GENERIC(X) \
  X(SI_USER)       \
  X(SI_KERNEL)     \
  X(SI_QUEUE)      \
  X(SI_TIMER)      \
  X(SI_MESGQ)      \
  X(SI_ASYNCIO)    \
  X(SI_TKILL)      \
  X(SI_ASYNCNL)    \
  X(SI_NOINFO)

#define ILL(X)     \
  X(ILL_ILLOPN)    \
  X(ILL_ILLADR)    \
  X(ILL_ILLTRP)    \
  X(ILL_PRVOPC)

#define FPE(X)     \
  X(FPE_INTDIV)    \
  X(FPE_INTOVF)    \
  X(FPE_FLTDIV)    \
  X(FPE_FLTOVF)    \
  X(FPE_FLTUND)    \
  X(FPE_FLTRES)    \
  X(FPE_FLTINV)    \
  X(FPE_FLTSUB)

#define DECL(NAME) extern const int32_t __host_##NAME __asm__(#NAME);
GENERIC(DECL)
ILL(DECL)
FPE(DECL)
DECL(SEGV_PKUERR)
DECL(BUS_OOMERR)
#undef DECL

// consts.sh marks a code the host doesn't have with this
#define NONE INT32_MIN

/**
 * Turns the si_code a bsd kernel reported into linux's number.
 *
 * The codes any signal may carry come first, since no kernel numbers
 * them inside the range of a signal's own codes. A code with no linux
 * counterpart passes through.
 */
__privileged int __sicode2linux(int sig, int code) {
  if (IsLinux() || IsWindows())
    return code;
#define X(NAME)                                   \
  if (__host_##NAME != NONE && code == __host_##NAME) \
    return NAME;
  GENERIC(X)
  switch (sig) {
    case SIGILL:
      ILL(X)
      break;
    case SIGFPE:
      FPE(X)
      break;
    case SIGSEGV:
      if (__host_SEGV_PKUERR != -1 && code == __host_SEGV_PKUERR)
        return SEGV_PKUERR;
      break;
    case SIGBUS:
      // freebsd and openbsd report an unbacked page as an object error
      if ((IsFreebsd() || IsOpenbsd()) && code == BUS_OBJERR)
        return BUS_ADRERR;
      if (__host_BUS_OOMERR != -1 && code == __host_BUS_OOMERR)
        return BUS_OOMERR;
      break;
    default:
      break;
  }
#undef X
  return code;
}

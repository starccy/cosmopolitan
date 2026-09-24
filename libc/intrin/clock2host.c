#include "libc/dce.h"
#include "libc/sysv/consts/clock.h"
#include "libc/sysv/consts/host.internal.h"

__HOSTCONST(int, CLOCK_MONOTONIC);
__HOSTCONST(int, CLOCK_PROCESS_CPUTIME_ID);
__HOSTCONST(int, CLOCK_THREAD_CPUTIME_ID);
__HOSTCONST(int, CLOCK_MONOTONIC_RAW);
__HOSTCONST(int, CLOCK_REALTIME_COARSE);
__HOSTCONST(int, CLOCK_MONOTONIC_COARSE);
__HOSTCONST(int, CLOCK_BOOTTIME);

/**
 * Turns a clock id into the number the host kernel knows it by.
 *
 * Linux ids pass through, which keeps the dynamic ones working there.
 * Windows and x86 XNU never get here since their clocks are polyfilled
 * by code that reads the Linux numbers.
 *
 * @return host clock id, or 127 if the host has no such clock
 */
int __clock2host(int clock) {
  if (IsLinux() || IsWindows())
    return clock;
  switch (clock) {
    case CLOCK_REALTIME:
      return 0;
    case CLOCK_MONOTONIC:
      return __host_CLOCK_MONOTONIC;
    case CLOCK_PROCESS_CPUTIME_ID:
      return __host_CLOCK_PROCESS_CPUTIME_ID;
    case CLOCK_THREAD_CPUTIME_ID:
      return __host_CLOCK_THREAD_CPUTIME_ID;
    case CLOCK_MONOTONIC_RAW:
      return __host_CLOCK_MONOTONIC_RAW;
    case CLOCK_REALTIME_COARSE:
      return __host_CLOCK_REALTIME_COARSE;
    case CLOCK_MONOTONIC_COARSE:
      return __host_CLOCK_MONOTONIC_COARSE;
    case CLOCK_BOOTTIME:
      return __host_CLOCK_BOOTTIME;
    default:
      return 127;
  }
}

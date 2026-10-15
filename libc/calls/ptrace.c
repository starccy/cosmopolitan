#include "libc/calls/ptrace.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/dce.h"
#include "libc/intrin/strace.h"
#include "libc/sysv/errfuns.h"

/**
 * Traces a process, with Linux request numbers.
 *
 * The three `PTRACE_PEEK*` requests return the word they read, so
 * callers clear errno beforehand to tell -1 data from an error.
 *
 * @return request-specific value on success, or -1 w/ errno
 * @raise ENOSYS if not Linux
 */
long ptrace(int request, ...) {
  va_list va;
  long rc, word;
  va_start(va, request);
  int pid = va_arg(va, int);
  void *addr = va_arg(va, void *);
  void *data = va_arg(va, void *);
  va_end(va);
  if (!IsLinux()) {
    rc = enosys();
  } else if (request >= PTRACE_PEEKTEXT && request <= PTRACE_PEEKUSER) {
    rc = __sys_ptrace(request, pid, (long)addr, &word);
    if (rc != -1)
      rc = word;
  } else {
    rc = __sys_ptrace(request, pid, (long)addr, data);
  }
  STRACE("ptrace(%d, %d, %p, %p) → %ld% m", request, pid, addr, data, rc);
  return rc;
}

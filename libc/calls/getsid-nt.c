#include "libc/calls/calls.h"
#include "libc/calls/syscall-nt.internal.h"
#include "libc/intrin/pgrp.h"
#include "libc/intrin/weaken.h"
#include "libc/nt/enum/processaccess.h"
#include "libc/nt/process.h"
#include "libc/nt/runtime.h"
#include "libc/sysv/errfuns.h"
#include "libc/sysv/pib.h"

// sessions exist in the pgrp entries alone (libc/intrin/pgrp-nt.c): a
// process cosmo knows nothing about counts as a session of its own
textwindows int sys_getsid_nt(int pid) {
  if (pid < 0)
    return esrch();
  if (!pid || pid == getpid())
    return __get_pib()->sid ? __get_pib()->sid : getpid();
  int s;
  if (_weaken(__sid_of) && (s = _weaken(__sid_of)(pid)) > 0)
    return s;
  int64_t h = OpenProcess(kNtProcessQueryLimitedInformation, false, pid);
  if (!h)
    return esrch();
  CloseHandle(h);
  return pid;
}

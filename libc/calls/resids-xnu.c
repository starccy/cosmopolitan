#include "libc/calls/calls.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-sysv.internal.h"
#include "libc/errno.h"

#define XNU_PROC_INFO_CALL_PIDINFO 2
#define XNU_PROC_PIDTBSDINFO       3

// the first 44 bytes of <sys/proc_info.h>'s struct proc_bsdinfo
struct XnuBsdInfo {
  uint32_t pbi_flags;
  uint32_t pbi_status;
  uint32_t pbi_xstatus;
  uint32_t pbi_pid;
  uint32_t pbi_ppid;
  uint32_t pbi_uid;
  uint32_t pbi_gid;
  uint32_t pbi_ruid;
  uint32_t pbi_rgid;
  uint32_t pbi_svuid;
  uint32_t pbi_svgid;
  uint32_t rfu_1;
  char rest[136 - 48];
};

/**
 * Reads the real, effective and saved user and group ids on xnu, which
 * has no getresuid() or getresgid() system call.
 *
 * @param ids receives ruid, euid, svuid, rgid, egid, svgid
 * @return 0 on success, or -1 w/ errno
 */
int __resids_xnu(uint32_t ids[6]) {
  struct XnuBsdInfo bi;
  int rc = sys_proc_info(XNU_PROC_INFO_CALL_PIDINFO, getpid(),
                         XNU_PROC_PIDTBSDINFO, 0, &bi, sizeof(bi));
  if (rc == -1)
    return -1;
  if (rc != sizeof(bi)) {
    errno = EIO;
    return -1;
  }
  ids[0] = bi.pbi_ruid;
  ids[1] = bi.pbi_uid;
  ids[2] = bi.pbi_svuid;
  ids[3] = bi.pbi_rgid;
  ids[4] = bi.pbi_gid;
  ids[5] = bi.pbi_svgid;
  return 0;
}

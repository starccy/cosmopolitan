#ifndef COSMOPOLITAN_LIBC_SYSV_CONSTS_WAITID_H_
#define COSMOPOLITAN_LIBC_SYSV_CONSTS_WAITID_H_

#define WSTOPPED 2
#define WEXITED  4
#define WNOWAIT  0x01000000

#define P_ALL   0
#define P_PID   1
#define P_PGID  2
#define P_PIDFD 3

#ifndef __ASSEMBLER__
/* posix says waitid() takes one of the P_* above as this type */
typedef enum {
  __P_ALL = P_ALL,
  __P_PID = P_PID,
  __P_PGID = P_PGID,
  __P_PIDFD = P_PIDFD
} idtype_t;
#endif

#endif /* COSMOPOLITAN_LIBC_SYSV_CONSTS_WAITID_H_ */

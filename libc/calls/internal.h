#ifndef COSMOPOLITAN_LIBC_CALLS_INTERNAL_H_
#define COSMOPOLITAN_LIBC_CALLS_INTERNAL_H_
#include "libc/atomic.h"
#include "libc/calls/struct/sigset.h"
#include "libc/calls/struct/sigval.h"
#include "libc/calls/struct/timespec.h"
#include "libc/dce.h"
#include "libc/intrin/fds.h"
#include "libc/macros.h"
#include "libc/sysv/pib.h"

#define kSigactionMinRva 8 /* >SIG_{ERR,DFL,IGN,...} */

COSMOPOLITAN_C_START_

#define kIoMotion ((const int8_t[3]){1, 0, 0})

extern const struct Fd kEmptyFd;

int __reservefd(int);
int __reservefd_unlocked(int);
void __releasefd(int);
uint32_t sys_getuid_nt(void);
int __ensurefds_unlocked(int);
void __printfds(struct Fd *, size_t);
int __sigcheck(sigset_t, bool);
struct Fd;
#define __EFD_TIMERFD 0x10000  // evflags: the eventfd is a timerfd
#define __EFD_INOTIFY 0x20000  // evflags: the eventfd is an inotify
uint64_t __eventfd_take(struct Fd *);
int __eventfd_post(int, uint64_t);
int __eventfd_drain(int);
void __timerfd_close(struct Fd *);
int __eventfd_emu(unsigned, int);
int __eventfd_wait_nt(int64_t, sigset_t);
ssize_t __inotify_read(int, struct Fd *, void *, size_t);
void __inotify_ref(struct Fd *);
void __inotify_close(struct Fd *);
bool __eventfd_add(struct Fd *, uint64_t, bool *);
ssize_t __eventfd_read(int, void *, size_t);
ssize_t __eventfd_write(int, const void *, size_t);
int sys_eventfd_nt(unsigned, int);
ssize_t sys_read_eventfd_nt(struct Fd *, void *);
ssize_t sys_write_eventfd_nt(struct Fd *, uint64_t);
void __epoll_rearm_in(int);
void __epoll_rearm_out(int);
void __epoll_forget(int);
void __epoll_ref(struct Fd *);
int __epoll_close(struct Fd *);
int CountConsoleInputBytes(void);
int FlushConsoleInputBytes(void);
int64_t GetConsoleInputHandle(void);
int64_t GetConsoleOutputHandle(void);
void EchoConsoleNt(const char *, size_t, bool);
int IsWindowsExecutable(int64_t, const char16_t *);
int IsWindowsExecutableName(const char16_t *);
void InterceptTerminalCommands(const char *, size_t);
void sys_console_sync_nt(void);
void sys_read_nt_wipe_keystrokes(void);
int __generate_pid(atomic_ulong **);

forceinline bool __isfdopen(int fd) {
  if (fd < __get_pib()->fds.n) {
    char kind = __get_pib()->fds.p[fd].kind;
    return kind != kFdEmpty && kind != kFdReserved;
  } else {
    return false;
  }
}

forceinline bool __isfdkind(int fd, int kind) {
  return fd < __get_pib()->fds.n && __get_pib()->fds.p[fd].kind == kind;
}

int _check_signal(bool);
int _check_cancel(void);
bool _is_canceled(void);
int sys_close_nt(int, int);
int _park_norestart(struct timespec, uint64_t);
int _park_restartable(struct timespec, uint64_t);
int sys_openat_metal(int, const char *, int, unsigned);

#ifdef __x86_64__
bool __iswsl1(void);
#else
#define __iswsl1() false
#endif

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_INTERNAL_H_ */

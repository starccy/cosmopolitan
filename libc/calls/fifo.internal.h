#ifndef COSMOPOLITAN_LIBC_CALLS_FIFO_INTERNAL_H_
#define COSMOPOLITAN_LIBC_CALLS_FIFO_INTERNAL_H_
#include "libc/calls/struct/sigset.h"
#include "libc/calls/struct/stat.h"
#include "libc/intrin/fds.h"
COSMOPOLITAN_C_START_

int __mkfifo_nt(int, const char *, unsigned);
bool __fifo_path_nt(const char16_t *);
int64_t __fifo_open_nt(const char16_t *, uint32_t, sigset_t, struct Fd *);
void __fifo_close_nt(struct Fd *);
void __fifo_dup_nt(struct Fd *);
void __fifo_fork_child_nt(void);
ssize_t __fifo_read_nt(int, void *, size_t, sigset_t);
int64_t __fifo_write_handle_nt(struct Fd *);
bool __fifo_write_swap_nt(struct Fd *);
void __fifo_stat_nt(struct Fd *, struct stat *);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_FIFO_INTERNAL_H_ */

#ifndef COSMOPOLITAN_LIBC_PROCFS_PROCFS_INTERNAL_H_
#define COSMOPOLITAN_LIBC_PROCFS_PROCFS_INTERNAL_H_
COSMOPOLITAN_C_START_

// The /proc and /sys emulation on hosts that have neither (Windows and
// Apple Silicon macOS). Every entry here is weak in its caller and answers
// -2 for a path or descriptor that is not the emulation's business, so a
// program that never yoinks `procfs` pays nothing. A descriptor of the
// tree is kind kFdProc with a struct ProcfsHandle behind it.

struct ProcfsHandle;
struct dirent;
struct iovec;
struct stat;

int __procfs_open(int, const char *, int, unsigned);
int __procfs_stat(int, const char *, struct stat *, int);
int __procfs_access(int, const char *, int);
ssize_t __procfs_readlink(int, const char *, char *, size_t);
ssize_t __procfs_read(struct ProcfsHandle *, const struct iovec *, size_t,
                      ssize_t);
int64_t __procfs_seek(struct ProcfsHandle *, int64_t, unsigned);
int __procfs_fstat(struct ProcfsHandle *, struct stat *);
int __procfs_readdir(struct ProcfsHandle *, long, struct dirent *);
int __procfs_close(int);
struct ProcfsHandle *__procfs_keep(struct ProcfsHandle *);
void __procfs_drop(struct ProcfsHandle *);
void __procfs_postdup(int, int);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_PROCFS_PROCFS_INTERNAL_H_ */

#ifndef COSMOPOLITAN_LIBC_CALLS_XATTR_H_
#define COSMOPOLITAN_LIBC_CALLS_XATTR_H_
COSMOPOLITAN_C_START_

#define XATTR_CREATE  1
#define XATTR_REPLACE 2

ssize_t getxattr(const char *, const char *, void *, size_t) libcesque;
ssize_t lgetxattr(const char *, const char *, void *, size_t) libcesque;
ssize_t fgetxattr(int, const char *, void *, size_t) libcesque;
int setxattr(const char *, const char *, const void *, size_t, int) libcesque;
int lsetxattr(const char *, const char *, const void *, size_t, int) libcesque;
int fsetxattr(int, const char *, const void *, size_t, int) libcesque;
ssize_t listxattr(const char *, char *, size_t) libcesque;
ssize_t llistxattr(const char *, char *, size_t) libcesque;
ssize_t flistxattr(int, char *, size_t) libcesque;
int removexattr(const char *, const char *) libcesque;
int lremovexattr(const char *, const char *) libcesque;
int fremovexattr(int, const char *) libcesque;

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_XATTR_H_ */

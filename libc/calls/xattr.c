#include "libc/calls/calls.h"
#include "libc/calls/xattr.h"
#include "libc/dce.h"
#include "libc/errno.h"
#include "libc/intrin/strace.h"
#include "libc/intrin/weaken.h"
#include "libc/mem/mem.h"
#include "libc/str/str.h"
#include "libc/sysv/errfuns.h"

// Extended attributes, with Linux's interface and name space on every
// host that has them. Linux and NetBSD have this exact interface. XNU
// spells the calls with a position and an options argument, and has no
// l* forms, which XATTR_NOFOLLOW stands in for. FreeBSD keeps the name
// space (user, system) as an argument, and lists names with a length
// byte in front of each. Windows and OpenBSD have nothing comparable
// and answer ENOTSUP, which is also what a file system without them
// says on Linux.

// the extra arguments are xnu's position and options, which linux and
// netbsd ignore; except that the set calls take flags where xnu has its
// position, so those get spelled out per host
ssize_t sys_getxattr(const char *, const char *, void *, size_t, uint32_t,
                     int);
ssize_t sys_fgetxattr(int, const char *, void *, size_t, uint32_t, int);
ssize_t sys_lgetxattr(const char *, const char *, void *, size_t);
int sys_setxattr(const char *, const char *, const void *, size_t, long, int);
int sys_fsetxattr(int, const char *, const void *, size_t, long, int);
int sys_lsetxattr(const char *, const char *, const void *, size_t, int);
ssize_t sys_listxattr(const char *, char *, size_t, int);
ssize_t sys_flistxattr(int, char *, size_t, int);
ssize_t sys_llistxattr(const char *, char *, size_t);
int sys_removexattr(const char *, const char *, int);
int sys_fremovexattr(int, const char *, int);
int sys_lremovexattr(const char *, const char *);

ssize_t sys_extattr_get_file(const char *, int, const char *, void *, size_t);
ssize_t sys_extattr_get_link(const char *, int, const char *, void *, size_t);
ssize_t sys_extattr_get_fd(int, int, const char *, void *, size_t);
ssize_t sys_extattr_set_file(const char *, int, const char *, const void *,
                             size_t);
ssize_t sys_extattr_set_link(const char *, int, const char *, const void *,
                             size_t);
ssize_t sys_extattr_set_fd(int, int, const char *, const void *, size_t);
ssize_t sys_extattr_list_file(const char *, int, void *, size_t);
ssize_t sys_extattr_list_link(const char *, int, void *, size_t);
ssize_t sys_extattr_list_fd(int, int, void *, size_t);
int sys_extattr_delete_file(const char *, int, const char *);
int sys_extattr_delete_link(const char *, int, const char *);
int sys_extattr_delete_fd(int, int, const char *);

#define XATTR_NOFOLLOW_xnu 1
#define XATTR_CREATE_xnu   2
#define XATTR_REPLACE_xnu  4

#define EXTATTR_NAMESPACE_USER_freebsd   1
#define EXTATTR_NAMESPACE_SYSTEM_freebsd 2

#define FOLLOW   0
#define NOFOLLOW 1
#define BY_FD    2

// the x* functions below take a path or a descriptor, and how to reach
// the file, so each operation is written once
union Target {
  const char *path;
  int fd;
};

static int XnuFlags(int flags, int how) {
  int f = how == NOFOLLOW ? XATTR_NOFOLLOW_xnu : 0;
  if (flags & XATTR_CREATE)
    f |= XATTR_CREATE_xnu;
  if (flags & XATTR_REPLACE)
    f |= XATTR_REPLACE_xnu;
  return f;
}

// splits "user.foo" into freebsd's name space and "foo"
static int FreebsdNamespace(const char **name) {
  const char *n = *name;
  if (!strncmp(n, "user.", 5)) {
    *name = n + 5;
    return EXTATTR_NAMESPACE_USER_freebsd;
  }
  if (!strncmp(n, "system.", 7)) {
    *name = n + 7;
    return EXTATTR_NAMESPACE_SYSTEM_freebsd;
  }
  return -1;
}

static ssize_t FreebsdGet(union Target t, int how, int ns, const char *name,
                          void *value, size_t size) {
  switch (how) {
    case FOLLOW:
      return sys_extattr_get_file(t.path, ns, name, value, size);
    case NOFOLLOW:
      return sys_extattr_get_link(t.path, ns, name, value, size);
    default:
      return sys_extattr_get_fd(t.fd, ns, name, value, size);
  }
}

static ssize_t FreebsdList(union Target t, int how, int ns, void *buf,
                           size_t size) {
  switch (how) {
    case FOLLOW:
      return sys_extattr_list_file(t.path, ns, buf, size);
    case NOFOLLOW:
      return sys_extattr_list_link(t.path, ns, buf, size);
    default:
      return sys_extattr_list_fd(t.fd, ns, buf, size);
  }
}

static ssize_t XGet(union Target t, int how, const char *name, void *value,
                    size_t size) {
  if (IsLinux() || IsNetbsd()) {
    switch (how) {
      case FOLLOW:
        return sys_getxattr(t.path, name, value, size, 0, 0);
      case NOFOLLOW:
        return sys_lgetxattr(t.path, name, value, size);
      default:
        return sys_fgetxattr(t.fd, name, value, size, 0, 0);
    }
  } else if (IsXnu()) {
    if (how == BY_FD)
      return sys_fgetxattr(t.fd, name, value, size, 0, 0);
    return sys_getxattr(t.path, name, value, size, 0, XnuFlags(0, how));
  } else if (IsFreebsd()) {
    int ns = FreebsdNamespace(&name);
    if (ns == -1)
      return enotsup();
    // freebsd truncates silently, and reports the size for a null buffer
    ssize_t need = FreebsdGet(t, how, ns, name, 0, 0);
    if (need == -1)
      return -1;
    if (!size)
      return need;
    if (need > size)
      return erange();
    return FreebsdGet(t, how, ns, name, value, size);
  } else {
    return enotsup();
  }
}

static int XSet(union Target t, int how, const char *name, const void *value,
                size_t size, int flags) {
  if (flags & ~(XATTR_CREATE | XATTR_REPLACE))
    return einval();
  if (IsLinux() || IsNetbsd()) {
    switch (how) {
      case FOLLOW:
        return sys_setxattr(t.path, name, value, size, flags, 0);
      case NOFOLLOW:
        return sys_lsetxattr(t.path, name, value, size, flags);
      default:
        return sys_fsetxattr(t.fd, name, value, size, flags, 0);
    }
  } else if (IsXnu()) {
    if (how == BY_FD)
      return sys_fsetxattr(t.fd, name, value, size, 0, XnuFlags(flags, how));
    return sys_setxattr(t.path, name, value, size, 0, XnuFlags(flags, how));
  } else if (IsFreebsd()) {
    int ns = FreebsdNamespace(&name);
    if (ns == -1)
      return enotsup();
    if (flags) {
      // the create and replace conditions are checked here, since
      // freebsd's call doesn't take them
      ssize_t have = FreebsdGet(t, how, ns, name, 0, 0);
      if ((flags & XATTR_CREATE) && have != -1)
        return eexist();
      if ((flags & XATTR_REPLACE) && have == -1)
        return enodata();
    }
    ssize_t rc;
    switch (how) {
      case FOLLOW:
        rc = sys_extattr_set_file(t.path, ns, name, value, size);
        break;
      case NOFOLLOW:
        rc = sys_extattr_set_link(t.path, ns, name, value, size);
        break;
      default:
        rc = sys_extattr_set_fd(t.fd, ns, name, value, size);
        break;
    }
    return rc == -1 ? -1 : 0;
  } else {
    return enotsup();
  }
}

// rewrites freebsd's length-prefixed names as "user.name\0..."
static ssize_t FreebsdListNames(union Target t, int how, int ns,
                                const char *prefix, char *list, size_t size,
                                size_t *used) {
  ssize_t n = FreebsdList(t, how, ns, 0, 0);
  if (n <= 0)
    return n;
  char *buf;
  if (!_weaken(malloc) || !(buf = _weaken(malloc)(n)))
    return enomem();
  if ((n = FreebsdList(t, how, ns, buf, n)) == -1) {
    _weaken(free)(buf);
    return -1;
  }
  size_t plen = strlen(prefix);
  for (ssize_t i = 0; i < n;) {
    size_t len = buf[i] & 255;
    if (i + 1 + len > n)
      break;
    size_t need = plen + len + 1;
    if (size) {
      if (*used + need > size) {
        _weaken(free)(buf);
        return erange();
      }
      memcpy(list + *used, prefix, plen);
      memcpy(list + *used + plen, buf + i + 1, len);
      list[*used + plen + len] = 0;
    }
    *used += need;
    i += 1 + len;
  }
  _weaken(free)(buf);
  return 0;
}

static ssize_t XList(union Target t, int how, char *list, size_t size) {
  if (IsLinux() || IsNetbsd()) {
    switch (how) {
      case FOLLOW:
        return sys_listxattr(t.path, list, size, 0);
      case NOFOLLOW:
        return sys_llistxattr(t.path, list, size);
      default:
        return sys_flistxattr(t.fd, list, size, 0);
    }
  } else if (IsXnu()) {
    if (how == BY_FD)
      return sys_flistxattr(t.fd, list, size, 0);
    return sys_listxattr(t.path, list, size, XnuFlags(0, how));
  } else if (IsFreebsd()) {
    size_t used = 0;
    if (FreebsdListNames(t, how, EXTATTR_NAMESPACE_USER_freebsd, "user.", list,
                         size, &used) == -1)
      return -1;
    // the system name space needs privilege, so its refusal isn't ours
    int e = errno;
    if (FreebsdListNames(t, how, EXTATTR_NAMESPACE_SYSTEM_freebsd, "system.",
                         list, size, &used) == -1 &&
        errno == ERANGE)
      return -1;
    errno = e;
    return used;
  } else {
    return enotsup();
  }
}

static int XRemove(union Target t, int how, const char *name) {
  if (IsLinux() || IsNetbsd()) {
    switch (how) {
      case FOLLOW:
        return sys_removexattr(t.path, name, 0);
      case NOFOLLOW:
        return sys_lremovexattr(t.path, name);
      default:
        return sys_fremovexattr(t.fd, name, 0);
    }
  } else if (IsXnu()) {
    if (how == BY_FD)
      return sys_fremovexattr(t.fd, name, 0);
    return sys_removexattr(t.path, name, XnuFlags(0, how));
  } else if (IsFreebsd()) {
    int ns = FreebsdNamespace(&name);
    if (ns == -1)
      return enotsup();
    switch (how) {
      case FOLLOW:
        return sys_extattr_delete_file(t.path, ns, name);
      case NOFOLLOW:
        return sys_extattr_delete_link(t.path, ns, name);
      default:
        return sys_extattr_delete_fd(t.fd, ns, name);
    }
  } else {
    return enotsup();
  }
}

/**
 * Reads extended attribute.
 *
 * @param value receives the attribute, or with size 0 nothing, and the
 *     size is returned
 * @return size of the attribute, or -1 w/ errno
 * @raise ENODATA if the file has no such attribute
 * @raise ERANGE if size is too small for it
 * @raise ENOTSUP if the file system or host has none
 */
ssize_t getxattr(const char *path, const char *name, void *value,
                 size_t size) {
  ssize_t rc = XGet((union Target){.path = path}, FOLLOW, name, value, size);
  STRACE("getxattr(%#s, %#s, %p, %'zu) → %'ld% m", path, name, value, size,
         rc);
  return rc;
}

/**
 * Reads extended attribute of symbolic link itself.
 */
ssize_t lgetxattr(const char *path, const char *name, void *value,
                  size_t size) {
  ssize_t rc = XGet((union Target){.path = path}, NOFOLLOW, name, value, size);
  STRACE("lgetxattr(%#s, %#s, %p, %'zu) → %'ld% m", path, name, value, size,
         rc);
  return rc;
}

/**
 * Reads extended attribute of open file.
 */
ssize_t fgetxattr(int fd, const char *name, void *value, size_t size) {
  ssize_t rc = XGet((union Target){.fd = fd}, BY_FD, name, value, size);
  STRACE("fgetxattr(%d, %#s, %p, %'zu) → %'ld% m", fd, name, value, size, rc);
  return rc;
}

/**
 * Writes extended attribute.
 *
 * @param flags can have XATTR_CREATE or XATTR_REPLACE
 * @return 0 on success, or -1 w/ errno
 * @raise EEXIST if XATTR_CREATE was given and the attribute exists
 * @raise ENODATA if XATTR_REPLACE was given and it doesn't
 * @raise ENOTSUP if the file system or host has none
 */
int setxattr(const char *path, const char *name, const void *value,
             size_t size, int flags) {
  int rc = XSet((union Target){.path = path}, FOLLOW, name, value, size, flags);
  STRACE("setxattr(%#s, %#s, %p, %'zu, %#x) → %d% m", path, name, value, size,
         flags, rc);
  return rc;
}

/**
 * Writes extended attribute of symbolic link itself.
 */
int lsetxattr(const char *path, const char *name, const void *value,
              size_t size, int flags) {
  int rc =
      XSet((union Target){.path = path}, NOFOLLOW, name, value, size, flags);
  STRACE("lsetxattr(%#s, %#s, %p, %'zu, %#x) → %d% m", path, name, value,
         size, flags, rc);
  return rc;
}

/**
 * Writes extended attribute of open file.
 */
int fsetxattr(int fd, const char *name, const void *value, size_t size,
              int flags) {
  int rc = XSet((union Target){.fd = fd}, BY_FD, name, value, size, flags);
  STRACE("fsetxattr(%d, %#s, %p, %'zu, %#x) → %d% m", fd, name, value, size,
         flags, rc);
  return rc;
}

/**
 * Lists extended attribute names.
 *
 * @param list receives the names, each followed by a nul, or with size
 *     0 nothing, and the size needed is returned
 * @return bytes of names, or -1 w/ errno
 * @raise ERANGE if size is too small for them
 * @raise ENOTSUP if the file system or host has none
 */
ssize_t listxattr(const char *path, char *list, size_t size) {
  ssize_t rc = XList((union Target){.path = path}, FOLLOW, list, size);
  STRACE("listxattr(%#s, %p, %'zu) → %'ld% m", path, list, size, rc);
  return rc;
}

/**
 * Lists extended attribute names of symbolic link itself.
 */
ssize_t llistxattr(const char *path, char *list, size_t size) {
  ssize_t rc = XList((union Target){.path = path}, NOFOLLOW, list, size);
  STRACE("llistxattr(%#s, %p, %'zu) → %'ld% m", path, list, size, rc);
  return rc;
}

/**
 * Lists extended attribute names of open file.
 */
ssize_t flistxattr(int fd, char *list, size_t size) {
  ssize_t rc = XList((union Target){.fd = fd}, BY_FD, list, size);
  STRACE("flistxattr(%d, %p, %'zu) → %'ld% m", fd, list, size, rc);
  return rc;
}

/**
 * Removes extended attribute.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise ENODATA if the file has no such attribute
 * @raise ENOTSUP if the file system or host has none
 */
int removexattr(const char *path, const char *name) {
  int rc = XRemove((union Target){.path = path}, FOLLOW, name);
  STRACE("removexattr(%#s, %#s) → %d% m", path, name, rc);
  return rc;
}

/**
 * Removes extended attribute of symbolic link itself.
 */
int lremovexattr(const char *path, const char *name) {
  int rc = XRemove((union Target){.path = path}, NOFOLLOW, name);
  STRACE("lremovexattr(%#s, %#s) → %d% m", path, name, rc);
  return rc;
}

/**
 * Removes extended attribute of open file.
 */
int fremovexattr(int fd, const char *name) {
  int rc = XRemove((union Target){.fd = fd}, BY_FD, name);
  STRACE("fremovexattr(%d, %#s) → %d% m", fd, name, rc);
  return rc;
}

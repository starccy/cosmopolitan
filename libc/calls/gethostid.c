#include "libc/calls/calls.h"
#include "libc/serialize.h"
#include "libc/sysv/consts/o.h"

/**
 * Returns the machine's identifier.
 *
 * It's whatever /etc/hostid holds, little endian, or zero without that
 * file. The 32-bit value comes back sign extended, as glibc has it.
 */
long gethostid(void) {
  int fd;
  uint32_t id = 0;
  unsigned char b[4];
  if ((fd = open("/etc/hostid", O_RDONLY | O_CLOEXEC)) != -1) {
    if (read(fd, b, sizeof(b)) == sizeof(b))
      id = READ32LE(b);
    close(fd);
  }
  return (int32_t)id;
}

#include "libc/calls/calls.h"
#include "libc/errno.h"
#include "libc/runtime/runtime.h"
#include "libc/sysv/consts/madv.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/prot.h"
#include "libc/testlib/testlib.h"

TEST(madvise, free) {
  char *p;
  ASSERT_NE(MAP_FAILED, (p = mmap(0, getpagesize(), PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)));
  p[0] = 1;
  ASSERT_SYS(0, 0, madvise(p, getpagesize(), MADV_FREE));
  // a freed page reads back as its old contents or as zeros
  ASSERT_TRUE(p[0] == 1 || p[0] == 0);
  p[0] = 2;
  ASSERT_EQ(2, p[0]);
  ASSERT_SYS(0, 0, munmap(p, getpagesize()));
}

TEST(madvise, unknownAdviceIsInvalid) {
  char *p;
  ASSERT_NE(MAP_FAILED, (p = mmap(0, getpagesize(), PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)));
  ASSERT_SYS(EINVAL, -1, madvise(p, getpagesize(), 1000));
  ASSERT_SYS(0, 0, munmap(p, getpagesize()));
}

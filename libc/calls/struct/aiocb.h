#ifndef COSMOPOLITAN_LIBC_CALLS_STRUCT_AIOCB_H_
#define COSMOPOLITAN_LIBC_CALLS_STRUCT_AIOCB_H_
#include "libc/calls/struct/sigevent.h"
#include "libc/calls/struct/timespec.h"
#include "libc/sysv/consts/lio.h"
COSMOPOLITAN_C_START_

#define AIO_CANCELED    0
#define AIO_NOTCANCELED 1
#define AIO_ALLDONE     2

struct aiocb {
  int aio_fildes;
  int aio_lio_opcode;
  int aio_reqprio;
  volatile void *aio_buf;
  size_t aio_nbytes;
  struct sigevent aio_sigevent;
  void *__td;
  int __lock[2];
  volatile int __err;
  ssize_t __ret;
  int64_t aio_offset;
  void *__next, *__prev;
  char __dummy4[32 - 2 * sizeof(void *)];
};

int aio_read(struct aiocb *);
int aio_write(struct aiocb *);
int aio_fsync(int, struct aiocb *);
int aio_error(const struct aiocb *);
ssize_t aio_return(struct aiocb *);
int aio_cancel(int, struct aiocb *);
int aio_suspend(const struct aiocb *const[], int, const struct timespec *);
int lio_listio(int, struct aiocb *const[], int, struct sigevent *);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_STRUCT_AIOCB_H_ */

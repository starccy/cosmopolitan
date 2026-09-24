#ifndef COSMOPOLITAN_LIBC_CALLS_STRUCT_INOTIFY_EVENT_H_
#define COSMOPOLITAN_LIBC_CALLS_STRUCT_INOTIFY_EVENT_H_
COSMOPOLITAN_C_START_

struct inotify_event {
  int32_t wd;
  uint32_t mask;
  uint32_t cookie;
  uint32_t len;  // of name, padding included
  char name[];
};

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_STRUCT_INOTIFY_EVENT_H_ */

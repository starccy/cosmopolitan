#ifndef COSMOPOLITAN_LIBC_CALLS_STRUCT_FD_INTERNAL_H_
#define COSMOPOLITAN_LIBC_CALLS_STRUCT_FD_INTERNAL_H_
#include "libc/atomic.h"
#include "libc/sock/struct/sockaddr.h"
#include "libc/thread/thread.h"
COSMOPOLITAN_C_START_

#define kFdEmpty     0
#define kFdFile      1
#define kFdSocket    2
#define kFdConsole   4
#define kFdSerial    5  // metal
#define kFdZip       6  // unix + windows
#define kFdEpoll     7  // epoll: windows
#define kFdReserved  8
#define kFdDevNull   9
#define kFdDevRandom 10
#define kFdEvent     11  // eventfd: unix + windows
#define kFdProc      12  // /proc emulation: unix + windows

struct CursorShared {
  pthread_mutex_t lock;
  long pointer;
};

struct Cursor {
  struct CursorShared *shared;
  atomic_int refs;
  bool is_multiprocess;
  struct Cursor *next_free_cursor;
};

struct Fd {
  atomic_char kind;
  bool isbound;
  char connecting;
  bool used_explicit_drive_letter;
  bool was_created_during_vfork;
  unsigned flags;
  unsigned mode;
  long handle;
  int family;
  int type;
  int protocol;
  unsigned rcvtimeo;  // millis; 0 means wait forever
  unsigned sndtimeo;  // millis; 0 means wait forever
  void *connect_op;
  struct Cursor *cursor;
  int64_t dev;  // lazily set by flocks on windows
  int64_t ino;  // lazily set by flocks on windows
  long pkthandle6;  // packet sockets on windows: the ipv6 capture, or 0
  int pktifindex;
  char pktturn;
  uint64_t evcount;  // eventfd counter
  int evflags;       // EFD_SEMAPHORE
  int evpeer;        // eventfd off windows: the hidden socket end
  void *tftimer;     // timerfd off linux: its posix timer
  void *inotify;     // inotify off linux: the watches and the queue
  void *epset;       // epoll on windows: the interest list
  void *scm;         // unix stream on windows: received fds not yet taken
  void *pty;         // pseudoconsole on windows, see pty.internal.h
  bool ptymaster;
};

struct Fds {
  atomic_int f;  // lowest free slot
  unsigned n;    // in fds
  size_t c;      // in bytes
  struct Fd *p;
  struct Cursor *freed_cursors;
};

struct Cursor *__cursor_new(void);
bool __cursor_ref(struct Cursor *);
void __cursor_unref(struct Cursor *);
void __cursor_lock(struct Cursor *);
void __cursor_unlock(struct Cursor *);
void __cursor_destroy(struct Cursor *);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_STRUCT_FD_INTERNAL_H_ */

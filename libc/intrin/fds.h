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

// struct Fd::type of a kFdFile that is a fifo on windows, which execve()
// carries along with the fd
#define kFifoMark 0x46494630

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
  void *udg;         // unix datagram on windows, see unixdgram-nt.c
  void *pty;         // pseudoconsole on windows, see pty.internal.h
  bool ptymaster;
  bool devzero;  // windows: a kFdDevRandom that is /dev/zero
  bool devfull;  // windows: a kFdDevRandom that is /dev/full
  char devdir;   // windows: a handleless kFdDevRandom standing for a
                 // directory: 1 /dev, 2 /dev/pts, 3 /dev/fd
  bool peergone;  // windows SOCK_DGRAM pair: ECONNREFUSED already reported
  bool xnupkt;      // xnu: a socketpair(SOCK_SEQPACKET) end, see unixpair-xnu.c
  bool xnugone;     // xnu: an AF_UNIX datagram peer gone, not yet told to send
  bool xnudgram;    // xnu: an AF_UNIX datagram socket made by socket()
  bool listening;   // xnu, windows: listen() was called
  bool xnuseq;      // xnu: a socket(SOCK_SEQPACKET) framed on a stream
  char pmtudisc;    // xnu: IP_MTU_DISCOVER as set, plus one
  int64_t xnuino;   // xnu: the inode either of those belongs to
  bool passcred;    // off linux: SO_PASSCRED as set, see passcred.c
  int credpid;      // windows unix socket: the pid of the process it's from
  int credfrom;     // windows unix socket: who sent what's being received
  uint32_t credleft;  // windows unix stream: bytes left of that message
  void *fifo;       // windows fifo: its registry, see fifo-nt.c
  long fifow;       // windows fifo opened O_RDWR: the write end
  bool noquickack;  // off linux: TCP_QUICKACK cleared, see tcphint.c
  bool cork;        // windows socket: TCP_CORK as set
  int deferaccept;  // off linux: TCP_DEFER_ACCEPT as set
  unsigned usertimeout;  // off linux: TCP_USER_TIMEOUT as set, millis
  bool reuseport;   // windows socket: SO_REUSEPORT as set
  char sockbuf;     // off linux: 1 SO_SNDBUF set, 2 SO_RCVBUF set, 3 both
  uint8_t tclass;   // windows socket: IPV6_TCLASS as set
  char shut;        // windows socket: 1 after SHUT_RD, 2 SHUT_WR, 3 both
  bool msgtrunc;    // windows unix seqpacket: the last receive was cut
  char syncio;  // windows disk file: 0 not known yet, 1 synchronous, 2 not
  char disk;    // windows kFdFile: 0 not known yet, 1 a disk file, 2 not
  char exec;    // windows disk file: 0 name doesn't say, 1 not exec, 2 exec
  long fionbio;     // windows socket: the handle FIONBIO was last set on
  size_t zipdir;  // immutable bundle directory index (zero for ordinary fds)
  int fionbio_pid;  // and in which process, since fork() doesn't keep it
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

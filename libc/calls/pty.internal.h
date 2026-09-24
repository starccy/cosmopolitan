#ifndef COSMOPOLITAN_LIBC_CALLS_PTY_INTERNAL_H_
#define COSMOPOLITAN_LIBC_CALLS_PTY_INTERNAL_H_
#include "libc/calls/struct/termios.h"
#include "libc/calls/struct/winsize.h"
#include "libc/intrin/fds.h"
#include "libc/nt/struct/startupinfo.h"
COSMOPOLITAN_C_START_

// A pseudo terminal on Windows: a ConPTY between two pipes. The master
// descriptor reads the console's output pipe and writes its input pipe.
// The slave descriptor is a marker: a process spawned with it as stdio
// is attached to the console, which supplies the real handles.
struct Pty {
  int refs;         // descriptors pointing here in this process
  int mrefs;        // of which masters
  uint32_t owner;   // pid of the process that created the console
  int64_t hpc;      // HPCON, valid in the owner only
  int64_t hold;     // holder process keeping the console attachable
  uint32_t holdpid;
  int64_t in_w;     // master → console
  int64_t out_w;    // console → master, for writes on the slave
  int64_t live_r;   // every slave holder has the write end of this pipe
  struct winsize ws;
};

#define __pty_isslave(f) ((f)->pty && !(f)->ptymaster)

int sys_openpty_nt(int *, int *, const struct winsize *);
int64_t __pty_write_handle(struct Fd *);
int __pty_close_nt(struct Fd *);
int __pty_getwinsize(struct Fd *, struct winsize *);
int __pty_setwinsize(struct Fd *, const struct winsize *);
void __pty_termios(struct termios *);
int64_t __pty_exec_prepare(uint32_t *, bool *, int64_t *);
int __pty_wait_readable(struct Fd *, bool);
bool __pty_hangup(struct Fd *);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_PTY_INTERNAL_H_ */

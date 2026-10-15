#ifndef COSMOPOLITAN_LIBC_INTRIN_PGRP_H_
#define COSMOPOLITAN_LIBC_INTRIN_PGRP_H_
#include "libc/atomic.h"
COSMOPOLITAN_C_START_

/* what a process publishes as Local\cosmo.pgrp.<pid> */
struct PgrpEntry {
  atomic_int pid;  /* cosmo pid; in an alias under a win32 pid, the one meant */
  atomic_int pgid; /* process group */
  atomic_uint self; /* win32 pid of a cosmo program publishing itself */
  atomic_int sid;   /* session */
};

/* a member of a process group on our console */
struct PgrpMember {
  int pid;         /* cosmo pid, or the win32 pid of a host program */
  unsigned winpid; /* win32 pid */
  bool cosmo;      /* a cosmo program, which takes signals by file */
};

void __pgrp_own(void);
int __pgrp_self(void);
int __pgrp_of(int);
int __sid_of(int);
void __sid_self_set(int);
int __pid_of_winpid(unsigned);
void __pgrp_self_set(int);
intptr_t __pgrp_publish(int, int, int, struct PgrpEntry **);
intptr_t __pgrp_alias(unsigned, int);
intptr_t __pgrp_handle(void);
void __pgrp_disown(void);
void __pgrp_unpublish(intptr_t, struct PgrpEntry *);
int __pgrp_members(int, struct PgrpMember *, int);
int __pgrp_foreground(void);
void __pgrp_set_foreground(int);
bool __pgrp_background(void);
bool __pgrp_tostop(void);
void __pgrp_set_tostop(bool);
void __pgrp_post(int, int);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_INTRIN_PGRP_H_ */

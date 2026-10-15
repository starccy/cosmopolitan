#ifndef COSMOPOLITAN_LIBC_NT_ENUM_WAIT_H_
#define COSMOPOLITAN_LIBC_NT_ENUM_WAIT_H_

#define kNtWaitFailed    0xffffffffu
#define kNtWaitTimeout   0x00000102u
#define kNtWaitAbandoned 0x00000080u

// WAIT_TYPE of NtWaitForMultipleObjects()
#define kNtWaitAll 0
#define kNtWaitAny 1

#endif /* COSMOPOLITAN_LIBC_NT_ENUM_WAIT_H_ */

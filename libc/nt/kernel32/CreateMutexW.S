#include "libc/nt/codegen.h"
.imp	kernel32,__imp_CreateMutexW,CreateMutexW

	.text.windows
	.ftrace1
CreateMutex:
	.ftrace2
#ifdef __x86_64__
	push	%rbp
	mov	%rsp,%rbp
	mov	__imp_CreateMutexW(%rip),%rax
	jmp	__sysv2nt
#elif defined(__aarch64__)
	mov	x0,#0
	ret
#endif
	.endfn	CreateMutex,globl
	.previous

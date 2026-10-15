#include "libc/nt/ntdllimport.h"
.ntimp	NtRemoveIoCompletionEx,NtRemoveIoCompletionEx

	.text.windows
	.ftrace1
NtRemoveIoCompletionEx:
	.ftrace2
#ifdef __x86_64__
	push	%rbp
	mov	%rsp,%rbp
	mov	__imp_NtRemoveIoCompletionEx(%rip),%rax
	jmp	__sysv2nt6
#elif defined(__aarch64__)
	mov	x0,#0
	ret
#endif
	.endfn	NtRemoveIoCompletionEx,globl
	.previous

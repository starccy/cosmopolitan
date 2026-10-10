#include "libc/nt/ntdllimport.h"
.ntimp	NtCancelWaitCompletionPacket,NtCancelWaitCompletionPacket

	.text.windows
	.ftrace1
NtCancelWaitCompletionPacket:
	.ftrace2
#ifdef __x86_64__
	push	%rbp
	mov	%rsp,%rbp
	mov	__imp_NtCancelWaitCompletionPacket(%rip),%rax
	jmp	__sysv2nt
#elif defined(__aarch64__)
	mov	x0,#0
	ret
#endif
	.endfn	NtCancelWaitCompletionPacket,globl
	.previous

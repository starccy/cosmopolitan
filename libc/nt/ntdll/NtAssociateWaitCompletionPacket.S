#include "libc/nt/ntdllimport.h"
.ntimp	NtAssociateWaitCompletionPacket,NtAssociateWaitCompletionPacket

	.text.windows
	.ftrace1
NtAssociateWaitCompletionPacket:
	.ftrace2
#ifdef __x86_64__
	push	%rbp
	mov	%rsp,%rbp
	mov	__imp_NtAssociateWaitCompletionPacket(%rip),%rax
	jmp	__sysv2nt8
#elif defined(__aarch64__)
	mov	x0,#0
	ret
#endif
	.endfn	NtAssociateWaitCompletionPacket,globl
	.previous

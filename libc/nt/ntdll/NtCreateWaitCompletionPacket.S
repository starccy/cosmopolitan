#include "libc/nt/ntdllimport.h"
.ntimp	NtCreateWaitCompletionPacket,NtCreateWaitCompletionPacket

	.text.windows
	.ftrace1
NtCreateWaitCompletionPacket:
	.ftrace2
#ifdef __x86_64__
	push	%rbp
	mov	%rsp,%rbp
	mov	__imp_NtCreateWaitCompletionPacket(%rip),%rax
	jmp	__sysv2nt
#elif defined(__aarch64__)
	mov	x0,#0
	ret
#endif
	.endfn	NtCreateWaitCompletionPacket,globl
	.previous

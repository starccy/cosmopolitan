#include "libc/nt/ntdllimport.h"
.ntimp	NtResumeProcess,NtResumeProcess

	.text.windows
	.ftrace1
NtResumeProcess:
	.ftrace2
#ifdef __x86_64__
	push	%rbp
	mov	%rsp,%rbp
	mov	%rdi,%rcx
	sub	$32,%rsp
	call	*__imp_NtResumeProcess(%rip)
	leave
#elif defined(__aarch64__)
	mov	x0,#0
#endif
	ret
	.endfn	NtResumeProcess,globl
	.previous

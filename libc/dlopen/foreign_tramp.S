/*-*- mode:unix-assembly; indent-tabs-mode:t; tab-width:8; coding:utf-8     -*-│
│ vi: set et ft=asm ts=8 tw=8 fenc=utf-8                                   :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2024 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include "libc/dce.h"
#include "libc/macros.h"

#define SIZE 0x0200
#define SKEW 0x10

	.section .text.tpidr_raw,"ax",@progbits
foreign_tramp:
	.cfi_startproc

#ifdef __x86_64__

//	once the host glibc is loaded every thread can run with the host's
//	thread block, see libc/thread/hostthread.c. a cosmo tib has itself
//	at 0x00 and 0x38, a host thread block has itself at 0x00 and our
//	tib at 0x38
	cmpb	$0,__hostlibc+4(%rip)	// HostLibc::dual
	je	.Lswitch
	mov	%fs:0,%r10
	cmp	%fs:0x38,%r10
	je	.Lenter
	jmp	*%r11
.Lenter:
	.cfi_remember_state
	push	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp,-16
	mov	%rsp,%rbp
	.cfi_def_cfa_register %rbp
	sub	$0xc0,%rsp
	movdqu	%xmm0,0x00(%rsp)
	movdqu	%xmm1,0x10(%rsp)
	movdqu	%xmm2,0x20(%rsp)
	movdqu	%xmm3,0x30(%rsp)
	movdqu	%xmm4,0x40(%rsp)
	movdqu	%xmm5,0x50(%rsp)
	movdqu	%xmm6,0x60(%rsp)
	movdqu	%xmm7,0x70(%rsp)
	mov	%rdi,0x80(%rsp)
	mov	%rsi,0x88(%rsp)
	mov	%rdx,0x90(%rsp)
	mov	%rcx,0x98(%rsp)
	mov	%r8,0xa0(%rsp)
	mov	%r9,0xa8(%rsp)
	mov	%rax,0xb0(%rsp)
	mov	%r11,0xb8(%rsp)
	call	__host_enter
	movdqu	0x00(%rsp),%xmm0
	movdqu	0x10(%rsp),%xmm1
	movdqu	0x20(%rsp),%xmm2
	movdqu	0x30(%rsp),%xmm3
	movdqu	0x40(%rsp),%xmm4
	movdqu	0x50(%rsp),%xmm5
	movdqu	0x60(%rsp),%xmm6
	movdqu	0x70(%rsp),%xmm7
	mov	0x80(%rsp),%rdi
	mov	0x88(%rsp),%rsi
	mov	0x90(%rsp),%rdx
	mov	0x98(%rsp),%rcx
	mov	0xa0(%rsp),%r8
	mov	0xa8(%rsp),%r9
	mov	0xb0(%rsp),%rax
	mov	0xb8(%rsp),%r11
	leave
	.cfi_def_cfa %rsp,8
	jmp	*%r11
	.cfi_restore_state
	.weak	__host_enter

.Lswitch:
	push	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp,-16
	mov	%rsp,%rbp
	.cfi_def_cfa_register %rbp
	sub	$SIZE,%rsp

//	save vector arguments
	movdqu	%xmm0,-0x10(%rbp)
	movdqu	%xmm1,-0x20(%rbp)
	movdqu	%xmm2,-0x30(%rbp)
	movdqu	%xmm3,-0x40(%rbp)
	movdqu	%xmm4,-0x50(%rbp)
	movdqu	%xmm5,-0x60(%rbp)
	movdqu	%xmm6,-0x70(%rbp)
	movdqu	%xmm7,-0x80(%rbp)

//	save register arguments
	mov	%rdi,-0x88(%rbp)
	mov	%rsi,-0x90(%rbp)
	mov	%rdx,-0x98(%rbp)
	mov	%rcx,-0xa0(%rbp)
	mov	%r8,-0xa8(%rbp)
	mov	%r9,-0xb0(%rbp)

//	save function pointer, and %al for a variadic callee
	mov	%r11,-0xb8(%rbp)
	mov	%rax,-0xd0(%rbp)

//	block signals
	call	__sig_block
	mov	%rax,-0xc0(%rbp)

//	switch to foreign tls
#if SupportsXnu() || SupportsWindows()
	call	__get_tls_rax
#else
	mov	%fs:0x38,%rax
#endif
	mov	%rax,-0xc8(%rbp)
	mov	__foreign+8(%rip),%rdi
	call	__set_tls

//	move stack arguments
	movdqu	SKEW+0x00(%rbp),%xmm0
	movdqu	SKEW+0x10(%rbp),%xmm1
	movdqu	SKEW+0x20(%rbp),%xmm2
	movdqu	SKEW+0x30(%rbp),%xmm3
	movdqu	SKEW+0x40(%rbp),%xmm4
	movdqu	SKEW+0x50(%rbp),%xmm5
	movdqu	SKEW+0x60(%rbp),%xmm6
	movdqu	SKEW+0x70(%rbp),%xmm7
	movdqu	%xmm0,-SIZE+0x00(%rbp)
	movdqu	%xmm1,-SIZE+0x10(%rbp)
	movdqu	%xmm2,-SIZE+0x20(%rbp)
	movdqu	%xmm3,-SIZE+0x30(%rbp)
	movdqu	%xmm4,-SIZE+0x40(%rbp)
	movdqu	%xmm5,-SIZE+0x50(%rbp)
	movdqu	%xmm6,-SIZE+0x60(%rbp)
	movdqu	%xmm7,-SIZE+0x70(%rbp)
	movdqu	SKEW+0x80(%rbp),%xmm0
	movdqu	SKEW+0x90(%rbp),%xmm1
	movdqu	SKEW+0xa0(%rbp),%xmm2
	movdqu	SKEW+0xb0(%rbp),%xmm3
	movdqu	SKEW+0xc0(%rbp),%xmm4
	movdqu	SKEW+0xd0(%rbp),%xmm5
	movdqu	SKEW+0xe0(%rbp),%xmm6
	movdqu	SKEW+0xf0(%rbp),%xmm7
	movdqu	%xmm0,-SIZE+0x80(%rbp)
	movdqu	%xmm1,-SIZE+0x90(%rbp)
	movdqu	%xmm2,-SIZE+0xa0(%rbp)
	movdqu	%xmm3,-SIZE+0xb0(%rbp)
	movdqu	%xmm4,-SIZE+0xc0(%rbp)
	movdqu	%xmm5,-SIZE+0xd0(%rbp)
	movdqu	%xmm6,-SIZE+0xe0(%rbp)
	movdqu	%xmm7,-SIZE+0xf0(%rbp)

//	restore vector arguments
	movdqu	-0x10(%rbp),%xmm0
	movdqu	-0x20(%rbp),%xmm1
	movdqu	-0x30(%rbp),%xmm2
	movdqu	-0x40(%rbp),%xmm3
	movdqu	-0x50(%rbp),%xmm4
	movdqu	-0x60(%rbp),%xmm5
	movdqu	-0x70(%rbp),%xmm6
	movdqu	-0x80(%rbp),%xmm7

//	restore register arguments
	mov	-0x88(%rbp),%rdi
	mov	-0x90(%rbp),%rsi
	mov	-0x98(%rbp),%rdx
	mov	-0xa0(%rbp),%rcx
	mov	-0xa8(%rbp),%r8
	mov	-0xb0(%rbp),%r9

//	call function
	mov	-0xd0(%rbp),%rax
	call	*-0xb8(%rbp)

//	save function result
	movdqu	%xmm0,-0x10(%rbp)
	movdqu	%xmm1,-0x20(%rbp)
	mov	%rax,-0x28(%rbp)
	mov	%rdx,-0x30(%rbp)

//	restore tls
	mov	-0xc8(%rbp),%rdi
	call	__set_tls

//	unblock signals
	mov	-0xc0(%rbp),%rdi
	call	__sig_unblock

//	restore function result
	mov	-0x28(%rbp),%rax
	mov	-0x30(%rbp),%rdx
	movdqu	-0x10(%rbp),%xmm0
	movdqu	-0x20(%rbp),%xmm1

	add	$SIZE,%rsp
	pop	%rbp
	.cfi_def_cfa %rsp,8
	ret

#elif defined(__aarch64__)

//	the thread register is the host's on xnu. on linux, once the host
//	glibc is loaded, a thread runs with a host thread block whose second
//	word is our tib; a cosmo thread's register points just past its tib
	adrp	x9,__hostos
	ldr	w9,[x9,#:lo12:__hostos]
	tbnz	w9,#3,.Ldirect			// _HOSTXNU
	adrp	x9,__hostlibc
	add	x9,x9,#:lo12:__hostlibc
	ldrb	w9,[x9,#4]			// HostLibc::dual
	cbz	w9,.Lswitch
	mrs	x9,tpidr_el0
	ldr	x10,[x9,#8]
	add	x10,x10,#1024
	cmp	x9,x10
	b.eq	.Lenter
.Ldirect:
	br	x16
.Lenter:
	.cfi_remember_state
	stp	x29,x30,[sp,#-0xe0]!
	.cfi_def_cfa_offset 0xe0
	.cfi_offset x29,-0xe0
	.cfi_offset x30,-0xd8
	mov	x29,sp
	.cfi_def_cfa_register x29
	stp	q0,q1,[sp,#0x10]
	stp	q2,q3,[sp,#0x30]
	stp	q4,q5,[sp,#0x50]
	stp	q6,q7,[sp,#0x70]
	stp	x0,x1,[sp,#0x90]
	stp	x2,x3,[sp,#0xa0]
	stp	x4,x5,[sp,#0xb0]
	stp	x6,x7,[sp,#0xc0]
	stp	x8,x16,[sp,#0xd0]
	bl	__host_enter
	ldp	q0,q1,[sp,#0x10]
	ldp	q2,q3,[sp,#0x30]
	ldp	q4,q5,[sp,#0x50]
	ldp	q6,q7,[sp,#0x70]
	ldp	x0,x1,[sp,#0x90]
	ldp	x2,x3,[sp,#0xa0]
	ldp	x4,x5,[sp,#0xb0]
	ldp	x6,x7,[sp,#0xc0]
	ldp	x8,x16,[sp,#0xd0]
	ldp	x29,x30,[sp],#0xe0
	.cfi_def_cfa sp,0
	.cfi_restore x29
	.cfi_restore x30
	br	x16
	.cfi_restore_state
	.weak	__host_enter

.Lswitch:
	stp	x29,x30,[sp,-0x100]!
	.cfi_def_cfa_offset 0x100
	.cfi_offset x29,-0x100
	.cfi_offset x30,-0xf8
	mov	x29,sp
	.cfi_def_cfa_register x29

//	save vector arguments
	stp	q0,q1,[sp,0x10]
	stp	q2,q3,[sp,0x30]
	stp	q4,q5,[sp,0x50]
	stp	q6,q7,[sp,0x70]

//	save register arguments
	stp	x0,x1,[sp,0x90]
	stp	x2,x3,[sp,0xa0]
	stp	x4,x5,[sp,0xb0]
	stp	x6,x7,[sp,0xc0]

//	save function pointer, and x8 for a callee returning a struct
	str	x16,[sp,0xd0]
	str	x8,[sp,0xe8]

//	block signals
	bl	__sig_block
	str	x0,[sp,0xd8]

//	switch to the host thread block
	mrs	x9,tpidr_el0
	str	x9,[sp,0xe0]
	adrp	x9,__foreign
	ldr	x9,[x9,#:lo12:__foreign+8]
	msr	tpidr_el0,x9

//	move stack arguments
	sub	sp,sp,#0x100
	ldp	q0,q1,[sp,SIZE+0x00]
	ldp	q2,q3,[sp,SIZE+0x20]
	ldp	q4,q5,[sp,SIZE+0x40]
	ldp	q6,q7,[sp,SIZE+0x60]
	stp	q0,q1,[sp,0x00]
	stp	q2,q3,[sp,0x20]
	stp	q4,q5,[sp,0x40]
	stp	q6,q7,[sp,0x60]
	ldp	q0,q1,[sp,SIZE+0x80]
	ldp	q2,q3,[sp,SIZE+0xa0]
	ldp	q4,q5,[sp,SIZE+0xc0]
	ldp	q6,q7,[sp,SIZE+0xe0]
	stp	q0,q1,[sp,0x80]
	stp	q2,q3,[sp,0xa0]
	stp	q4,q5,[sp,0xc0]
	stp	q6,q7,[sp,0xe0]

//	restore vector arguments
	ldp	q0,q1,[sp,0x100+0x10]
	ldp	q2,q3,[sp,0x100+0x30]
	ldp	q4,q5,[sp,0x100+0x50]
	ldp	q6,q7,[sp,0x100+0x70]

//	restore register arguments
	ldp	x0,x1,[sp,0x100+0x90]
	ldp	x2,x3,[sp,0x100+0xa0]
	ldp	x4,x5,[sp,0x100+0xb0]
	ldp	x6,x7,[sp,0x100+0xc0]

//	call function
	ldr	x16,[sp,0x100+0xd0]
	ldr	x8,[sp,0x100+0xe8]
	blr	x16
	add	sp,sp,#0x100

//	save vector results
	stp	q0,q1,[sp,0x10]
	stp	q2,q3,[sp,0x30]
	stp	q4,q5,[sp,0x50]
	stp	q6,q7,[sp,0x70]

//	save register results
	stp	x0,x1,[sp,0x90]
	stp	x2,x3,[sp,0xa0]
	stp	x4,x5,[sp,0xb0]
	stp	x6,x7,[sp,0xc0]

//	switch back to our thread register
	ldr	x9,[sp,0xe0]
	msr	tpidr_el0,x9

//	unblock signals
	ldr	x0,[sp,0xd8]
	bl	__sig_unblock

//	restore vector results
	ldp	q0,q1,[sp,0x10]
	ldp	q2,q3,[sp,0x30]
	ldp	q4,q5,[sp,0x50]
	ldp	q6,q7,[sp,0x70]

//	restore register results
	ldp	x0,x1,[sp,0x90]
	ldp	x2,x3,[sp,0xa0]
	ldp	x4,x5,[sp,0xb0]
	ldp	x6,x7,[sp,0xc0]

	ldp	x29,x30,[sp],0x100
	.cfi_def_cfa sp,0
	.cfi_restore x29
	.cfi_restore x30
	ret

#endif // __x86_64__

	.cfi_endproc
	.endfn	foreign_tramp,globl

	.symver	__libc_start_main,__libc_start_main@GLIBC_2.2.5
	.text
	.globl	_start
	.hidden	_start
_start:	xor	%ebp,%ebp
	mov	%rdx,%r9
	pop	%rsi
	mov	%rsp,%rdx
	and	$-16,%rsp
	push	%rax
	push	%rsp
	xor	%r8d,%r8d
	xor	%ecx,%ecx
	lea	main(%rip),%rdi
	call	*__libc_start_main@GOTPCREL(%rip)
	hlt

	.data
	.globl	__dso_handle
	.hidden	__dso_handle
	.balign	8
__dso_handle:
	.quad	__dso_handle

	.section .note.GNU-stack,"x",@progbits

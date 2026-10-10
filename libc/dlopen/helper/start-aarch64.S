	.symver	__libc_start_main,__libc_start_main@GLIBC_2.17
	.text
	.globl	_start
	.hidden	_start
_start:	mov	x29,#0
	mov	x30,#0
	mov	x5,x0
	ldr	x1,[sp]
	add	x2,sp,#8
	mov	x6,sp
	mov	x3,#0
	mov	x4,#0
	adrp	x0,main
	add	x0,x0,:lo12:main
	bl	__libc_start_main
	brk	#1000

	.data
	.globl	__dso_handle
	.hidden	__dso_handle
	.balign	8
__dso_handle:
	.quad	__dso_handle

	.section .note.GNU-stack,"x",@progbits

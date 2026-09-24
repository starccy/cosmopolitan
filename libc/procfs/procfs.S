#include "libc/macros.h"

//	static_yoink this symbol for /proc and /sys on Windows and macOS.
	procfs = 0
	.globl	procfs

	.yoink	__procfs_open
	.yoink	__procfs_stat
	.yoink	__procfs_access
	.yoink	__procfs_readlink
	.yoink	__procfs_read
	.yoink	__procfs_seek
	.yoink	__procfs_fstat
	.yoink	__procfs_readdir
	.yoink	__procfs_close
	.yoink	__procfs_keep
	.yoink	__procfs_drop
	.yoink	__procfs_postdup

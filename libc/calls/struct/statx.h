#ifndef COSMOPOLITAN_LIBC_CALLS_STRUCT_STATX_H_
#define COSMOPOLITAN_LIBC_CALLS_STRUCT_STATX_H_
COSMOPOLITAN_C_START_

#define STATX_TYPE        0x0001
#define STATX_MODE        0x0002
#define STATX_NLINK       0x0004
#define STATX_UID         0x0008
#define STATX_GID         0x0010
#define STATX_ATIME       0x0020
#define STATX_MTIME       0x0040
#define STATX_CTIME       0x0080
#define STATX_INO         0x0100
#define STATX_SIZE        0x0200
#define STATX_BLOCKS      0x0400
#define STATX_BASIC_STATS 0x07ff
#define STATX_BTIME       0x0800
#define STATX_ALL         0x0fff
#define STATX_MNT_ID      0x1000
#define STATX__RESERVED   0x80000000u

struct statx_timestamp {
  int64_t tv_sec;
  uint32_t tv_nsec;
  int32_t __reserved;
};

struct statx { /* linux abi */
  uint32_t stx_mask;
  uint32_t stx_blksize;
  uint64_t stx_attributes;
  uint32_t stx_nlink;
  uint32_t stx_uid;
  uint32_t stx_gid;
  uint16_t stx_mode;
  uint16_t __spare0[1];
  uint64_t stx_ino;
  uint64_t stx_size;
  uint64_t stx_blocks;
  uint64_t stx_attributes_mask;
  struct statx_timestamp stx_atime;
  struct statx_timestamp stx_btime;
  struct statx_timestamp stx_ctime;
  struct statx_timestamp stx_mtime;
  uint32_t stx_rdev_major;
  uint32_t stx_rdev_minor;
  uint32_t stx_dev_major;
  uint32_t stx_dev_minor;
  uint64_t stx_mnt_id;
  uint32_t stx_dio_mem_align;
  uint32_t stx_dio_offset_align;
  uint64_t stx_subvol;
  uint32_t stx_atomic_write_unit_min;
  uint32_t stx_atomic_write_unit_max;
  uint32_t stx_atomic_write_segments_max;
  uint32_t stx_dio_read_offset_align;
  uint64_t __spare3[9];
};

int statx(int, const char *, int, unsigned, struct statx *);

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_CALLS_STRUCT_STATX_H_ */

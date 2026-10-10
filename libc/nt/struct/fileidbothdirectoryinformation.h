#ifndef COSMOPOLITAN_LIBC_NT_STRUCT_FILEIDBOTHDIRECTORYINFORMATION_H_
#define COSMOPOLITAN_LIBC_NT_STRUCT_FILEIDBOTHDIRECTORYINFORMATION_H_
COSMOPOLITAN_C_START_

struct NtFileIdBothDirectoryInformation {
  uint32_t NextEntryOffset;
  uint32_t FileIndex;
  int64_t CreationTime;
  int64_t LastAccessTime;
  int64_t LastWriteTime;
  int64_t ChangeTime;
  int64_t EndOfFile;
  int64_t AllocationSize;
  uint32_t FileAttributes;
  uint32_t FileNameLength;
  uint32_t EaSize; /* reparse tag when FileAttributes has reparse point */
  unsigned char ShortNameLength;
  char16_t ShortName[12];
  int64_t FileId;
  char16_t FileName[1];
};

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_NT_STRUCT_FILEIDBOTHDIRECTORYINFORMATION_H_ */

#ifndef COSMOPOLITAN_LIBC_NT_STRUCT_FILENOTIFYINFORMATION_H_
#define COSMOPOLITAN_LIBC_NT_STRUCT_FILENOTIFYINFORMATION_H_

struct NtFileNotifyInformation {
  uint32_t NextEntryOffset;
  uint32_t Action;          /* libc/nt/enum/fileaction.h */
  uint32_t FileNameLength;  /* in bytes, no terminator */
  char16_t FileName[];
};

#endif /* COSMOPOLITAN_LIBC_NT_STRUCT_FILENOTIFYINFORMATION_H_ */

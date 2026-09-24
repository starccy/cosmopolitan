#include "libc/calls/syscall-nt.internal.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/dce.h"
#include "libc/nt/enum/fileinfobyhandleclass.h"
#include "libc/nt/enum/filetype.h"
#include "libc/nt/errors.h"
#include "libc/nt/files.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/byhandlefileinformation.h"
#include "libc/sysv/errfuns.h"
#if SupportsWindows()

textwindows int sys_fallocate_nt(int64_t handle, int64_t offset,
                                 int64_t length, bool keep_size) {
  int type = GetFileType(handle);
  if (type == kNtFileTypePipe)
    return espipe();
  if (type != kNtFileTypeDisk)
    return enodev();
  struct NtByHandleFileInformation info;
  if (!GetFileInformationByHandle(handle, &info))
    return __winerr();
  int64_t size = (int64_t)info.nFileSizeHigh << 32 | info.nFileSizeLow;
  int64_t end = offset + length;
  int64_t alloc = end > size ? end : size;
  if (!SetFileInformationByHandle(handle, kNtFileAllocationInfo, &alloc,
                                  sizeof(alloc)))
    return __winerr();
  if (!keep_size && end > size) {
    if (!SetFileInformationByHandle(handle, kNtFileEndOfFileInfo, &end,
                                    sizeof(end)))
      return __winerr();
  }
  return 0;
}

#endif

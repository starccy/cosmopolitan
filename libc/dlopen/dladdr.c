#include "ape/sections.internal.h"
#include "libc/calls/calls.h"
#include "libc/dce.h"
#include "libc/dlopen/dlfcn.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/o.h"
#include "libc/calls/syscall_support-nt.internal.h"
#include "libc/macros.h"
#include "libc/nt/dll.h"
#include "libc/nt/enum/getmodulehandleex.h"
#include "libc/nt/pedef.internal.h"
#include "libc/nt/runtime.h"
#include "libc/nt/struct/imagedatadirectory.internal.h"
#include "libc/nt/struct/imagedosheader.internal.h"
#include "libc/nt/struct/imageexportdirectory.internal.h"
#include "libc/nt/struct/imagentheaders.internal.h"
#include "libc/nt/struct/imageoptionalheader.internal.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/syslib.internal.h"

// answers for host libraries on linux, once one is loaded; see dlopen.c
int __dladdr_host(const void *, Dl_info *) __attribute__((__weak__));

static char g_dladdr_fname[4096];

static int hexval(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

// returns 1 when the line's range contains addr and names a file, 0 otherwise.
// the fields between the range and the path never contain '/', so the first
// '/' starts the path; it runs to end of line, spaces included
static int CheckLine(char *line, uintptr_t addr, Dl_info *info) {
  uintptr_t start = 0, end = 0;
  char *p = line;
  int v;
  while ((v = hexval(*p)) >= 0) {
    start = (start << 4) | (uintptr_t)v;
    p++;
  }
  if (p == line || *p != '-')
    return 0;
  char *q = ++p;
  while ((v = hexval(*p)) >= 0) {
    end = (end << 4) | (uintptr_t)v;
    p++;
  }
  if (p == q || *p != ' ')
    return 0;
  if (addr < start || addr >= end)
    return 0;
  char *path = strchr(p, '/');
  if (!path)
    return 0;
  size_t n = strlen(path);
  if (n >= sizeof(g_dladdr_fname))
    return 0;
  memcpy(g_dladdr_fname, path, n + 1);
  info->dli_fname = g_dladdr_fname;
  info->dli_fbase = (void *)start;
  info->dli_sname = 0;
  info->dli_saddr = 0;
  return 1;
}

// the file mapping addr, from /proc/self/maps
static int dladdr_maps(const void *addr, Dl_info *info) {
  int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return 0;

  static char buf[8192];
  size_t len = 0;
  int found = 0, skipping = 0;
  for (;;) {
    ssize_t n = read(fd, buf + len, sizeof(buf) - len);
    if (n <= 0)
      break;
    len += (size_t)n;
    char *line = buf;
    for (;;) {
      char *nl = memchr(line, '\n', len - (size_t)(line - buf));
      if (!nl)
        break;
      *nl = 0;
      if (skipping) {
        skipping = 0;
      } else if (CheckLine(line, (uintptr_t)addr, info)) {
        found = 1;
        break;
      }
      line = nl + 1;
    }
    if (found)
      break;
    len -= (size_t)(line - buf);
    memmove(buf, line, len);
    if (len == sizeof(buf)) {
      len = 0;
      skipping = 1;
    }
  }
  close(fd);
  return found;
}

#ifdef __x86_64__
// the module holding addr, and the nearest export at or below it
static int dladdr_nt(const void *addr, Dl_info *info) {
  int64_t mod;
  char16_t path16[PATH_MAX];
  if (!GetModuleHandleEx(kNtGetModuleHandleExFlagFromAddress |
                             kNtGetModuleHandleExFlagUnchangedRefcount,
                         (const char16_t *)addr, &mod))
    return 0;
  uint32_t n = GetModuleFileName(mod, path16, ARRAYLEN(path16));
  if (!n || n >= ARRAYLEN(path16) || __mkunixpath(path16, g_dladdr_fname) < 0)
    return 0;
  char *base = (char *)mod;
  info->dli_fname = g_dladdr_fname;
  info->dli_fbase = base;
  info->dli_sname = 0;
  info->dli_saddr = 0;
  struct NtImageDosHeader *dos = (void *)base;
  struct NtImageNtHeaders *nt = (void *)(base + dos->e_lfanew);
  struct NtImageDataDirectory *dir =
      &nt->OptionalHeader.DataDirectory[kNtImageDirectoryEntryExport];
  if (!dir->VirtualAddress || !dir->Size)
    return 1;
  struct NtImageExportDirectory *ex = (void *)(base + dir->VirtualAddress);
  uint32_t *funcs = (uint32_t *)(base + ex->AddressOfFunctions);
  uint32_t *names = (uint32_t *)(base + ex->AddressOfNames);
  uint16_t *ords = (uint16_t *)(base + ex->AddressOfNameOrdinals);
  uintptr_t rva = (uintptr_t)addr - (uintptr_t)base, best = 0;
  for (uint32_t i = 0; i < ex->NumberOfNames; ++i) {
    if (ords[i] >= ex->NumberOfFunctions)
      continue;
    uint32_t f = funcs[ords[i]];
    // an rva inside the export directory is a forwarder string
    if (f >= dir->VirtualAddress && f < dir->VirtualAddress + dir->Size)
      continue;
    if (f <= rva && (!info->dli_sname || f > best)) {
      best = f;
      info->dli_sname = base + names[i];
      info->dli_saddr = base + f;
    }
  }
  return 1;
}
#endif

/**
 * Finds the file that maps an address, and the symbol nearest below it.
 *
 * For code in a host library, which the host's loader knows, the answer
 * is the host's: the library's path, its base, and the nearest exported
 * symbol when there is one. On Linux that needs a host library loaded
 * already, and otherwise /proc/self/maps names the file, with the
 * symbol fields left null. On Windows the symbol comes from the module's
 * export table. An address in this program itself gets the program's
 * path and no symbol, since it has no dynamic symbol table.
 *
 * The returned `dli_fname` may point into a static buffer overwritten by
 * the next call.
 *
 * @return 1 if info was filled in, 0 otherwise
 */
int dladdr(const void *addr, Dl_info *info) {
  addr = cosmo_dluntramp((void *)addr);
  if (__dladdr_host && __dladdr_host(addr, info))
    return 1;
  if (IsLinux())
    return dladdr_maps(addr, info);
#ifdef __x86_64__
  if (IsWindows())
    return dladdr_nt(addr, info);
#endif
#ifdef __aarch64__
  if (IsXnuSilicon()) {
    int (*host)(const void *, Dl_info *);
    if ((host = __syslib->__dlsym((void *)-2, "dladdr")) && host(addr, info))
      return 1;
  }
#endif
  if ((uintptr_t)addr >= (uintptr_t)__executable_start &&
      (uintptr_t)addr < (uintptr_t)_end) {
    info->dli_fname = GetProgramExecutableName();
    info->dli_fbase = (void *)__executable_start;
    info->dli_sname = 0;
    info->dli_saddr = 0;
    return 1;
  }
  return 0;
}

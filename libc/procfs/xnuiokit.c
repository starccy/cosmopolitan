#include "libc/procfs/internal.h"
#include "libc/procfs/xnu.internal.h"
#include "libc/runtime/syslib.internal.h"

// The IOKit side of the XNU emulation: /proc/diskstats and partitions out
// of the storage drivers, /sys/class/power_supply out of the smart
// battery, and /sys/class/dmi/id out of the platform expert device. The
// frameworks are loaded with the ape loader's dlopen the first time one
// of these files is read, so a process that never looks pays nothing.
// Everything runs under the carrier's lock. CoreFoundation is not usable
// in a forked child, so a child answers as if the frameworks were absent.

#ifdef __aarch64__

#define XNU_RTLD_LAZY          1
#define XNU_RTLD_LOCAL         4
#define CF_UTF8                0x08000100
#define CF_SINT64              4
#define IO_SERVICE_PLANE       "IOService"

typedef uint32_t io_object_t;

static struct {
  bool tried, ok;
  int pid;
  void *(*IOServiceMatching)(const char *);
  int (*IOServiceGetMatchingServices)(uint32_t, void *, io_object_t *);
  io_object_t (*IOIteratorNext)(io_object_t);
  int (*IOObjectRelease)(io_object_t);
  void *(*IORegistryEntryCreateCFProperty)(io_object_t, void *, void *,
                                           uint32_t);
  int (*IORegistryEntryGetParentEntry)(io_object_t, const char *,
                                       io_object_t *);
  io_object_t (*IORegistryEntryFromPath)(uint32_t, const char *);
  unsigned char (*IOObjectConformsTo)(io_object_t, const char *);
  void *(*CFStringCreateWithCString)(void *, const char *, uint32_t);
  void *(*CFDictionaryGetValue)(void *, void *);
  unsigned char (*CFNumberGetValue)(void *, long, void *);
  unsigned long (*CFGetTypeID)(void *);
  unsigned long (*CFNumberGetTypeID)(void);
  unsigned long (*CFStringGetTypeID)(void);
  unsigned long (*CFDataGetTypeID)(void);
  unsigned long (*CFBooleanGetTypeID)(void);
  unsigned long (*CFDictionaryGetTypeID)(void);
  unsigned char (*CFStringGetCString)(void *, char *, long, uint32_t);
  const uint8_t *(*CFDataGetBytePtr)(void *);
  long (*CFDataGetLength)(void *);
  unsigned char (*CFBooleanGetValue)(void *);
  void (*CFRelease)(void *);
} g;

static bool iokit_load(void) {
  if (!g.tried) {
    g.tried = true;
    void *io, *cf;
    if (IsXnuSilicon() && __syslib && __syslib->__version >= 6 &&
        (cf = __syslib->__dlopen("/System/Library/Frameworks/"
                                 "CoreFoundation.framework/CoreFoundation",
                                 XNU_RTLD_LAZY | XNU_RTLD_LOCAL)) &&
        (io = __syslib->__dlopen(
             "/System/Library/Frameworks/IOKit.framework/IOKit",
             XNU_RTLD_LAZY | XNU_RTLD_LOCAL))) {
      bool ok = true;
#define SYM(lib, name) \
  ok &= !!(*(void **)&g.name = __syslib->__dlsym(lib, #name))
      SYM(io, IOServiceMatching);
      SYM(io, IOServiceGetMatchingServices);
      SYM(io, IOIteratorNext);
      SYM(io, IOObjectRelease);
      SYM(io, IORegistryEntryCreateCFProperty);
      SYM(io, IORegistryEntryGetParentEntry);
      SYM(io, IORegistryEntryFromPath);
      SYM(io, IOObjectConformsTo);
      SYM(cf, CFStringCreateWithCString);
      SYM(cf, CFDictionaryGetValue);
      SYM(cf, CFNumberGetValue);
      SYM(cf, CFGetTypeID);
      SYM(cf, CFNumberGetTypeID);
      SYM(cf, CFStringGetTypeID);
      SYM(cf, CFDataGetTypeID);
      SYM(cf, CFBooleanGetTypeID);
      SYM(cf, CFDictionaryGetTypeID);
      SYM(cf, CFStringGetCString);
      SYM(cf, CFDataGetBytePtr);
      SYM(cf, CFDataGetLength);
      SYM(cf, CFBooleanGetValue);
      SYM(cf, CFRelease);
#undef SYM
      if (ok) {
        g.pid = getpid();
        g.ok = true;
      }
    }
  }
  return g.ok && g.pid == getpid();
}

// ---------------------------------------------------------------------------
// Property readers. A value may be a number, a boolean, a string or data
// (device tree strings are data with a trailing NUL); each reader takes
// the kinds that make sense for it and leaves the output alone otherwise.

static void *key(const char *name) {
  return g.CFStringCreateWithCString(0, name, CF_UTF8);
}

static bool value_i64(void *v, int64_t *out) {
  if (!v)
    return false;
  unsigned long t = g.CFGetTypeID(v);
  if (t == g.CFNumberGetTypeID())
    return g.CFNumberGetValue(v, CF_SINT64, out);
  if (t == g.CFBooleanGetTypeID()) {
    *out = g.CFBooleanGetValue(v) ? 1 : 0;
    return true;
  }
  return false;
}

static bool value_str(void *v, char *out, size_t n) {
  if (!v)
    return false;
  unsigned long t = g.CFGetTypeID(v);
  if (t == g.CFStringGetTypeID())
    return g.CFStringGetCString(v, out, (long)n, CF_UTF8);
  if (t == g.CFDataGetTypeID()) {
    const uint8_t *p = g.CFDataGetBytePtr(v);
    size_t len = (size_t)g.CFDataGetLength(v);
    if (!p)
      return false;
    size_t k = 0;
    while (k < len && k < n - 1 && p[k])
      k++;
    memcpy(out, p, k);
    out[k] = 0;
    return k > 0;
  }
  return false;
}

static bool prop_i64(io_object_t e, const char *name, int64_t *out) {
  void *k = key(name);
  void *v = g.IORegistryEntryCreateCFProperty(e, k, 0, 0);
  bool ok = value_i64(v, out);
  if (v)
    g.CFRelease(v);
  g.CFRelease(k);
  return ok;
}

static bool prop_str(io_object_t e, const char *name, char *out, size_t n) {
  void *k = key(name);
  void *v = g.IORegistryEntryCreateCFProperty(e, k, 0, 0);
  bool ok = value_str(v, out, n);
  if (v)
    g.CFRelease(v);
  g.CFRelease(k);
  return ok;
}

// a number inside a dictionary-valued property (the Statistics dict)
static int64_t dict_i64(void *dict, const char *name) {
  void *k = key(name);
  int64_t v = 0;
  value_i64(g.CFDictionaryGetValue(dict, k), &v);
  g.CFRelease(k);
  return v;
}

static io_object_t services(const char *cls) {
  void *match = g.IOServiceMatching(cls);
  io_object_t it = 0;
  if (!match || g.IOServiceGetMatchingServices(0, match, &it))
    return 0;
  return it;
}

// ---------------------------------------------------------------------------
// Disks. Every whole IOMedia under a block storage driver is a disk; the
// driver carries the counters, the media its BSD name and device numbers.
// Times are nanoseconds there and milliseconds in the file; sectors are
// the 512-byte units Linux reports whatever the hardware's.

void pfs_xnu_diskstats(struct pfs_buf *b) {
  if (!iokit_load())
    return;
  io_object_t it = services("IOMedia"), e;
  if (!it)
    return;
  while ((e = g.IOIteratorNext(it))) {
    int64_t whole = 0, major = 0, minor = 0;
    char name[32];
    io_object_t parent = 0;
    if (prop_i64(e, "Whole", &whole) && whole &&
        prop_str(e, "BSD Name", name, sizeof name) &&
        !g.IORegistryEntryGetParentEntry(e, IO_SERVICE_PLANE, &parent)) {
      if (g.IOObjectConformsTo(parent, "IOBlockStorageDriver")) {
        prop_i64(e, "BSD Major", &major);
        prop_i64(e, "BSD Minor", &minor);
        void *k = key("Statistics");
        void *st = g.IORegistryEntryCreateCFProperty(parent, k, 0, 0);
        g.CFRelease(k);
        if (st && g.CFGetTypeID(st) == g.CFDictionaryGetTypeID()) {
          unsigned long long rd_ms =
              (unsigned long long)(dict_i64(st, "Total Time (Read)") / 1000000);
          unsigned long long wr_ms =
              (unsigned long long)(dict_i64(st, "Total Time (Write)") / 1000000);
          pfs_printf(b,
                     "%4d %7d %s %llu 0 %llu %llu %llu 0 %llu %llu 0 %llu "
                     "%llu\n",
                     (int)major, (int)minor, name,
                     (unsigned long long)dict_i64(st, "Operations (Read)"),
                     (unsigned long long)(dict_i64(st, "Bytes (Read)") / 512),
                     rd_ms,
                     (unsigned long long)dict_i64(st, "Operations (Write)"),
                     (unsigned long long)(dict_i64(st, "Bytes (Write)") / 512),
                     wr_ms, rd_ms + wr_ms, rd_ms + wr_ms);
        }
        if (st)
          g.CFRelease(st);
      }
      g.IOObjectRelease(parent);
    }
    g.IOObjectRelease(e);
  }
  g.IOObjectRelease(it);
}

// Every IOMedia with a BSD name, disks and their slices alike, with the
// device numbers the kernel gave them.
void pfs_xnu_partitions(struct pfs_buf *b) {
  pfs_printf(b, "major minor  #blocks  name\n\n");
  if (!iokit_load())
    return;
  io_object_t it = services("IOMedia"), e;
  if (!it)
    return;
  while ((e = g.IOIteratorNext(it))) {
    int64_t major = 0, minor = 0, size = 0;
    char name[32];
    if (prop_str(e, "BSD Name", name, sizeof name)) {
      prop_i64(e, "BSD Major", &major);
      prop_i64(e, "BSD Minor", &minor);
      prop_i64(e, "Size", &size);
      pfs_printf(b, "%4d  %7d %10llu %s\n", (int)major, (int)minor,
                 (unsigned long long)(size / 1024), name);
    }
    g.IOObjectRelease(e);
  }
  g.IOObjectRelease(it);
}

// ---------------------------------------------------------------------------
// The battery. AppleSmartBattery reports charge in mAh (the AppleRaw*
// pair; the plain pair is a percentage on Apple silicon) at a voltage in
// mV, so the mWh figures the sysfs files want are their product. A Mac
// without one is on mains.

bool pfs_xnu_battery(struct pfs_batt *out) {
  memset(out, 0, sizeof *out);
  out->ac = true;
  if (!iokit_load())
    return false;
  io_object_t it = services("AppleSmartBattery");
  if (!it)
    return true;
  io_object_t e = g.IOIteratorNext(it);
  if (!e) {
    g.IOObjectRelease(it);
    return true;
  }
  int64_t v = 0, mv = 0, cur = 0, max = 0, design = 0, amp = 0;
  if (prop_i64(e, "BatteryInstalled", &v) && v) {
    out->present = true;
    prop_i64(e, "Voltage", &mv);
    if (!prop_i64(e, "AppleRawCurrentCapacity", &cur))
      prop_i64(e, "CurrentCapacity", &cur);
    if (!prop_i64(e, "AppleRawMaxCapacity", &max))
      prop_i64(e, "MaxCapacity", &max);
    prop_i64(e, "DesignCapacity", &design);
    if (!prop_i64(e, "InstantAmperage", &amp))
      prop_i64(e, "Amperage", &amp);
    if (amp < 0)
      amp = -amp;
    if (prop_i64(e, "CycleCount", &v))
      out->cycles = (uint32_t)v;
    if (prop_i64(e, "IsCharging", &v))
      out->charging = v != 0;
    if (prop_i64(e, "ExternalConnected", &v))
      out->ac = v != 0;
    out->discharging = !out->ac;
    out->volt_mv = (uint32_t)mv;
    out->rem_mwh = (uint32_t)(cur * mv / 1000);
    out->max_mwh = (uint32_t)(max * mv / 1000);
    out->design_mwh = (uint32_t)(design * mv / 1000);
    out->rate_mw = (int32_t)(amp * mv / 1000);
    memcpy(out->chem, "LION", 5);
  } else if (prop_i64(e, "ExternalConnected", &v)) {
    out->ac = v != 0;
  }
  g.IOObjectRelease(e);
  g.IOObjectRelease(it);
  return true;
}

// ---------------------------------------------------------------------------
// The platform identity. The expert device names the model and maker,
// the device tree's chosen node carries the firmware version (iBoot on
// Apple silicon) that stands in for a BIOS, and its product node the
// marketing name where the machine has one.

bool pfs_xnu_dmi(struct pfs_dmi *out) {
  static struct pfs_dmi cached;
  static int state;  // 0 untried, 1 have, -1 failed
  if (!state) {
    state = -1;
    if (iokit_load()) {
      io_object_t it = services("IOPlatformExpertDevice");
      io_object_t e = it ? g.IOIteratorNext(it) : 0;
      if (e) {
        memset(&cached, 0, sizeof cached);
        cached.have_sys = true;
        cached.have_board = true;
        cached.have_chassis = true;
        if (!prop_str(e, "manufacturer", cached.sys_vendor,
                      sizeof cached.sys_vendor))
          strcpy(cached.sys_vendor, "Apple Inc.");
        prop_str(e, "model", cached.product_name, sizeof cached.product_name);
        strcpy(cached.board_vendor, cached.sys_vendor);
        if (!prop_str(e, "board-id", cached.board_name,
                      sizeof cached.board_name))
          prop_str(e, "target-type", cached.board_name,
                   sizeof cached.board_name);
        strcpy(cached.chassis_vendor, cached.sys_vendor);
        g.IOObjectRelease(e);
        io_object_t chosen = g.IORegistryEntryFromPath(0, "IODeviceTree:/chosen");
        if (chosen) {
          if (prop_str(chosen, "system-firmware-version", cached.bios_version,
                       sizeof cached.bios_version)) {
            cached.have_bios = true;
            strcpy(cached.bios_vendor, cached.sys_vendor);
          }
          g.IOObjectRelease(chosen);
        }
        io_object_t product = g.IORegistryEntryFromPath(0, "IODeviceTree:/product");
        if (product) {
          prop_str(product, "product-name", cached.product_family,
                   sizeof cached.product_family);
          g.IOObjectRelease(product);
        }
        if (!cached.product_family[0])
          strcpy(cached.product_family, "Mac");
        // a battery makes it a notebook, the SMBIOS types 10 and 3
        struct pfs_batt batt;
        cached.chassis_type =
            pfs_xnu_battery(&batt) && batt.present ? 10 : 3;
        state = 1;
      }
      if (it)
        g.IOObjectRelease(it);
    }
  }
  if (state != 1)
    return false;
  *out = cached;
  return true;
}

#else

void pfs_xnu_diskstats(struct pfs_buf *b) {
  (void)b;
}
void pfs_xnu_partitions(struct pfs_buf *b) {
  pfs_printf(b, "major minor  #blocks  name\n\n");
}
bool pfs_xnu_battery(struct pfs_batt *out) {
  memset(out, 0, sizeof *out);
  return false;
}
bool pfs_xnu_dmi(struct pfs_dmi *out) {
  (void)out;
  return false;
}

#endif

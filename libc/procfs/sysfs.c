#include "libc/procfs/internal.h"

// The emulated slices of /sys: /sys/class/net (the interface counters and
// facts), /sys/class/power_supply (batteries), /sys/devices/system/cpu
// (cpufreq and topology) and /sys/class/dmi/id (the SMBIOS identity, also
// at /sys/devices/virtual/dmi/id where the real files live). Each slice is
// one walk emitting (relative path, content) pairs from host data cached
// for a throttle window; kind, listing and content of any path in a slice
// are all read off the walk. Everything is under pc_lock.

typedef void (*sysfs_emit)(void *ctx, const char *rel, const char *val,
                           size_t n);

static void sysfs_net_walk(sysfs_emit emit, void *ctx) {
  static struct pfs_ifstat ifs[32];
  static int n;
  static int64_t last;
  int64_t t = pfs_now_ms();
  if (!last || t - last >= NET_MS) {
    n = pfs_net_ifstats(ifs, 32);
    last = t;
  }
  char rel[200], val[32];
  for (int i = 0; i < n; i++) {
    struct pfs_ifstat *s = &ifs[i];
    static const char *const names[] = {"rx_bytes",   "tx_bytes",  "rx_packets",
                                        "tx_packets", "rx_errors", "tx_errors",
                                        "rx_dropped", "tx_dropped"};
    const uint64_t vals[] = {s->rx_bytes, s->tx_bytes, s->rx_pkts, s->tx_pkts,
                             s->rx_errs,  s->tx_errs,  s->rx_drop, s->tx_drop};
    for (int k = 0; k < 8; k++) {
      int m = snprintf(val, sizeof val, "%llu\n", (unsigned long long)vals[k]);
      snprintf(rel, sizeof rel, "%.15s/statistics/%s", s->name, names[k]);
      emit(ctx, rel, val, (size_t)m);
    }
    int m = snprintf(val, sizeof val, "%u\n", s->mtu);
    snprintf(rel, sizeof rel, "%.15s/mtu", s->name);
    emit(ctx, rel, val, (size_t)m);
    snprintf(rel, sizeof rel, "%.15s/operstate", s->name);
    emit(ctx, rel, s->up ? "up\n" : "down\n", s->up ? 3 : 5);
    // the interface-facts trio readers reach for next: hardware
    // address (all zeros where there is none, as loopback reads on
    // Linux), carrier, and the negotiated speed in Mb/s (-1 when down
    // or unknown, the kernel's own answer in that state)
    char mac[20];
    m = 0;
    for (int k = 0; k < 6; k++)
      m += snprintf(mac + m, sizeof mac - (size_t)m, "%02x%s",
                    k < (int)s->maclen ? s->mac[k] : 0, k < 5 ? ":" : "\n");
    snprintf(rel, sizeof rel, "%.15s/address", s->name);
    emit(ctx, rel, mac, (size_t)m);
    snprintf(rel, sizeof rel, "%.15s/carrier", s->name);
    emit(ctx, rel, s->up ? "1\n" : "0\n", 2);
    if (s->up && s->speed_mbps)
      m = snprintf(val, sizeof val, "%llu\n",
                   (unsigned long long)s->speed_mbps);
    else
      m = snprintf(val, sizeof val, "-1\n");
    snprintf(rel, sizeof rel, "%.15s/speed", s->name);
    emit(ctx, rel, val, (size_t)m);
  }
}

// /sys/class/power_supply. Battery readers hard-require type, status, the
// energy_* trio, power_now and voltage_now per battery; everything else has
// a fallback. Design capacity, cycle count and chemistry come off the
// battery device itself; when that query has no answer, design falls back
// to full (health then reads 100%). Voltage NT never says, so it is a
// nominal constant that only feeds the display field.
static void sysfs_power_walk(sysfs_emit emit, void *ctx) {
  static struct pfs_batt b;
  static bool have;
  static int64_t last;
  int64_t t = pfs_now_ms();
  if (!last || t - last >= 1000) {
    have = pfs_battery(&b);
    last = t;
  }
  if (!have)
    return;
  char rel[64], buf[64];
  emit(ctx, "ADP0/type", "Mains\n", 6);
  emit(ctx, "ADP0/online", b.ac ? "1\n" : "0\n", 2);
  if (!b.present)
    return;  // a battery that went away takes its files along
  struct {
    const char *name, *sval;
    uint64_t nval;
  } files[] = {
      {"type", "Battery", 0},
      {"present", 0, 1},
      {"status", 0, 0},  // filled below
      {"capacity", 0, b.max_mwh ? b.rem_mwh * 100ull / b.max_mwh : 0},
      {"energy_now", 0, (uint64_t)b.rem_mwh * 1000},
      {"energy_full", 0, (uint64_t)b.max_mwh * 1000},
      {"energy_full_design", 0,
       (uint64_t)(b.design_mwh ? b.design_mwh : b.max_mwh) * 1000},
      {"cycle_count", 0, b.cycles},
      {"power_now", 0, (uint64_t)b.rate_mw * 1000},
      {"voltage_now", 0, 11400000},  // nominal; NT does not say
      {"model_name", "APE Battery", 0},
      {"manufacturer", "cosmopolitan", 0},
      {"technology", 0, 0},  // filled below
  };
  files[2].sval = b.charging               ? "Charging"
                  : b.discharging          ? "Discharging"
                  : b.rem_mwh >= b.max_mwh ? "Full"
                                           : "Unknown";
  size_t itech = sizeof files / sizeof files[0] - 1;
  files[itech].sval = !strncmp(b.chem, "NiCd", 4)   ? "NiCd"
                      : !strncmp(b.chem, "NiMH", 4) ? "NiMH"
                      : !strncmp(b.chem, "LiP", 3)  ? "Li-poly"
                                                    : "Li-ion";
  for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
    int m = files[i].sval ? snprintf(buf, sizeof buf, "%s\n", files[i].sval)
                          : snprintf(buf, sizeof buf, "%llu\n",
                                     (unsigned long long)files[i].nval);
    snprintf(rel, sizeof rel, "BAT0/%s", files[i].name);
    emit(ctx, rel, buf, (size_t)m);
  }
}

// /sys/devices/system/cpu: the online/possible/present range files, and
// where the host says (NT), the cpufreq files sysinfo reads its
// frequencies from plus the topology pair.
static void sysfs_cpu_walk(sysfs_emit emit, void *ctx) {
  static uint32_t cur[64], max[64];
  static uint8_t core[64], pkg[64];
  static int n, topo, ncpu;
  static int64_t last;
  int64_t t = pfs_now_ms();
  if (!last || t - last >= 1000) {
    n = pfs_cpu_mhz(cur, max, 64);
    topo = pfs_cpu_topology(core, pkg, 64);
    ncpu = n;
    if (!ncpu) {
      long v = sysconf(_SC_NPROCESSORS_ONLN);
      ncpu = v > 0 ? (v < 64 ? (int)v : 64) : 1;
    }
    last = t;
  }
  char rel[64], buf[64];
  int m = snprintf(buf, sizeof buf, "0-%d\n", ncpu - 1);
  static const char *const ranges[] = {"online", "possible", "present"};
  for (int i = 0; i < 3; i++)
    emit(ctx, ranges[i], buf, (size_t)m);
  for (int i = 0; i < n; i++) {
    struct {
      const char *name;
      uint32_t mhz;
    } f[] = {
        {"scaling_cur_freq", cur[i]},
        {"scaling_max_freq", max[i]},
        {"cpuinfo_max_freq", max[i]},
        {"scaling_min_freq", 0},  // NT has no floor figure; 0 is honest
        {"cpuinfo_min_freq", 0},
    };
    for (int k = 0; k < 5; k++) {
      m = snprintf(buf, sizeof buf, "%u\n", f[k].mhz * 1000);  // kHz
      snprintf(rel, sizeof rel, "cpu%d/cpufreq/%s", i, f[k].name);
      emit(ctx, rel, buf, (size_t)m);
    }
    struct {
      const char *name;
      int val;
    } tp[] = {
        {"core_id", topo && i < topo ? core[i] : i},
        {"physical_package_id", topo && i < topo ? pkg[i] : 0},
    };
    for (int k = 0; k < 2; k++) {
      m = snprintf(buf, sizeof buf, "%d\n", tp[k].val);
      snprintf(rel, sizeof rel, "cpu%d/topology/%s", i, tp[k].name);
      emit(ctx, rel, buf, (size_t)m);
    }
  }
}

// /sys/class/dmi/id. Fixed for the machine's uptime: read once.
static void sysfs_dmi_walk(sysfs_emit emit, void *ctx) {
  static struct pfs_dmi d;
  static int state;  // 0 untried, 1 have, -1 none
  if (!state)
    state = pfs_dmi(&d) ? 1 : -1;
  if (state < 0)
    return;
  char rel[64], buf[600];
  const struct {
    bool have;
    const char *name;
    const char *val;
  } files[] = {
      {d.have_bios, "bios_vendor", d.bios_vendor},
      {d.have_bios, "bios_version", d.bios_version},
      {d.have_bios, "bios_date", d.bios_date},
      {d.have_sys, "sys_vendor", d.sys_vendor},
      {d.have_sys, "product_name", d.product_name},
      {d.have_sys, "product_version", d.product_version},
      {d.have_sys, "product_sku", d.product_sku},
      {d.have_sys, "product_family", d.product_family},
      {d.have_board, "board_vendor", d.board_vendor},
      {d.have_board, "board_name", d.board_name},
      {d.have_board, "board_version", d.board_version},
      {d.have_board, "board_asset_tag", d.board_asset_tag},
      {d.have_chassis, "chassis_vendor", d.chassis_vendor},
      {d.have_chassis, "chassis_version", d.chassis_version},
  };
  for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
    if (!files[i].have)
      continue;
    int m = snprintf(buf, sizeof buf, "%s\n", files[i].val);
    snprintf(rel, sizeof rel, "id/%s", files[i].name);
    emit(ctx, rel, buf, (size_t)m);
  }
  if (d.have_chassis) {
    int m = snprintf(buf, sizeof buf, "%d\n", d.chassis_type);
    emit(ctx, "id/chassis_type", buf, (size_t)m);
  }
  // modalias: every field strung together the way the kernel spells it,
  // spaces and colons dropped from the values
  const struct {
    const char *tag;
    const char *val;
  } parts[] = {
      {"bvn", d.bios_vendor},     {"bvr", d.bios_version},
      {"bd", d.bios_date},        {"svn", d.sys_vendor},
      {"pn", d.product_name},     {"pvr", d.product_version},
      {"rvn", d.board_vendor},    {"rn", d.board_name},
      {"rvr", d.board_version},   {"cvn", d.chassis_vendor},
      {"cvr", d.chassis_version},
  };
  size_t k = snprintf(buf, sizeof buf, "dmi:");
  for (size_t i = 0; i < sizeof parts / sizeof parts[0]; i++) {
    for (const char *c = parts[i].tag; *c && k < sizeof buf - 3; c++)
      buf[k++] = *c;
    for (const char *c = parts[i].val; *c && k < sizeof buf - 3; c++)
      if (*c != ' ' && *c != ':')
        buf[k++] = *c;
    buf[k++] = ':';
    if (i == 9 && k < sizeof buf - 8)
      k += (size_t)snprintf(buf + k, sizeof buf - k, "ct%d:", d.chassis_type);
  }
  buf[k++] = '\n';
  emit(ctx, "id/modalias", buf, k);
}

static const struct {
  const char *prefix;
  int len;
  void (*walk)(sysfs_emit, void *);
} g_slices[] = {
    {"/sys/class/net", 14, sysfs_net_walk},
    {"/sys/class/power_supply", 23, sysfs_power_walk},
    {"/sys/devices/system/cpu", 23, sysfs_cpu_walk},
    {"/sys/class/dmi", 14, sysfs_dmi_walk},
    {"/sys/devices/virtual/dmi", 24, sysfs_dmi_walk},
};
#define NSLICES (sizeof g_slices / sizeof g_slices[0])

// Whether `path` is a proper ancestor of `prefix` at a component boundary.
static bool ancestor(const char *path, const char *prefix) {
  size_t n = strlen(path);
  return strlen(prefix) > n && !strncmp(path, prefix, n) && prefix[n] == '/';
}

// The slice `path` is the root of or lies under, or -1.
static int slice_of(const char *path) {
  for (size_t i = 0; i < NSLICES; i++) {
    if (strncmp(path, g_slices[i].prefix, g_slices[i].len))
      continue;
    if (path[g_slices[i].len] && path[g_slices[i].len] != '/')
      continue;
    return (int)i;
  }
  return -1;
}

// What a walk says about one relative path: an exact hit is a file, a
// prefix hit a directory.
struct kind_ctx {
  const char *rel;
  size_t len;
  int kind;
};

static void kind_emit(void *vctx, const char *rel, const char *val, size_t n) {
  struct kind_ctx *c = vctx;
  (void)val, (void)n;
  if (c->kind == 0)
    return;
  if (!strcmp(rel, c->rel))
    c->kind = 0;
  else if (!strncmp(rel, c->rel, c->len) && rel[c->len] == '/')
    c->kind = 1;
}

int pc_sysfs_kind(const char *path) {
  if (!strcmp(path, "/sys"))
    return 1;
  int i = slice_of(path);
  if (i < 0) {
    for (size_t k = 0; k < NSLICES; k++)
      if (ancestor(path, g_slices[k].prefix))
        return 1;
    return -1;
  }
  const char *rel = path + g_slices[i].len;
  if (!*rel)
    return 1;
  rel++;
  struct kind_ctx c = {rel, strlen(rel), -1};
  g_slices[i].walk(kind_emit, &c);
  return c.kind;
}

struct pick_ctx {
  const char *rel;
  struct pfs_buf *out;
  bool found;
};

static void pick_emit(void *vctx, const char *rel, const char *val, size_t n) {
  struct pick_ctx *c = vctx;
  if (c->found || strcmp(rel, c->rel))
    return;
  c->found = true;
  pfs_put(c->out, val, n);
}

bool pc_sysfs_gen(const char *path, struct pfs_buf *out) {
  int i = slice_of(path);
  if (i < 0 || path[g_slices[i].len] != '/')
    return false;
  struct pick_ctx c = {path + g_slices[i].len + 1, out, false};
  g_slices[i].walk(pick_emit, &c);
  return c.found;
}

// The entries directly under one relative path of a walk, each once.
struct list_ctx {
  const char *rel;  // "" for the slice root
  size_t len;
  struct pc_list *l;
};

static void list_put(struct pc_list *l, const char *name, size_t n,
                     unsigned char type) {
  if (n >= sizeof l->p[0].name)
    n = sizeof l->p[0].name - 1;
  for (int i = 0; i < l->n; i++)
    if (!strncmp(l->p[i].name, name, n) && !l->p[i].name[n])
      return;
  char buf[32];
  memcpy(buf, name, n);
  buf[n] = 0;
  pc_list_add(l, buf, type);
}

static void list_emit(void *vctx, const char *rel, const char *val, size_t n) {
  struct list_ctx *c = vctx;
  (void)val, (void)n;
  const char *leaf = rel;
  if (c->len) {
    if (strncmp(rel, c->rel, c->len) || rel[c->len] != '/')
      return;
    leaf = rel + c->len + 1;
  }
  const char *slash = strchr(leaf, '/');
  if (slash)
    list_put(c->l, leaf, (size_t)(slash - leaf), DT_DIR);
  else
    list_put(c->l, leaf, strlen(leaf), DT_REG);
}

int pc_sysfs_list(const char *path, struct pc_list *l) {
  int i = slice_of(path);
  if (i < 0) {
    // the directories on the way to the slices
    size_t n = strlen(path);
    bool any = !strcmp(path, "/sys");
    pc_list_add(l, ".", DT_DIR);
    pc_list_add(l, "..", DT_DIR);
    for (size_t k = 0; k < NSLICES; k++) {
      if (!ancestor(path, g_slices[k].prefix))
        continue;
      any = true;
      const char *leaf = g_slices[k].prefix + n + 1;
      const char *slash = strchr(leaf, '/');
      list_put(l, leaf, slash ? (size_t)(slash - leaf) : strlen(leaf), DT_DIR);
    }
    return any ? 0 : -1;
  }
  const char *rel = path + g_slices[i].len;
  if (*rel)
    rel++;
  if (*rel && pc_sysfs_kind(path) != 1)
    return -1;
  pc_list_add(l, ".", DT_DIR);
  pc_list_add(l, "..", DT_DIR);
  struct list_ctx c = {rel, strlen(rel), l};
  g_slices[i].walk(list_emit, &c);
  return 0;
}

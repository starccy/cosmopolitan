#include "ape/sections.internal.h"
#include "libc/dce.h"
#include "libc/dlopen/dlfcn.h"
#include "libc/intrin/atomic.h"
#include "libc/intrin/strace.h"
#include "libc/macros.h"
#include "libc/mem/mem.h"
#include "libc/str/str.h"

extern char __eh_frame_start[] __attribute__((__weak__));
extern char __eh_frame_end[] __attribute__((__weak__));

#define DW_EH_PE_absptr  0x00
#define DW_EH_PE_uleb128 0x01
#define DW_EH_PE_udata2  0x02
#define DW_EH_PE_udata4  0x03
#define DW_EH_PE_udata8  0x04
#define DW_EH_PE_sleb128 0x09
#define DW_EH_PE_sdata2  0x0a
#define DW_EH_PE_sdata4  0x0b
#define DW_EH_PE_sdata8  0x0c
#define DW_EH_PE_pcrel   0x10
#define DW_EH_PE_datarel 0x30
#define DW_EH_PE_indirect 0x80
#define DW_EH_PE_omit    0xff

struct Cie {
  const uint8_t *start;
  uint8_t fde_enc;
  uint8_t lsda_enc;
  bool has_z;
  bool signal;
  uint32_t out;  // where its copy went
};

struct Out {
  uint8_t *p;
  size_t n, cap;
};

static uint64_t read_uleb(const uint8_t **pp) {
  uint64_t r = 0;
  int shift = 0;
  uint8_t b;
  do {
    b = *(*pp)++;
    r |= (uint64_t)(b & 0x7f) << shift;
    shift += 7;
  } while (b & 0x80);
  return r;
}

static int64_t read_sleb(const uint8_t **pp) {
  int64_t r = 0;
  int shift = 0;
  uint8_t b;
  do {
    b = *(*pp)++;
    r |= (int64_t)(b & 0x7f) << shift;
    shift += 7;
  } while (b & 0x80);
  if (shift < 64 && (b & 0x40))
    r |= -((int64_t)1 << shift);
  return r;
}

// reads a pointer in the given encoding, 0 if it isn't one we handle
static bool read_ptr(const uint8_t **pp, uint8_t enc, uint64_t *out) {
  const uint8_t *field = *pp;
  uint64_t v;
  if (enc == DW_EH_PE_omit)
    return false;
  switch (enc & 0x0f) {
    case DW_EH_PE_absptr:
    case DW_EH_PE_udata8:
    case DW_EH_PE_sdata8:
      memcpy(&v, *pp, 8), *pp += 8;
      break;
    case DW_EH_PE_udata4: {
      uint32_t x;
      memcpy(&x, *pp, 4), *pp += 4, v = x;
      break;
    }
    case DW_EH_PE_sdata4: {
      int32_t x;
      memcpy(&x, *pp, 4), *pp += 4, v = (int64_t)x;
      break;
    }
    case DW_EH_PE_udata2: {
      uint16_t x;
      memcpy(&x, *pp, 2), *pp += 2, v = x;
      break;
    }
    case DW_EH_PE_sdata2: {
      int16_t x;
      memcpy(&x, *pp, 2), *pp += 2, v = (int64_t)x;
      break;
    }
    case DW_EH_PE_uleb128:
      v = read_uleb(pp);
      break;
    case DW_EH_PE_sleb128:
      v = read_sleb(pp);
      break;
    default:
      return false;
  }
  switch (enc & 0x70) {
    case 0:
      break;
    case DW_EH_PE_pcrel:
      v += (uintptr_t)field;
      break;
    default:
      return false;
  }
  if (enc & DW_EH_PE_indirect)
    v = *(uint64_t *)v;
  *out = v;
  return true;
}

static bool out_grow(struct Out *o, size_t n) {
  if (o->n + n <= o->cap)
    return true;
  size_t cap = o->cap ? o->cap * 2 : 65536;
  while (cap < o->n + n)
    cap *= 2;
  void *p = realloc(o->p, cap);
  if (!p)
    return false;
  o->p = p;
  o->cap = cap;
  return true;
}

static bool out_bytes(struct Out *o, const void *p, size_t n) {
  if (!out_grow(o, n))
    return false;
  memcpy(o->p + o->n, p, n);
  o->n += n;
  return true;
}

static bool out_u32(struct Out *o, uint32_t x) {
  return out_bytes(o, &x, 4);
}

static bool out_u64(struct Out *o, uint64_t x) {
  return out_bytes(o, &x, 8);
}

static bool out_pad(struct Out *o) {
  static const uint8_t zero[8];
  return out_bytes(o, zero, (8 - o->n % 8) % 8);
}

// copies a CIE with the augmentation cut down to "zR" (plus "S" for a
// signal frame) and absolute pointers for its FDEs
static bool copy_cie(const uint8_t *p, const uint8_t *end, struct Cie *cie,
                     struct Out *o) {
  const uint8_t *body = p + 8;
  uint8_t version = *body++;
  const char *aug = (const char *)body;
  body += strlen(aug) + 1;
  if (version != 1 && version != 3)
    return false;
  if (strchr(aug, 'e'))  // "eh", gcc 2 style
    return false;
  const uint8_t *align = body;
  read_uleb(&body);
  read_sleb(&body);
  const uint8_t *ra = body;
  if (version == 1)
    body++;
  else
    read_uleb(&body);
  cie->has_z = aug[0] == 'z';
  cie->fde_enc = DW_EH_PE_absptr;
  cie->lsda_enc = DW_EH_PE_omit;
  cie->signal = false;
  if (cie->has_z) {
    uint64_t len = read_uleb(&body);
    const uint8_t *aug_end = body + len;
    for (const char *a = aug + 1; *a; ++a) {
      uint64_t skip;
      switch (*a) {
        case 'L':
          cie->lsda_enc = *body++;
          break;
        case 'R':
          cie->fde_enc = *body++;
          break;
        case 'P': {
          uint8_t enc = *body++;
          if (!read_ptr(&body, enc, &skip))
            return false;
          break;
        }
        case 'S':
          cie->signal = true;
          break;
        case 'B':
          break;
        default:
          return false;
      }
    }
    body = aug_end;
  }
  const uint8_t *insns = body;
  size_t insns_len = end - insns;
  cie->out = o->n;
  size_t start = o->n;
  if (!out_u32(o, 0) || !out_u32(o, 0))
    return false;
  uint8_t v1 = 1;
  if (!out_bytes(o, &v1, 1))
    return false;
  const char *newaug = cie->signal ? "zRS" : "zR";
  if (!out_bytes(o, newaug, strlen(newaug) + 1))
    return false;
  if (!out_bytes(o, align, ra - align))
    return false;
  if (version == 1) {
    if (!out_bytes(o, ra, 1))
      return false;
  } else {
    // the return register as one byte, since the copy is version 1
    const uint8_t *r = ra;
    uint64_t reg = read_uleb(&r);
    uint8_t b = reg;
    if (reg > 127 || !out_bytes(o, &b, 1))
      return false;
  }
  uint8_t augdata[2] = {1, DW_EH_PE_absptr};
  if (!out_bytes(o, augdata, 2))
    return false;
  if (!out_bytes(o, insns, insns_len) || !out_pad(o))
    return false;
  uint32_t len = o->n - start - 4;
  memcpy(o->p + start, &len, 4);
  return true;
}

static bool copy_fde(const uint8_t *p, const uint8_t *end,
                     const struct Cie *cie, struct Out *o) {
  const uint8_t *body = p + 8;
  uint64_t pc_begin, pc_range;
  if (!read_ptr(&body, cie->fde_enc, &pc_begin))
    return false;
  if (!read_ptr(&body, cie->fde_enc & 0x0f, &pc_range))
    return false;
  if (cie->has_z) {
    uint64_t len = read_uleb(&body);
    body += len;
  }
  // the instructions are copied as they are; compilers don't put
  // DW_CFA_set_loc, the one with an address in it, in .eh_frame
  const uint8_t *insns = body;
  size_t start = o->n;
  if (!out_u32(o, 0))
    return false;
  if (!out_u32(o, (uint32_t)(o->n - cie->out)))
    return false;
  if (!out_u64(o, pc_begin) || !out_u64(o, pc_range))
    return false;
  uint8_t zero = 0;
  if (!out_bytes(o, &zero, 1))
    return false;
  if (!out_bytes(o, insns, end - insns) || !out_pad(o))
    return false;
  uint32_t len = o->n - start - 4;
  memcpy(o->p + start, &len, 4);
  return true;
}

// the copy, made once
static _Atomic(uint8_t *) host_frames;
static size_t host_frames_size;

static uint8_t *host_frames_make(void) {
  uint8_t *had = 0, *res;
  if ((res = atomic_load_explicit(&host_frames, memory_order_acquire)))
    return res;
  struct Out o = {0};
  struct Cie cies[64];
  size_t ncie = 0;
  const uint8_t *p = (const uint8_t *)__eh_frame_start;
  const uint8_t *end = (const uint8_t *)__eh_frame_end;
  while (p + 4 <= end) {
    uint32_t len;
    memcpy(&len, p, 4);
    if (!len)
      break;
    if (len == 0xffffffff || p + 4 + len > end)
      break;
    const uint8_t *next = p + 4 + len;
    uint32_t id;
    memcpy(&id, p + 4, 4);
    if (!id) {
      if (ncie < ARRAYLEN(cies)) {
        cies[ncie].start = p;
        if (copy_cie(p, next, cies + ncie, &o))
          ++ncie;
      }
    } else {
      const uint8_t *cie_start = p + 4 - id;
      for (size_t i = 0; i < ncie; ++i)
        if (cies[i].start == cie_start) {
          copy_fde(p, next, cies + i, &o);
          break;
        }
    }
    p = next;
  }
  if (!out_u32(&o, 0)) {
    free(o.p);
    return 0;
  }
  if (!atomic_compare_exchange_strong_explicit(&host_frames, &had, o.p,
                                               memory_order_acq_rel,
                                               memory_order_acquire)) {
    free(o.p);
    return had;
  }
  host_frames_size = o.n;
  return o.p;
}

/**
 * Registers this program's frames with the host's unwinder.
 *
 * `find` looks a symbol up in a host library that's already loaded.
 * Nothing happens until a host unwinder is, so this is called again
 * after each library loads.
 */
void __host_frames_register(void *(*find)(const char *, const char *)) {
  static _Atomic(bool) done;
  if (atomic_load_explicit(&done, memory_order_acquire))
    return;
  if (!__eh_frame_start || (char *)__eh_frame_end == (char *)__eh_frame_start)
    return;
  void (*register_frame)(const void *) = 0;
  if (IsXnu()) {
    register_frame = find(0, "__register_frame");
  } else {
    register_frame = find("libgcc_s.so.1", "__register_frame");
    if (!register_frame)
      register_frame = find("libunwind.so.1", "__register_frame");
  }
  if (!register_frame)
    return;
  if (atomic_exchange_explicit(&done, true, memory_order_acq_rel))
    return;
  uint8_t *frames = host_frames_make();
  if (!frames)
    return;
  if (IsXnu()) {
    // apple's takes one FDE at a time
    const uint8_t *p = frames, *end = frames + host_frames_size;
    while (p + 4 <= end) {
      uint32_t len, id;
      memcpy(&len, p, 4);
      if (!len)
        break;
      memcpy(&id, p + 4, 4);
      if (id)
        register_frame(p);
      p += 4 + len;
    }
  } else {
    register_frame(frames);
  }
  STRACE("registered %zu bytes of frames with the host unwinder",
         host_frames_size);

}

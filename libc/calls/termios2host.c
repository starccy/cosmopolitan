/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include "libc/calls/struct/metatermios.internal.h"
#include "libc/calls/termios.internal.h"
#include "libc/dce.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/baud.internal.h"
#include "libc/sysv/consts/host.internal.h"
#include "libc/sysv/consts/termios.h"

/*
 * struct termios is Linux's on the outside. The BSDs keep the same
 * fields with their own bit positions, c_cc indices and a wider layout
 * on XNU, so tcgetattr() and tcsetattr() convert through here.
 */

#define DECL(NAME) extern const uint32_t __host_##NAME __asm__(#NAME);

#define IFLAGS(X)                                                        \
  X(IGNBRK) X(BRKINT) X(IGNPAR) X(PARMRK) X(INPCK) X(ISTRIP) X(INLCR)  \
  X(IGNCR) X(ICRNL) X(IUCLC) X(IXON) X(IXANY) X(IXOFF) X(IMAXBEL)      \
  X(IUTF8)
#define OFLAGS(X) \
  X(OPOST) X(OLCUC) X(ONLCR) X(OCRNL) X(ONOCR) X(ONLRET) X(OFILL) X(OFDEL)
#define CFLAGS(X) \
  X(CSTOPB) X(CREAD) X(PARENB) X(PARODD) X(HUPCL) X(CLOCAL) X(CRTSCTS) X(CMSPAR)
#define LFLAGS(X)                                                       \
  X(ISIG) X(ICANON) X(XCASE) X(ECHO) X(ECHOE) X(ECHOK) X(ECHONL)      \
  X(NOFLSH) X(TOSTOP) X(ECHOCTL) X(ECHOPRT) X(ECHOKE) X(FLUSHO)       \
  X(PENDIN) X(IEXTEN) X(EXTPROC)
#define ODLYS(X)                                                        \
  X(NLDLY) X(NL1) X(CRDLY) X(CR1) X(CR2) X(CR3) X(TABDLY) X(TAB1)      \
  X(TAB2) X(TAB3) X(BSDLY) X(BS1) X(VTDLY) X(VT1) X(FFDLY) X(FF1)
#define CCS(X)                                                          \
  X(VINTR) X(VQUIT) X(VERASE) X(VKILL) X(VEOF) X(VTIME) X(VMIN)        \
  X(VSWTC) X(VSTART) X(VSTOP) X(VSUSP) X(VEOL) X(VREPRINT) X(VDISCARD) \
  X(VWERASE) X(VLNEXT) X(VEOL2)

IFLAGS(DECL)
OFLAGS(DECL)
CFLAGS(DECL)
LFLAGS(DECL)
ODLYS(DECL)
CCS(DECL)
DECL(CSIZE)
DECL(CS6)
DECL(CS7)
DECL(CS8)
DECL(_POSIX_VDISABLE)

struct Bit {
  uint32_t linux;
  const uint32_t *host;
};

#define ENTRY(NAME) {NAME, &__host_##NAME},
static const struct Bit kIflags[] = {IFLAGS(ENTRY)};
static const struct Bit kOflags[] = {OFLAGS(ENTRY)};
static const struct Bit kCflags[] = {CFLAGS(ENTRY)};
static const struct Bit kLflags[] = {LFLAGS(ENTRY)};
static const struct Bit kCcs[] = {CCS(ENTRY)};

#define ARRAY(A) A, sizeof(A) / sizeof(*A)

static uint32_t bits2host(const struct Bit *t, int n, uint32_t linux) {
  uint32_t host = 0;
  for (int i = 0; i < n; ++i)
    if (linux & t[i].linux)
      host |= *t[i].host;
  return host;
}

static uint32_t bits2linux(const struct Bit *t, int n, uint32_t host) {
  uint32_t linux = 0;
  for (int i = 0; i < n; ++i)
    if (*t[i].host && (host & *t[i].host) == *t[i].host)
      linux |= t[i].linux;
  return linux;
}

// CSIZE and the output delays are fields with enumerated values, not
// bits, so they're matched whole.

static uint32_t csize2host(uint32_t linux) {
  switch (linux & CSIZE) {
    case CS6:
      return __host_CS6;
    case CS7:
      return __host_CS7;
    case CS8:
      return __host_CS8;
    default:
      return 0;
  }
}

static uint32_t csize2linux(uint32_t host) {
  uint32_t f = host & __host_CSIZE;
  if (__host_CS8 && f == __host_CS8)
    return CS8;
  if (__host_CS7 && f == __host_CS7)
    return CS7;
  if (__host_CS6 && f == __host_CS6)
    return CS6;
  return CS5;
}

static const struct {
  uint32_t mask, value;
  const uint32_t *hmask, *hvalue;
} kDelays[] = {
    {NLDLY, NL1, &__host_NLDLY, &__host_NL1},      //
    {CRDLY, CR1, &__host_CRDLY, &__host_CR1},      //
    {CRDLY, CR2, &__host_CRDLY, &__host_CR2},      //
    {CRDLY, CR3, &__host_CRDLY, &__host_CR3},      //
    {TABDLY, TAB1, &__host_TABDLY, &__host_TAB1},  //
    {TABDLY, TAB2, &__host_TABDLY, &__host_TAB2},  //
    {TABDLY, TAB3, &__host_TABDLY, &__host_TAB3},  //
    {BSDLY, BS1, &__host_BSDLY, &__host_BS1},      //
    {VTDLY, VT1, &__host_VTDLY, &__host_VT1},      //
    {FFDLY, FF1, &__host_FFDLY, &__host_FF1},      //
};

#define ODLY_MASK (NLDLY | CRDLY | TABDLY | BSDLY | VTDLY | FFDLY)

static uint32_t odly2host(uint32_t linux) {
  uint32_t host = 0;
  for (int i = 0; i < sizeof(kDelays) / sizeof(*kDelays); ++i)
    if (*kDelays[i].hmask && (linux & kDelays[i].mask) == kDelays[i].value)
      host |= *kDelays[i].hvalue;
  return host;
}

static uint32_t odly2linux(uint32_t host) {
  uint32_t linux = 0;
  for (int i = 0; i < sizeof(kDelays) / sizeof(*kDelays); ++i)
    if (*kDelays[i].hmask && *kDelays[i].hvalue &&
        (host & *kDelays[i].hmask) == *kDelays[i].hvalue)
      linux |= kDelays[i].value;
  return linux;
}

static const struct {
  uint32_t code, rate;
} kBauds[] = {
    {B0, 0},              {B50, 50},           {B75, 75},
    {B110, 110},          {B134, 134},         {B150, 150},
    {B200, 200},          {B300, 300},         {B600, 600},
    {B1200, 1200},        {B1800, 1800},       {B2400, 2400},
    {B4800, 4800},        {B9600, 9600},       {B19200, 19200},
    {B38400, 38400},      {B57600, 57600},     {B115200, 115200},
    {B230400, 230400},    {B460800, 460800},   {B500000, 500000},
    {B576000, 576000},    {B921600, 921600},   {B1000000, 1000000},
    {B1152000, 1152000},  {B1500000, 1500000}, {B2000000, 2000000},
    {B2500000, 2500000},  {B3000000, 3000000}, {B3500000, 3500000},
    {B4000000, 4000000},
};

/**
 * Turns a B* code into bits per second, or 0 if it isn't one.
 */
uint32_t __baud2rate(uint32_t code) {
  for (int i = 0; i < sizeof(kBauds) / sizeof(*kBauds); ++i)
    if (kBauds[i].code == code)
      return kBauds[i].rate;
  return 0;
}

/**
 * Turns bits per second into its B* code, or BOTHER if there isn't one.
 */
uint32_t __rate2baud(uint32_t rate) {
  for (int i = 0; i < sizeof(kBauds) / sizeof(*kBauds); ++i)
    if (kBauds[i].rate == rate)
      return kBauds[i].code;
  return BOTHER;
}

static bool cc_is_count(uint32_t linux) {
  return linux == VMIN || linux == VTIME;
}

static void termios2bsd(struct termios_bsd *b, const struct termios *lt) {
  bzero(b, sizeof(*b));
  b->c_iflag = bits2host(ARRAY(kIflags), lt->c_iflag);
  b->c_oflag = bits2host(ARRAY(kOflags), lt->c_oflag & ~ODLY_MASK) |
               odly2host(lt->c_oflag);
  b->c_cflag = bits2host(ARRAY(kCflags), lt->c_cflag & ~(CSIZE | CBAUD)) |
               csize2host(lt->c_cflag);
  b->c_lflag = bits2host(ARRAY(kLflags), lt->c_lflag);
  memset(b->c_cc, __host__POSIX_VDISABLE, sizeof(b->c_cc));
  for (int i = 0; i < sizeof(kCcs) / sizeof(*kCcs); ++i) {
    uint8_t c = lt->c_cc[kCcs[i].linux];
    if (!c && !cc_is_count(kCcs[i].linux))
      c = __host__POSIX_VDISABLE;
    if (*kCcs[i].host < sizeof(b->c_cc))
      b->c_cc[*kCcs[i].host] = c;
  }
  uint32_t code = lt->c_cflag & CBAUD;
  uint32_t rate = code == BOTHER ? lt->_c_ospeed : __baud2rate(code);
  // a null speed makes bsd hang up the terminal
  if (!rate)
    rate = 9600;
  b->_c_ispeed = rate;
  b->_c_ospeed = rate;
}

static void bsd2termios(struct termios *lt, const struct termios_bsd *b) {
  bzero(lt, sizeof(*lt));
  lt->c_iflag = bits2linux(ARRAY(kIflags), b->c_iflag);
  lt->c_oflag = bits2linux(ARRAY(kOflags), b->c_oflag) | odly2linux(b->c_oflag);
  lt->c_cflag = bits2linux(ARRAY(kCflags), b->c_cflag) | csize2linux(b->c_cflag);
  lt->c_lflag = bits2linux(ARRAY(kLflags), b->c_lflag);
  for (int i = 0; i < sizeof(kCcs) / sizeof(*kCcs); ++i) {
    if (*kCcs[i].host >= sizeof(b->c_cc))
      continue;
    uint8_t c = b->c_cc[*kCcs[i].host];
    if (c == __host__POSIX_VDISABLE && !cc_is_count(kCcs[i].linux))
      c = 0;
    lt->c_cc[kCcs[i].linux] = c;
  }
  lt->c_cflag |= __rate2baud(b->_c_ospeed);
  lt->_c_ispeed = b->_c_ispeed;
  lt->_c_ospeed = b->_c_ospeed;
}

/**
 * Converts termios into what the host kernel takes.
 *
 * @return pointer to hand the kernel, which is `lt` itself on Linux
 */
void *__termios2host(union metatermios *mt, const struct termios *lt) {
  if (!IsBsd())
    return (/*unconst*/ void *)lt;
  if (IsXnu()) {
    struct termios_bsd b;
    termios2bsd(&b, lt);
    mt->xnu.c_iflag = b.c_iflag;
    mt->xnu.c_oflag = b.c_oflag;
    mt->xnu.c_cflag = b.c_cflag;
    mt->xnu.c_lflag = b.c_lflag;
    memcpy(mt->xnu.c_cc, b.c_cc, sizeof(b.c_cc));
    mt->xnu._c_ispeed = b._c_ispeed;
    mt->xnu._c_ospeed = b._c_ospeed;
    return &mt->xnu;
  }
  termios2bsd(&mt->bsd, lt);
  return &mt->bsd;
}

/**
 * Converts what a BSD kernel returned into termios.
 */
void __termios2linux(struct termios *lt, const union metatermios *mt) {
  if (IsXnu()) {
    struct termios_bsd b;
    b.c_iflag = mt->xnu.c_iflag;
    b.c_oflag = mt->xnu.c_oflag;
    b.c_cflag = mt->xnu.c_cflag;
    b.c_lflag = mt->xnu.c_lflag;
    memcpy(b.c_cc, mt->xnu.c_cc, sizeof(b.c_cc));
    b._c_ispeed = mt->xnu._c_ispeed;
    b._c_ospeed = mt->xnu._c_ospeed;
    bsd2termios(lt, &b);
  } else {
    bsd2termios(lt, &mt->bsd);
  }
}

#include "libc/dce.h"
#include "libc/mem/mem.h"
#include "libc/nt/dll.h"
#include "libc/nt/thunk/msabi.h"
#include "libc/procfs/internal.h"

// /etc/ssl/certs/ca-certificates.crt on windows: the trusted roots of
// the system certificate store as a PEM bundle, which is where a program
// built for linux looks for them. crypt32 is loaded on first use, not
// imported, so programs that never ask pay nothing. A bundle that maps
// this path stats it from a priority 10 constructor, before the ifunc
// slots are filled and before malloc works, so the size is answered by
// a pass over the store that writes nothing, and nothing here calls the
// str* family.

#ifdef __x86_64__
struct NtCertContext {
  uint32_t dwCertEncodingType;
  unsigned char *pbCertEncoded;
  uint32_t cbCertEncoded;
  void *pCertInfo;
  int64_t hCertStore;
};

#define kNtX509AsnEncoding 1

static const char kBase64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// bytes a PEM block for n DER bytes takes: 4 chars per 3 bytes, a
// newline per 64 chars, and the two armour lines
static size_t PemSize(size_t n) {
  size_t b64 = (n + 2) / 3 * 4;
  return 28 + b64 + (b64 + 63) / 64 + 26;
}

static char *Put(char *p, const char *s) {
  while ((*p = *s++))
    ++p;
  return p;
}

static char *PemAppend(char *p, const unsigned char *der, size_t n) {
  size_t col = 0;
  p = Put(p, "-----BEGIN CERTIFICATE-----\n");
  for (size_t i = 0; i < n; i += 3) {
    unsigned v = der[i] << 16;
    if (i + 1 < n)
      v |= der[i + 1] << 8;
    if (i + 2 < n)
      v |= der[i + 2];
    *p++ = kBase64[v >> 18 & 63];
    *p++ = kBase64[v >> 12 & 63];
    *p++ = i + 1 < n ? kBase64[v >> 6 & 63] : '=';
    *p++ = i + 2 < n ? kBase64[v & 63] : '=';
    if ((col += 4) == 64) {
      *p++ = '\n';
      col = 0;
    }
  }
  if (col)
    *p++ = '\n';
  return Put(p, "-----END CERTIFICATE-----\n");
}

static int64_t __msabi (*OpenStore)(uint64_t, const char16_t *);
static const struct NtCertContext *__msabi (*NextCert)(
    int64_t, const struct NtCertContext *);
static bool32 __msabi (*CloseStore)(int64_t, uint32_t);

static bool LoadCrypt32(void) {
  if (OpenStore)
    return true;
  int64_t crypt32 = LoadLibrary(u"crypt32.dll");
  if (!crypt32)
    return false;
  NextCert = (void *)GetProcAddress(crypt32, "CertEnumCertificatesInStore");
  CloseStore = (void *)GetProcAddress(crypt32, "CertCloseStore");
  if (!NextCert || !CloseStore)
    return false;
  OpenStore = (void *)GetProcAddress(crypt32, "CertOpenSystemStoreW");
  return !!OpenStore;
}

// walks the ROOT store (current user and local machine merged) and
// returns the PEM length, writing the text when out is given; -1 when
// crypt32 or the store cannot be opened
static ssize_t Walk(char *out) {
  if (!LoadCrypt32())
    return -1;
  int64_t store = OpenStore(0, u"ROOT");
  if (!store)
    return -1;
  size_t len = 0;
  for (const struct NtCertContext *c = 0; (c = NextCert(store, c));) {
    if (!(c->dwCertEncodingType & kNtX509AsnEncoding))
      continue;
    if (out)
      PemAppend(out + len, c->pbCertEncoded, c->cbCertEncoded);
    len += PemSize(c->cbCertEncoded);
  }
  CloseStore(store, 0);
  return len;
}
#endif

ssize_t __nt_ca_bundle_size(void) {
#ifdef __x86_64__
  return Walk(0);
#else
  return -1;
#endif
}

char *__nt_ca_bundle(size_t *n) {
#ifdef __x86_64__
  ssize_t len;
  char *s;
  if ((len = Walk(0)) < 0 || !(s = malloc(len + 1)))
    return 0;
  if (Walk(s) != len) {
    free(s);
    return 0;
  }
  s[len] = 0;
  *n = len;
  return s;
#else
  return 0;
#endif
}

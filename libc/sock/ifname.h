#ifndef COSMOPOLITAN_LIBC_SOCK_IFNAME_H_
#define COSMOPOLITAN_LIBC_SOCK_IFNAME_H_
COSMOPOLITAN_C_START_

struct if_nameindex {
  unsigned if_index;
  char *if_name;
};

unsigned if_nametoindex(const char *) libcesque;
char *if_indextoname(unsigned, char *) libcesque;
struct if_nameindex *if_nameindex(void) libcesque;
void if_freenameindex(struct if_nameindex *) libcesque;

COSMOPOLITAN_C_END_
#endif /* COSMOPOLITAN_LIBC_SOCK_IFNAME_H_ */

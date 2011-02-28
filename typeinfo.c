#include <sys/uio.h>
#include <string.h>
#include <inttypes.h>
#include "str/fmt.h"

int size_of(char *type, size_t size)
{
  struct iovec iov[4];
  char padding[] = "             : ";
  char sz[FMT_ULONG];
  iov[0].iov_base = type;
  iov[0].iov_len = strlen(type);
  iov[1].iov_base = &padding[iov[0].iov_len];
  iov[1].iov_len = sizeof(padding) - iov[0].iov_len;
  iov[2].iov_base = sz;
  iov[2].iov_len = fmt_ulong(sz, size);
  iov[3].iov_base = "\n";
  iov[3].iov_len = 1;
  writev(1, iov, 4);
}

#define SIZE(a) size_of(#a, sizeof(a))

int main()
{
  SIZE(char);
  SIZE(char *);
  SIZE(int);
  SIZE(size_t);
  SIZE(long);
  SIZE(long long);
  SIZE(uint32_t);
  SIZE(float);
  SIZE(double);
  SIZE(uid_t);
  SIZE(gid_t);
  SIZE(off_t);
  return 0;
}

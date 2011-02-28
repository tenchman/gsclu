/* $Id: fmt_ulong.c 58 2007-10-28 22:16:11Z gernot $ */

/* Public domain. */

#include "fmt.h"

size_t fmt_ulong(register char *s, register unsigned long u)
{
  register unsigned int len;
  register unsigned long q;
  len = 1;
  q = u;
  while (q > 9) {
    ++len;
    q /= 10;
  }
  if (s) {
    s += len;
    do {
      *--s = '0' + (u % 10);
      u /= 10;
    } while (u);		/* handles u == 0 */
  }
  return len;
}

#include <stdlib.h>
#include <string.h>
#include "str.h"

char *str_ndup(const char *s, const int n)
{
  register char *tmp = (char *) malloc(n + 1);
  if (tmp) {
    memcpy(tmp, s, n);
    tmp[n] = '\0';
  }
  return tmp;
}

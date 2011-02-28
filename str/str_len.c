#include "str.h"

size_t str_len(const char *s)
{
  register const char *t;

  t = s;
  for (;;) {
    if (!*t)
      return t - s;
    ++t;
  }
}

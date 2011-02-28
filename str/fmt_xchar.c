/* $Id: fmt_xchar.c 11 2005-11-02 21:20:52Z gernot $ */

#include "fmt.h"

const char digits[16] = "0123456789abcdef";

unsigned int fmt_xchar(char *s, unsigned char c)
{
  s[0] = digits[(c >> 4) & 0xf];
  s[1] = digits[c & 0xf];
  return 2;
}

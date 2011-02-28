#include <string.h>
#include <ctype.h>
#include "read_write.h"
#include "attributes.h"

REGPARM(2)
int readulonglong(char *s, unsigned long long *u)
{
  register unsigned int pos = 0;
  unsigned long long result = 0;
  unsigned long long c;
  while (s[pos] == ' ' || s[pos] == '\n' || s[pos] == '\t')
    ++pos;
  while ((c = (unsigned long long) (unsigned char) (s[pos] - '0')) < 10) {
    result = result * 10 + c;
    ++pos;
  }
  *u = result;
  return pos;
}

REGPARM(2)
int readulong(char *s, unsigned long *u)
{
  unsigned long long ull;
  int pos = readulonglong(s, &ull);
  *u = (unsigned long) ull;
  return pos;
}

REGPARM(2)
int readlong(char *s, long *l)
{
  unsigned long long ull;
  int negative = 0, pos;
  char *tmp = s;
  while (*tmp == ' ')
    ++tmp;
  if (*tmp == '-') {
    negative = 1;
    ++tmp;
  }
  pos = readulonglong(tmp, &ull);
  if (negative)
    *l = -(long) ull;
  else
    *l = (long) ull;
  return pos + tmp - s;
}

REGPARM(2)
int readint(char *s, int *i)
{
  long l;
  int pos = readlong(s, &l);
  *i = (int) l;
  return pos;
}

REGPARM(2)
int readchar(char *s, char *c)
{
  char *pos = s;
  while (*pos == ' ')
    ++pos;
  *c = *pos++;
  return pos - s;
}

REGPARM(3)
static int readprocstring(char *s, char **str, int isname)
{
  char *pos = s;
  char *start;

  while (isspace(*pos))
    ++pos;
  start = pos;
  if (isname && *pos == '(') {
    *start = '[';
    while (*pos != ')')
      ++pos;
    *pos++ = ']';
  } else {
    while (!isspace(*pos))
      ++pos;
  }
  if (str) {
    memcpy(*str, start, pos - start);
    (*str)[pos - start] = '\0';
  }
  return pos - s;
}

REGPARM(2)
int readprocname(char *s, char **str)
{
  return readprocstring(s, str, 1);
}

REGPARM(2)
int readstring(char *s, char **str)
{
  return readprocstring(s, str, 0);
}


REGPARM(2)
int skip(char *s, int n)
{
  char *pos = s;
  while (n) {
    while (isspace(*pos))
      ++pos;
    while (!isspace(*pos))
      ++pos;
    --n;
  }
  return pos - s;
}

REGPARM(3)
int writeulonglong(register char *s, char *end, unsigned long long u, int width,
		   int align)
{
  register unsigned int len;
  unsigned long long q;
  int retval;

  len = 1;
  q = u;
  while (q > 9) {
    ++len;
    q /= 10;
  }
  if (len > width)
    width = len;		/* never cut */
  retval = width;
  if (s) {
    s += width;
    if (align == LEFT) {
      while (width > len) {
	*--s = ' ';
	--width;
      }
    }
    do {
      *--s = '0' + (u % 10);
      u /= 10;
    } while (u);		/* handles u == 0 */
    if (align == RIGHT) {
      width -= len;
      while (width--)
	*--s = ' ';
    }
  }
  return retval;
}

REGPARM(3)
int writelonglong(register char *s, char *end, long long l, int width,
		  int align)
{
  register unsigned int len = 0;
  if (l < 0LL) {
    *s++ = '-';
    ++len;
    l = -l;
  }
  return len + writeulonglong(s, end, (unsigned long long) l, width, align);
}

/* write a string of at least but not more than 'width' characters
 * If width == 0 write the whole string, as long as it fits into the
 * buffer.
 */
REGPARM(3)
int writestring(char *s, char *end, char *str, int width)
{
  int len = strlen(str);
  int pad = len > width ? 0 : width - len;
  while (s < end) {
    if (!(*s = *str))
      break;
    ++s;
    ++str;
  }
  while (pad) {
    *s++ = ' ';
    --pad;
  }
  return width ? width : len;
}

#include "str.h"

/*! \brief find a linebreak in a string
 *
 * Find and return the end of a line. If endptr is not NULL, endofline()
 * stores the address of the first character after the linebreak in
 * *endptr.
 *
 * @param line - the line to inspect
 * @param endptr - an optional pointer to return the first character after
 *  the linebreak to
 *
 * @return A pointer to the first linebreak found, NULL otherwise.
**/
char *str_endofline(const char *line, char **endptr)
{
  char *tmp = (char *) line;
  int c, incr = 0;

  while ((c = *tmp)) {
    if (c == '\n' || c == '\r') {
      if ((tmp[1] == '\n' || tmp[1] == '\r') && tmp[1] != c)
	incr = 2;
      else
	incr = 1;
      break;
    }
    tmp++;
  }

  if (endptr)
    *endptr = tmp + incr;

  return incr ? tmp : (char *) 0;
}

#include "str.h"

/*! \brief search for a linebreak in a string
 *
 * The function str_eof() searches for a linebreak in the given string
 * \p line. It returns the number of bytes before the linebreak was found
 * and optional in \p len the length of the linebreak. Different linebreak
 * styles are supported.
 *
 *   unix linebreaks: '\n'
 *   dos linebreaks: '\r\n'
 *   mac linebreaks: '\r'
 *
 * @param line - the string in question
 * @param len - an integer to return the length of the linebreak to
 *
 * @return the number of bytes before the linebreak or the length of line if
 *  no linebreak was found.
**/
size_t str_eol(const char *line, size_t * len)
{
  char *tmp = (char *) line;
  int c;
  size_t incr = 0;
  while ((c = *tmp)) {
    if (c == '\n' || c == '\r') {
      if ((tmp[1] == '\n' || tmp[1] == '\r') && tmp[1] != c)
	incr = 2;
      else
	incr = 1;
      break;
    }
    ++tmp;
  }
  if (len)
    *len = incr;
  return tmp - line;
}

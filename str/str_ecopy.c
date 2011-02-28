/* $Id: str_ecopy.c 342 2005-09-22 22:09:43Z gernot $ */
#include "str.h"

/*! \brief safe string copy
 *
 * The  str_ecopy() function copies the string pointed to by \a src
 * (including the terminating '\\0' character) to the array pointed to by
 * \a dst. If the source string exceeds the bounds defined by \a dst and
 * \a end (i.e. (end - dst) characters) the resulting string will be cutted.
 *
 * Note: In difference to other similar functions the resulting string will
 *   allways be null-terminated.
 *
 * @note: This function prevents you from overwriting the bounds of your
 *  buffer (if properly defined). It does no error reporting.
 * 
 * @param dst - a pointer to the destination buffer
 * @param end - a pointer to the end of the destination buffer
 * @param src - the string to copy
 *
 * @return The number of bytes copied.
**/
size_t str_ecopy(char *dst, const char *end, const char *src)
{
  register char *s = dst;
  register const char *t = src;

  if (!(dst && end))
    return 0;
  if (end <= dst)
    return 0;

  while (s < end) {
    if (!(*s = *t))
      break;
    ++s;
    ++t;
  }
  *s = '\0';
  return s - dst;
}

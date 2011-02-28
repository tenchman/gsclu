/* $Id: fmt_long.c 58 2007-10-28 22:16:11Z gernot $ */

/* \file fmt_long
 * \author djb
 * \see http://cr.yp.to/
**/

#include "fmt.h"

/*! \brief convert a long integer into its ASCII representation
 *
 * The function fmt_long() writes an ASCII representation ("-" and "0" to "9",
 * base 10) of \a n to \a dest and returns the number of bytes written.
 *
 * For convenience, lstr.h defines the constant FMT_ULONG to be big enough to
 * contain every possible fmt_long() output plus the final '\\0'.
 *
 * If \a dest equals NULL, fmt_long() returns the number of bytes it would
 * have written.
 * 
 * to get a '\\0' terminated string use the following code:
 * \code
 * char buf[FMT_ULONG];
 *
 * buf[fmt_ulong(buf, 123456)] = '\0';
 * \endcode
 *
 * @note fmt_long() does not append the final '\\0'.
 *
 * @param dest - the buffer to write to
 * @param n - the long integer to convert
 *
 * @return The number of bytes written.
 *
**/
size_t fmt_long(char *dest, long n)
{
  if (n >= 0)
    return fmt_ulong(dest, n);
  *dest++ = '-';
  return 1 + fmt_ulong(dest, -n);
}

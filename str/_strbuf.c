/* $Id: _strbuf.c 58 2007-10-28 22:16:11Z gernot $ */

/*!
 * \file strbuf.c
 * \author Gernot Tenchio <gernot@tenchio.de>
 * \brief save string functions
**/

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "strbuf.h"
#include "str.h"
#include "fmt.h"

#define write2(s) write(2, s, strlen(s))

/*! \brief enlarge a string buffer
 *
 * Enlarge the string buffer \p strbuf to hold at least \p len additional
 * charcters.
 *
 * @param strbuf - the buffer to enlarge
 * @param len - the number of additional characters to hold
 *
 * @return 0 on success, STRBUF_ERROR otherwise.
**/
#ifdef P_strbuf_realloc
size_t strbuf_realloc(strbuf_t * strbuf, size_t len)
{
  unsigned int l;
  if (strbuf->s)
    l = (strbuf->len + len) | STRBUF_BOUNDS;
  else
    l = len | STRBUF_BOUNDS;
  char *tmp = realloc(strbuf->s, l);
  if (tmp) {
    strbuf->s = tmp;
    strbuf->total = l;
    return 0;
  }
  return STRBUF_ERROR;
}
#endif

/*! \brief check whether the buffer is large enough to hold \a len characters
 *
 * Check whether the buffer \p strbuf is large enough to hold \p len
 * characters. If not, try to allocate the required memory.
 * 
 * @param strbuf - the buffer to check
 * @param len - the length to check for
 *
 * @return 0 on success, -1 otherwise.
**/
#ifdef P_strbuf_check
size_t strbuf_check(strbuf_t * strbuf, const size_t len)
{
  if (STRBUF_AVAIL(strbuf) < len + 1)
    return strbuf_realloc(strbuf, len);
  return 0;
}
#endif

/*! \brief set the length of \p strbuf
 *
 * Set the length of the string buffer \p strbuf to the length
 * given by \p len. If the string was larger than \p len characters
 * before, it will be cutted down to \p len characters. If it was
 * shorter before, the total length will be increased if necessary
 * and the empty space is filled with spaces.
 *
 * @param strbuf - the buffer to work on
 * @param len - the length to set the buffer to
 *
 * @return The new length on success, 0 otherwise.
**/
#ifdef P_strbuf_setlength
size_t strbuf_setlength(strbuf_t * strbuf, size_t len)
{
  if (len < 0)
    return 0;
  if (STRBUF_LEN(strbuf) > len) {
    strbuf->len = len;
    strbuf->s[len] = '\0';
  } else if (STRBUF_LEN(strbuf) < len) {
    int needed = len - strbuf->len;
    if (strbuf_check(strbuf, needed) == 0) {
      memset(strbuf->s, ' ', needed);
      strbuf->s[len] = '\0';
    } else
      return 0;
  }
  return len;
}
#endif

/*! \brief append a null terminated 'C' string to a strbuf_t structure
 *
 * Append the null terminated 'C' string \p s to the strbuf_t structure
 * \a strbuf. The function strbuf_nappends() does not write more than \a n
 * bytes (including the trailing '\0').
 *
 * @param strbuf - the strbuf_t structure to append \p s to
 * @param s - the null terminated 'C' string to append
 * @param n - the number of characters to append
 *
 * @return The length of characters appended, or 0 if either \p s was
 *   NULL or the allocation of additinal required memory failed.
**/
#ifdef P_strbuf_nappends
size_t strbuf_nappends(strbuf_t * strbuf, const char *s, const size_t n)
{
  size_t len = 0;
  if (s) {
    len = strlen(s);
    len = (n < len) ? n : len;
    if (STRBUF_AVAIL(strbuf) < len + 1) {
      if (strbuf_realloc(strbuf, len) == STRBUF_ERROR)
	return 0;
    }
    memcpy(strbuf->s + strbuf->len, s, len + 1);
    strbuf->len += len;
  }
  return len;
}
#endif

/*! \brief append a null terminated 'C' string to a strbuf_t structure
 *
 * Append the null terminated 'C' string \p s to the strbuf_t structure
 * \a strbuf.
 *
 * @param strbuf - the strbuf_t structure to append \p s to
 * @param s - the null terminated 'C' string to append
 *
 * @return The length of characters appended, or 0 if either \p s was
 *   NULL or the allocation of additinal required memory failed.
**/
#ifdef P_strbuf_appends
size_t strbuf_appends(strbuf_t * strbuf, const char *s)
{
  size_t len = 0;
  if (s) {
    len = strlen(s);
    return strbuf_nappends(strbuf, s, len);
  }
  return len;
}
#endif

/*! \brief append a character 'n' times to a strbuf_t structure
 *
 * Append the character \p c to \p n times to the strbuf_t structure
 * \a strbuf.
 *
 * @param strbuf - the strbuf_t structure to appand \p c to
 * @param s - the character to append
 * @param n - the number of characters to append
 *
 * @return The length of characters assigned, or 0 if the allocation of the
 *   required memory failed.
 */
#ifdef P_strbuf_appendcn
size_t strbuf_appendcn(strbuf_t * strbuf, const char c, const size_t n)
{
  char *tmp = malloc(n + 1);
  size_t len = 0;
  if (tmp) {
    memset(tmp, c, n);
    len = strbuf_nappends(strbuf, tmp, n);
    free(tmp);
  }
  return len;
}
#endif

/*! \brief assign a null terminated 'C' string to a strbuf_t structure
 *
 * Assign the null terminated 'C' string \p s to the strbuf_t structure
 * \a strbuf.
 *
 * @param strbuf - the strbuf_t structure to assign \p s to
 * @param s - the null terminated 'C' string to assign
 *
 * @return The length of characters assigned, or 0 if either \p s was
 *   NULL or the allocation of the required memory failed.
**/
#ifdef P_strbuf_puts
size_t strbuf_puts(strbuf_t * strbuf, const char *s)
{
  strbuf->len = 0;
  return strbuf_appends(strbuf, s);
}
#endif

/*! \brief prepend a null terminated 'C' string to a strbuf_t structure
 *
 * Prepend the null terminated 'C' string \p s to the strbuf_t structure
 * \a strbuf.
 *
 * @param strbuf - the strbuf_t structure to prepend \p s to
 * @param s - the null terminated 'C' string to be prepended
 *
 * @return The length of characters prepended, or 0 if either \p s was
 *   NULL or the allocation of the required memory failed.
**/
#ifdef P_strbuf_prepends
size_t strbuf_prepends(strbuf_t * strbuf, const char *s)
{
  size_t len = 0;
  if (s) {
    len = strlen(s);
    if (strbuf_check(strbuf, len) == 0) {
      memmove(strbuf->s + len, strbuf->s, strbuf->len + 1);
      memcpy(strbuf->s, s, len);
      strbuf->len += len;
    }
  }
  return len;
}
#endif

/*! \brief append a <tt>long int</tt> to a strbuf_t structure
 *
 * Append the ASCII representation of the <tt>long int</tt> \a l to the
 * strbuf_t structure \a strbuf.
 *
 * @param strbuf - the strbuf_t structure to append \p s to
 * @param l - the <tt>long int</tt> to append
 *
 * @return The length of characters appended, or 0 if either \p s was
 *   NULL or the allocation of additinal required memory failed.
**/
#ifdef P_strbuf_appendl
size_t strbuf_appendl(strbuf_t * strbuf, const long l)
{
  char buf[STRBUF_LONG];
  int len;

  len = fmt_long(buf, l);
  buf[len] = '\0';
  return strbuf_appends(strbuf, buf);
}
#endif

/*! \brief append a <tt>unsigned long long int</tt> hexformatted to a
 * strbuf_t structure
 *
 * Append the Hexadecimal representation of the <tt>unsigned long long int</tt>
 * \a l to the strbuf_t structure \a strbuf.
 *
 * @param strbuf - the strbuf_t structure to append \p s to
 * @param l - the <tt>unsigned long long int</tt> to append
 *
 * @return The length of characters appended, or 0 if either \p s was
 *   NULL or the allocation of additinal required memory failed.
**/
#ifdef P_strbuf_appendllx
size_t strbuf_appendllx(strbuf_t * strbuf, const unsigned long long l)
{
  char buf[STRBUF_LONG];
  int len;

  len = fmt_xlonglong(buf, l);
  buf[len] = '\0';
  return strbuf_appends(strbuf, buf);
}
#endif

#ifdef P_strbuf_appendll
size_t strbuf_appendll(strbuf_t * strbuf, const long long l)
{
  char buf[STRBUF_LONG];
  int len;

  len = fmt_longlong(buf, l);
  buf[len] = '\0';
  return strbuf_appends(strbuf, buf);
}
#endif

#ifdef P_strbuf_appendllu
size_t strbuf_appendllu(strbuf_t * strbuf, const unsigned long long l)
{
  char buf[STRBUF_LONG];
  int len;

  len = fmt_ulonglong(buf, l);
  buf[len] = '\0';
  return strbuf_appends(strbuf, buf);
}
#endif

#ifdef P_strbuf_write
size_t strbuf_write(strbuf_t * strbuf, int fd)
{
  size_t retval = 0;
  if (STRBUF_LEN(strbuf))
    retval = write(fd, strbuf->s, strbuf->len);
  return retval;
}
#endif

/*! \brief free the string buffer associated to \a strbuf
 *
 * @param strbuf - the strbuf structure the free
 *
 * @return nothing
**/
#ifdef P_strbuf_nullify
void strbuf_nullify(strbuf_t * strbuf)
{
  if (strbuf) {
    if (strbuf->s)
      free(strbuf->s);
    strbuf->s = NULL;
    strbuf->len = strbuf->total = 0;
  }
}
#endif

/*! \brief append a variable of arguments to a strbuf
 *
 * Append a variable number of arguments in a printf like manner to
 * a strbuf structure.
 *
 * Conversion specifiers supported:
 *  %s
 *  %d,%i
 *  %x
 *  %p
 *  %m
 * Flags supported:
 *  # - The value should be converted to an ``alternate form''. For 'x'
 *      conversions, a non-zero result has the string  `0x' prepended to it.
 *  0 - The value should be zero padded.
 *  - - The  converted  value  is  to  be left adjusted on the field boundary.
 *
 * @param strbuf - the strbuf structure to append too
 * @param format - a string describing the format
 * @param ap - a va_list containing the arguments
 *
 * @return The length of characters appended.
**/
#define PF_FLAG_HEX         (1<<1)
#define PF_FLAG_UNSIGNED    (1<<2)
#define PF_FLAG_DOT         (1<<3)
#define PF_FLAG_ZERO        (1<<4)
#define PF_FLAG_ALTERNATE   (1<<5)
#define PF_FLAG_LEFT        (1<<6)

#ifdef P_strbuf_vappendf
size_t strbuf_vappendf(strbuf_t * strbuf, const char *format, va_list ap)
{
  size_t len = 0;
  char *start = (char *) format;
  char *pos = start;
  char *tmp;
  strbuf_t strtmp = STRBUF_ZERO;

  while (*format) {
    if (*format == '%') {
      int flaglong = 0;
      int flags = 0;
      int width = 0;
      int preci = 0;

      strtmp.len = 0;

      if (pos != start)
	len += strbuf_nappends(strbuf, start, pos - start);

    readmore:

      format++;
      switch (*format) {
	/* modifiers */
      case 'l':
	++flaglong;
	goto readmore;
      case '.':
	flags |= PF_FLAG_DOT;
	goto readmore;
      case '#':
	flags |= PF_FLAG_ALTERNATE;
	goto readmore;
      case '-':
	flags |= PF_FLAG_LEFT;
	goto readmore;
	/* integers */
      case 'p':
	flags |= PF_FLAG_ALTERNATE;
	width = 10;
      case 'x':
	flags |= PF_FLAG_HEX;	/* fall through */
      case 'i':
      case 'd':
      case 'u':
	flags |= PF_FLAG_UNSIGNED;
	{
	  long long l;
	  size_t sz;
	  char *alternate = NULL;

	  switch (flaglong) {
	  case 0:
	    l = (long long) va_arg(ap, int);
	    break;
	  case 1:
	    l = (long long) va_arg(ap, long);
	    break;
	  default:
	    l = (long long) va_arg(ap, long long);
	  }

	  if (flags & PF_FLAG_HEX)
	    sz = strbuf_appendllx(&strtmp, (unsigned long long) l);
	  else if (flags & PF_FLAG_UNSIGNED)
	    sz = strbuf_appendllu(&strtmp, (unsigned long long) l);
	  else
	    sz = strbuf_appendll(&strtmp, l);

	  if ((flags & PF_FLAG_HEX) && (flags & PF_FLAG_ALTERNATE)) {
	    sz += 2;
	    alternate = "0x";
	  }

	  if (width <= sz) {
	    /* all is good, no padding */
	    strbuf_appends(strbuf, alternate);
	    strbuf_nappends(strbuf, strtmp.s, strtmp.len);
	  } else if (flags & PF_FLAG_LEFT) {
	    /* left aligned */
	    strbuf_appends(strbuf, alternate);
	    strbuf_nappends(strbuf, strtmp.s, strtmp.len);
	    strbuf_appendcn(strbuf, (flags & PF_FLAG_ZERO) ? '0' : ' ',
			    width - sz);
	  } else {
	    /* right aligned */
	    if (flags & PF_FLAG_ZERO) {
	      strbuf_appends(strbuf, alternate);
	      strbuf_appendcn(strbuf, '0', width - sz);
	    } else {
	      strbuf_appendcn(strbuf, ' ', width - sz);
	      strbuf_appends(strbuf, alternate);
	    }
	    strbuf_nappends(strbuf, strtmp.s, strtmp.len);
	  }

	  break;
	}
      case 's':
	{
	  char *c = va_arg(ap, char *);
	  if (!c)
	    c = "(null)";
	  len += strbuf_appends(strbuf, c);
	}
	break;
      case 'm':
	len += strbuf_appends(strbuf, strerror(errno));
	break;
      case '0':
	flags |= PF_FLAG_ZERO;
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
	if (flags & PF_FLAG_DOT)
	  return -1;
	width = strtoul(format, &tmp, 10);
	if (*tmp == '.') {
	  flags |= PF_FLAG_DOT;
	  preci = strtoul(tmp + 1, &tmp, 10);
	}
	format = tmp - 1;
	goto readmore;
      default:
	/* unsupported modifier */
	break;
      }
      ++format;
      start = pos = (char *) format;
      continue;
    }
    ++pos;
    ++format;
  }

  if (pos != start)
    len += strbuf_nappends(strbuf, start, pos - start);

  return len;
}
#endif

#ifdef P_strbuf_putf
size_t strbuf_putf(strbuf_t * strbuf, const char *format, ...)
{
  va_list ap;
  int retval;

  va_start(ap, format);
  strbuf->len = 0;
  retval = strbuf_vappendf(strbuf, format, ap);
  va_end(ap);

  return retval;
}
#endif

#ifdef P_strbuf_fappend
size_t strbuf_appendf(strbuf_t * strbuf, const char *format, ...)
{
  va_list ap;
  int retval;

  va_start(ap, format);
  retval = strbuf_vappendf(strbuf, format, ap);
  va_end(ap);

  return retval;
}
#endif

#ifdef STANDALONE
int main(void)
{
  strbuf_t b = { 0, 0, 0 };
  int i;

  for (i = 0; i <= 1023; i++) {
    strbuf_appends(&b, "X");
  }
  strbuf_nullify(&b);
  strbuf_appends(&b, "tach ");
  strbuf_appendl(&b, 234567);
  strbuf_appends(&b, " auch");
  strbuf_write(&b, 2);
}
#endif

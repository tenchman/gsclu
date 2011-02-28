/* $Id: strbuf.h 67 2008-04-24 05:20:55Z gernot $ */
#ifndef __STRBUF_H
#define __STRBUF_H 1

/*!
 * \file strbuf.h
 *
 * \author Gernot Tenchio <gernot@tenchio.de>
 * \brief save, self memory allocating string functions
 * \date 21.09.2005
 *
 * Example:
 * \code
 *
 * #include <strbuf.h>
 *
 * int main(void) {
 *   strbuf_t str = { 0 };
 *
 *   strbuf_appends(&str, "Tach viele ");
 *   strbuf_appendi(&str, 100);
 *   strbuf_appends(&str, "tausend Male!");
 *   strbuf_write(&str, 2);
 *   strbuf_nullify(&buf);
 * }
 * \endcode
**/

#include <stdarg.h>
#include <stddef.h>

/*! the alignment of a strbuf_t structure */
#define STRBUF_BOUNDS 0xFF
/*! calculate the remaining free characters in a strbuf_t structure */
#define STRBUF_AVAIL(__s) (__s?__s->total-__s->len:0)
#define STRBUF_LEN(__s) (__s?__s->len:0)
#define STRBUF_LONG 41
#define STRBUF_ZERO  { 0, 0, 0 }

#define IOBUF_SIZE   1024
#define IOBUF_ZERO   { 0, 0, 0, 0, 0 }

#define STRIO_MAXTRIES 5

#define STRBUF_ESYS	1
#define STRBUF_ENULL	2

#define STRBUF_ERROR -1

typedef struct strbuf_t {
  char *s;			/*! the holy buffer itself */
  unsigned int len;		/*! current length */
  unsigned int total;		/*! length of total allocated memory */
} strbuf_t;

typedef struct iobuf_t {
  char *s;			/*! the holy buffer itself */
  unsigned int len;		/*! current length */
  unsigned int pos;		/*! current position in buffer */
  unsigned int total;		/*! length of total allocated memory */
  int fd;			/*! a filedescriptor associated to this iobuf */
} iobuf_t;

extern int strbuf_errno;
extern iobuf_t *iobuf_stdin;
extern iobuf_t *iobuf_stdout;
extern iobuf_t *iobuf_stderr;

size_t strbuf_puts(strbuf_t * strbuf, const char *s);
size_t strbuf_appends(strbuf_t * strbuf, const char *s);
size_t strbuf_prepends(strbuf_t * strbuf, const char *s);
size_t strbuf_appendl(strbuf_t * strbuf, const long l);
size_t strbuf_nappend(strbuf_t * strbuf, const char *s, const size_t n);
size_t strbuf_nappends(strbuf_t * strbuf, const char *s, const size_t n);
size_t strbuf_write(strbuf_t * strbuf, int fd);
size_t strbuf_read(strbuf_t * strbuf, iobuf_t * iobuf);
size_t strbuf_setlength(strbuf_t * strbuf, size_t len);
size_t strbuf_appendcn(strbuf_t * strbuf, const char c, const size_t n);
void strbuf_nullify(strbuf_t * strbuf);
size_t strbuf_appendll(strbuf_t * strbuf, const long long l);
size_t strbuf_appendllx(strbuf_t * strbuf, const unsigned long long l);
size_t strbuf_appendllu(strbuf_t * strbuf, const unsigned long long l);

#define strbuf_appendi(__s, __i) strbuf_appendl(__s, (int)__i)
#define strbuf_reset(__s) strbuf_setlength(__s, 0)

/* formatted string operations */
size_t strbuf_appendf(strbuf_t * strbuf, const char *format, ...);
size_t strbuf_putf(strbuf_t * strbuf, const char *format, ...);
size_t strbuf_vappendf(strbuf_t * strbuf, const char *format, va_list ap);
size_t strbuf_aprintf(strbuf_t * strbuf, const char *format, ...);
size_t strbuf_fdputf(int fd, strbuf_t * strbuf, const char *format, ...);

/* io functions */
size_t strbuf_fgets(strbuf_t * strbuf, iobuf_t * iobuf);
size_t strbuf_fputs(strbuf_t * strbuf, iobuf_t * iobuf);

/* internal functions */
size_t strbuf_realloc(strbuf_t * strbuf, size_t len);
size_t strbuf_check(strbuf_t * strbuf, const size_t len);
#endif

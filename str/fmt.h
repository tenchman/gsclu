/* Public domain. */

#include <sys/types.h>

#ifndef FMT_H
#define FMT_H

#define FMT_ULONG 40		/* enough space to hold 2^128 - 1 in decimal, plus \0 */
#define FMT_LEN ((char *) 0)	/* convenient abbreviation */

size_t fmt_ulong(char *s, unsigned long u);
size_t fmt_long(char *dest, long l);
size_t fmt_ulonglong(char *s, unsigned long long u);
size_t fmt_longlong(char *dest, long long l);
size_t fmt_xlong(char *dest, unsigned long i);
size_t fmt_xlonglong(char *dest, unsigned long long i);
size_t fmt_ulonglong(char *dest, unsigned long long int i);
#endif

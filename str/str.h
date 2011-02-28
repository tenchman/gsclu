#ifndef __STH_H
#define __STR_H 1

#include <sys/types.h>

#define REGPARM(x) __attribute__((regparm(x)))

size_t str_ecopy(char *dst, const char *end, const char *src);
size_t str_eol(const char *line, size_t * len);
size_t str_len(const char *s);
char *str_endofline(const char *line, char **endptr);
char *str_ndup(const char *s, const int n);
int str_casecmp(const char *s1, const char *s2);

#endif

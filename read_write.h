#ifndef __PS__READ_H
#define __PS_READ_H 1

#define LEFT  0
#define RIGHT 1

#include "attributes.h"

REGPARM(2)
int readulonglong(char *s, unsigned long long *u);
REGPARM(2)
int readulong(char *s, unsigned long *u);
REGPARM(2)
int readlong(char *s, long *l);
REGPARM(2)
int readint(char *s, int *i);
REGPARM(2)
int readchar(char *s, char *c);
REGPARM(2)
int readstring(char *s, char **str);
REGPARM(2)
int readprocname(char *s, char **str);
REGPARM(3)
int writelonglong(char *s, char *end, long long l, unsigned int width, int align);
REGPARM(3)
int writeulonglong(char *s, char *end, unsigned long long u, unsigned int width,
		   int align);
REGPARM(3)
int writestring(char *s, char *end, char *str, int width);
REGPARM(2)
int skip(char *s, int n) __attribute__ ((pure));
// int writestring(char *s, char *end, char *str, int width, int align);

#endif

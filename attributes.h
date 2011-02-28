#ifndef __ATTRIBUTES_H
#define __ATTRIBUTES_H

#ifdef __i386__
#define REGPARM(x) __attribute__((regparm(x)))
#else
#define REGPARM(x)
#endif
#define NORETURN  __attribute__((noreturn))
#define NONNULL   __attribute__((nonnull))
#endif

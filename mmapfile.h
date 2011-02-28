#ifndef _MMAP_FILE_H
#define _MMAP_FILE_H 1

#include <sys/stat.h>

char *mmapfile(char *fn, struct stat *st);

#endif

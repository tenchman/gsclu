#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "str.h"
#include "gtget.h"

/**
 * read ONE line from file \p name.
**/
char *readconfig(char *name)
{
  int fd;
  char *retval = NULL;
  struct stat sb;
  if ((fd = open(name, O_RDONLY)) > 0) {
    if (fstat(fd, &sb) == 0) {
      int len = sb.st_size;
      char *txt = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
      while (len && (txt[len--] == '\n'));
      if ((retval = malloc(len + 1))) {
	memcpy(retval, txt, len);
	retval[len] = '\0';
      }
      munmap(txt, sb.st_size);
    }
    close(fd);
  }
  return retval;
}

/**
 * try to read the content of the file "host/name". If that fails, try to
 * read the content of the file "name"
**/
char *tryconfig(char *host, char *name)
{
  size_t len = str_len(host) + str_len(name) + 2;
  char buf[len];
  char *tmp = buf;
  char *end = buf + len;

  tmp += str_ecopy(tmp, end, host);
  tmp += str_ecopy(tmp, end, "/");
  tmp += str_ecopy(tmp, end, name);

  if ((tmp = readconfig(buf)))
    return tmp;

  return readconfig(name);
}

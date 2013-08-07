#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "str.h"
#include "gtget.h"

/*
 * read a variable from environment case insentive
**/
char *getcaseenv(const char *s)
{
  int i;
  unsigned int len;

  if (NULL == __environ || NULL == s)
    return NULL;
  len = strlen(s);
  for (i = 0; __environ[i]; ++i)
    if (0 == (strncasecmp(__environ[i], s, len)) && ('=' == __environ[i][len]))
      return __environ[i] + len + 1;
  return NULL;
}

/**
 * read ONE line from file \p name.
**/
static char *readconfig(connection_t *conn, char *name)
{
  int fd;
  char *retval = NULL;
  struct stat sb;
  if ((fd = openat(conn->conffd, name, O_RDONLY)) > 0) {
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
char *tryconfig(connection_t *conn, char *host, char *name)
{
  size_t len = str_len(host) + str_len(name) + 2;
  char buf[len];
  char *tmp = buf;
  char *end = buf + len;

  tmp += str_ecopy(tmp, end, host);
  tmp += str_ecopy(tmp, end, "/");
  tmp += str_ecopy(tmp, end, name);

  if ((tmp = readconfig(conn, buf)))
    return tmp;

  return readconfig(conn, name);
}

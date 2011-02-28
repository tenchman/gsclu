#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

char *mmapfile(char *fn, struct stat *st)
{
  char *buf = NULL;
  int fd = open(fn, O_RDONLY);
  int terrno;

  if (fd < 0)
    return NULL;

  if (fstat(fd, st) < 0 || st->st_size <= 0) {
    terrno = errno;
    close(fd);
    errno = terrno;
    return NULL;
  }

  buf = mmap((char *) 0, st->st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (buf == (char *) (-1)) {
    terrno = errno;
    close(fd);
    errno = terrno;
    return NULL;
  }
  /* from mmap(2):
     "closing the file descriptor does not unmap the region."
   */
  close(fd);
  return buf;
}

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/*
 * Map the content of a file  in the virtual address space of the calling process.
 *
 * @fn - name of the file to open
 * @st - pointer to a 'struct stat' structure to hold file informations
**/
char *mmapfile(char *fn, struct stat *st)
{
  char *buf = NULL;
  int fd = open(fn, O_RDONLY);
  int __errno;

  if (fd < 0) {
    /* */
  } else if (0 > fstat(fd, st)) {
    /* */
  } else if ((char *)-1 == (buf = mmap((char *) 0, st->st_size, PROT_READ, MAP_PRIVATE, fd, 0))) {
    buf = NULL;
  }

  /**
   * from mmap(2):
   * "closing the file descriptor does not unmap the region."
  **/
  __errno = errno;
  close(fd);
  errno = __errno;
  return buf;
}

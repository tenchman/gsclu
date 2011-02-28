/*
 * $Id: mimencode.c 24 2005-12-01 22:57:15Z gernot $
 * mimencode.c simple command line base64 encoder
 *
 * fmt_base64() is taken from Felix v. Leitners libowfat
**/

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

const char base64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

unsigned long fmt_base64(char *dest, const char *src, unsigned long len)
{
  register const unsigned char *s = (const unsigned char *) src;
  unsigned short bits = 0, temp = 0;
  unsigned long written = 0, i;
  for (i = 0; i < len; ++i) {
    temp <<= 8;
    temp += s[i];
    bits += 8;
    while (bits > 6) {
      if (dest)
	dest[written] = base64[((temp >> (bits - 6)) & 63)];
      ++written;
      bits -= 6;
    }
  }
  if (bits) {
    temp <<= (6 - bits);
    if (dest)
      dest[written] = base64[temp & 63];
    ++written;
  }
  while (written & 3) {
    if (dest)
      dest[written] = '=';
    ++written;
  }
  return written;
}

int main(int argc, char **argv)
{
  char inbuf[54];
  char outbuf[72 + 1];		// 72 + '\n'
  int fdin = 0, len;

  if (argv[1])
    if (!(fdin = open(argv[1], O_RDONLY)))
      _exit(1);
  while ((len = read(fdin, inbuf, sizeof(inbuf))) > 0) {
    len = fmt_base64(outbuf, inbuf, len);
    outbuf[len] = '\n';
    write(1, outbuf, len + 1);
  }
  close(fdin);
  _exit(0);
}

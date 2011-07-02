/* gtget is Copyright (c) 2004 - XXXX Gernot Tenchio

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* $Id$ */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include "gtget.h"
#include "strbuf.h"
#include "fmt.h"
#include "str.h"

void die(connection_t * conn, const char *msg1, const char *msg2)
{
  write(2, msg1, str_len(msg1));
  if (msg2)
    write2f(": %s\n", msg2);
  else
    write(2, "\n", 1);
  cleanup(conn, CLEANUP_AND_UNLINK);
  _exit(1);
}

void die_protocol(connection_t * conn)
{
  conn->code = GTGET_EPROTO;
  die(conn, "protocol not supported", NULL);
}

void die_sys(connection_t * conn, const char *message)
{
  conn->code = GTGET_ESYS;
  die(conn, message, strerror(errno));
}

void die_write(connection_t * conn)
{
  die_sys(conn, "write error");
}

void cleanup(connection_t * conn, int how)
{
  if (conn->flags & GTGET_FLAG_DOSSL)
    gtget_ssl_close(conn);

  if (conn->sockfd > 0)
    close(conn->sockfd);
  memset(conn->response, 0, sizeof(response_header_t));
  conn->ressource = NULL;
  conn->remote->host = NULL;

  if (how) {
    if (conn->postfd > 0)
      close(conn->postfd);
    conn->postfd = 0;

    /* close the output file descriptor */
    if (conn->outfd > 1)
      close(conn->outfd);
    conn->outfd = -1;

    /* remove the stale outfile */
    if ((how > 1) && (chdir(conn->cwd) == 0))
      unlink(conn->outfile);
  }
}

char *tryopen(const char *path)
{
  int fd;
  char *result = NULL;
  if ((fd = open(path, O_RDONLY)) > 0) {
    close(fd);
    result = (char *) path;
  }
  return result;
}

/* Check the existence of either \a file1 or \a file2
 *
 * @param file1 - the first file to check
 * @param file2 - an alternative file to check
 *
 * if \a file1 is not NULL its presence is mandatory
**/
char *tryopen_alt(connection_t * conn, const char *file1, const char *file2)
{
  char *result = NULL;
  if (file1) {
    if (!(result = tryopen(file1)))
      die_sys(conn, file1);
  } else {
    if ((result = tryopen(file2)) == NULL && errno != ENOENT)
      die_sys(conn, file2);
  }
  return result;
}

/*
 * a very, very limited printf like function, use with care!
**/
int write2f(const char *format, ...)
{
  va_list ap;
  int retval;
  char buf[BUFSIZE];
  char *pos = buf;
  char *end = buf + BUFSIZE;

  va_start(ap, format);
  while (*format) {
    if (*format == '%') {
      format++;
      switch (*format) {
      case 'd':
	{
	  long l = va_arg(ap, signed long);
	  if (l < 0) {
	    *pos++ = '-';
	    l = -l;
	  }
	  pos += fmt_ulong(pos, l);
	  break;
	}
      case 's':
	{
	  char *c = NULL;
	  if ((c = va_arg(ap, char *))) {
	    pos += str_ecopy(pos, end, c);
	  } else {
	    pos += str_ecopy(pos, end, "(null)");
	  }
	}
	break;
      default:
	write(2, "writef: unsupported modifier!\n", 14);
	exit(1);
      }
      ++format;
      continue;
    }
    *pos++ = *format++;
  }
  retval = write(2, buf, pos - buf);
  va_end(ap);
  return retval;
}

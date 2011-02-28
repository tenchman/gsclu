/* gtget is Copyright (c) 2004 - XXXX Gernot Tenchio

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

#include <stdlib.h>
#include "gtget.h"

extern int timedout;

static ssize_t std_write(connection_t * c, char *buf, size_t n)
{
  int r = 0;
  if (timedout)
    r = -1;
  else {
    alarm(c->timeout);
    r = write(c->sockfd, buf, n);
    alarm(0);
  }
  return r;
}

static ssize_t std_read(connection_t * c, char *buf, size_t n)
{
  int r = -1;
  if (!timedout) {
    alarm(c->timeout);
    r = read(c->sockfd, buf, n);
    alarm(0);
  }
  return r;
}

int do_write(connection_t * conn, MD5_CTX * ctx, const char *buf, int len)
{
  size_t w;
  if ((w = write(conn->outfd, buf, len)) != len)
    die_write(conn);

  if (conn->flags & GTGET_FLAG_DOMD5)
    MD5Update(ctx, (unsigned char *) buf, w);

  if (conn->verbosity >= 4)
    write2f("DOWRITE: wrote %d bytes\n", w);
  return w;
}


/*! \brief setup the gtget read/write functions
 *
 * @param conn - a proper initialized connection to work on
 *
 * @return 0 on success, -1 otherwise.
**/
void setup_io_funcs(connection_t * conn, int dossl)
{
  if (dossl) {
    conn->read = gtget_ssl_read;
    conn->write = gtget_ssl_write;
  } else {
    conn->read = std_read;
    conn->write = std_write;
  }
}

void proxy_connect(connection_t * conn)
{
  int method = conn->method;
  int flags = conn->flags;

  conn->flags &= ~GTGET_FLAG_FORCEMD5;
  conn->method = METHOD_CONNECT;
  if (do_get(conn) < 0 || conn->response->reason != 200)
    die(conn, "proxy error", conn->response->reasonstr);
  free(conn->response->reasonstr);
  conn->response->reasonstr = NULL;
  conn->method = method;
  conn->flags = flags;
}

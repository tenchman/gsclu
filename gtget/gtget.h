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
#ifndef __GTGET_H
#define __GTGET_H 1

#define BUFSIZE 20000
#define FULLNAME "gtget 0.3.2"

#define METHOD_GET	0
#define METHOD_POST	1
#define METHOD_CONNECT	2
#define SETNULL(__x)	memset(&__x, 0, sizeof(__x));

#define CLEANUP_AND_CLOSE  1
#define CLEANUP_AND_UNLINK 2

#define GTGET_ESYS      -1
#define GTGET_ESSL      -2
#define GTGET_EPROTO    -3

#define LOG_ERROR       (1<<0)
#define LOG_HEADERS     (1<<1)

#define GTGET_FLAG_DOSSL    (1<<0)
#define GTGET_FLAG_DOMD5    (1<<1)
#define GTGET_FLAG_INSECURE (1<<2)
#define GTGET_FLAG_PROGRESS (1<<3)
#define GTGET_FLAG_FORCEMD5 (1<<4)

#include <md5.h>
#include "../attributes.h"
#include "sslSocket.h"
#include "timer.h"

typedef struct response_header_t {
  char *reasonstr;
  char *location;
  char *digest;
  size_t contentlength;
  size_t chunklength;
  size_t bodylength;
  size_t totallength;
  size_t headerlength;
  int chunked;
  int reason;
} response_header_t;

typedef struct destination_t {
  char *host;
  char *auth;
  int port;
} destination_t;

typedef struct connection_s connection_t;
typedef ssize_t(*iofunc_t) (connection_t *, char *, size_t);

struct connection_s {
  int sockfd;			/* the socket */
  int postfd;			/* the file descriptor to read the postdata from */
  int outfd;			/* the file descriptor to write the output to */
  int httpversion;		/* HTTP/1.[0|1] */
  int code;			/* error code to return on die() */
  char *outfile;		/* the filename of the file to write */
  char *caFile;			/* SSL CA */
  char *ccFile;			/* SSL client certificate */
  char *ckFile;			/* SSL client key */
  char *cwd;
  int timeout;			/* timeout for connect/read/write */
  int method;			/* METHOD_GET/POST/CONNECT */
  char *postdata;		/* pointer to the postdata */
  size_t postlen;		/* length of postdata */
  char *uri;
  destination_t *remote;
  destination_t *proxy;
  response_header_t *response;
  void *ssl;
  char *ressource;
  GTtimer_t connect_timer;
  GTtimer_t timer;
  iofunc_t write;
  iofunc_t read;
  unsigned int verbosity;
  unsigned int flags;
};

char *tryconfig(char *host, char *name);
char *tryopen(const char *path);
char *tryopen_alt(connection_t * conn, const char *file1, const char *file2);
char *readconfig(char *name);
void setup_io_funcs(connection_t * conn, int dossl);
int check_cn(char *cn, char *fqdn);
int write2f(const char *format, ...);

int do_get(connection_t * conn);
int do_write(connection_t * conn, MD5_CTX * ctx, const char *buf, int len);
void proxy_connect(connection_t * conn);

void die(connection_t * conn, const char *msg1, const char *msg2);
void die_sys(connection_t * conn, const char *message);
void die_write(connection_t * conn);
void die_protocol(connection_t * conn);
void cleanup(connection_t * conn, int how);

REGPARM(1)
void gtget_ssl_init(connection_t * conn);
REGPARM(1)
void gtget_ssl_close(connection_t * conn);
REGPARM(1)
void gtget_ssl_connect(connection_t * conn);
ssize_t gtget_ssl_read(connection_t * c, char *buf, size_t n);
ssize_t gtget_ssl_write(connection_t * c, char *buf, size_t n);
#endif

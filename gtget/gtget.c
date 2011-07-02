/* gtget is Copyright (c) 2004 - XXXX Gernot Tenchio

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* Author's email: gernot@tenchio.de */

/*
  TODO:
    - handle redirects: done
    - HTTP/1.1: partially done
    - more proxy stuff
    - handle 303 See Other
    - option -r for max. retries
*/

#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <math.h>
#include <md5.h>
#include <limits.h>
#include <errno.h>
#include "../attributes.h"
#include "timer.h"
#include "strbuf.h"
#include "fmt.h"
#include "str.h"
#include "gtget.h"

#define MOVE_CURSOR_LEFT "\033[0G"
#define CONNECT(__fd, __sa) \
  connect(__fd, (struct sockaddr *)__sa, sizeof(struct sockaddr))

static char *configdir = NULL;
static char iobuf[SSL_MAX_PLAINTEXT_LEN];
int timedout = 0;

REGPARM(2)
static void (*print_progress) (size_t, size_t) = NULL;

const char base64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

unsigned long fmt_base64(unsigned char *dest, const unsigned char *src,
			 unsigned long len)
{
  register const unsigned char *s = (const unsigned char *) src;
  unsigned short bits = 0, temp = 0;
  unsigned long written = 0, i;

  for (i = 0; i < len; ++i) {
    temp <<= 8;
    temp += s[i];
    bits += 8;
    while (bits > 6) {
      dest[written] = base64[((temp >> (bits - 6)) & 63)];
      ++written;
      bits -= 6;
    }
  }

  if (bits) {
    temp <<= (6 - bits);
    dest[written] = base64[temp & 63];
    ++written;
  }

  while (written & 3) {
    dest[written] = '=';
    ++written;
  }

  dest[written] = '\0';
  return written;
}

static void sighandler(int sig)
{
  timedout = 1;
  errno = ETIMEDOUT;
}

REGPARM(2)
static void print_recv_of(size_t recv, size_t total)
{
  write2f("%s%d/%d ", MOVE_CURSOR_LEFT, recv, total);
}

REGPARM(2)
static void print_recv(size_t recv, size_t total)
{
  write2f("%s%d ", MOVE_CURSOR_LEFT, recv);
}


REGPARM(1)
static void parseurl(connection_t * conn)
{
  char *host = conn->uri, *tmp;
  conn->remote->port = 80;

  conn->flags &= ~GTGET_FLAG_DOSSL;
  if (strncmp(host, "http", 4))
    die_protocol(conn);
  host += 4;
  if (*host == 's') {
    ++host;
    conn->flags |= GTGET_FLAG_DOSSL;
    conn->remote->port = 443;
  }

  if (strncmp(host, "://", 3))
    die_protocol(conn);
  host += 3;

  if ((tmp = strchr(host, '/'))) {
    conn->remote->host = str_ndup(host, tmp - host);
    conn->ressource = tmp;
  } else {
    conn->remote->host = strdup(host);
    conn->ressource = "/";
  }

  if (!conn->outfile) {
    if ((tmp = strrchr(conn->ressource, '/')) && tmp[1] != '\0') {
      conn->outfile = strdup(++tmp);
      if ((tmp = strchr(conn->outfile, '?')))
	*tmp = '\0';
    }
    if (!conn->outfile || !conn->outfile[0])
      conn->outfile = "index.html";
  }

  if ((tmp = strchr(conn->remote->host, ':'))) {
    *tmp++ = '\0';
    conn->remote->port = atoi(tmp);
  }
  conn->remote->auth = tryconfig(conn->remote->host, "auth");
}

REGPARM(2)
static char *tryproxy(char *host, char *search)
{
  char *proxy;
  int len = str_len(search) + 1;
  char s[len];
  memcpy(s, search, len);
  proxy = tryconfig(host, s);
  if (!proxy)
    proxy = getenv(s);
  if (!proxy) {
    int i = 0;
    while (s[i]) {
      s[i] = toupper(s[i]);
      i++;
    }
    proxy = getenv(search);
  }
  return proxy;
}

REGPARM(1)
static void setup_proxy(connection_t * conn)
{
  char *tmp, *host = NULL;
  int port;

  if (conn->flags & GTGET_FLAG_DOSSL)
    host = tryproxy(conn->remote->host, "https_proxy");
  
  if (!host)
    host = tryproxy(conn->remote->host, "http_proxy");

  if (!host)
    host = getenv("ALL_PROXY");

  if (host) {
    int n;
    if ((tmp = strstr(host, "://")))
      host = tmp + 3;
    
    if ((tmp = strchr(host, ':'))) {
      n = tmp - host;
      port = atoi(++tmp);
    } else {
      port = 3128;
      n = strlen(host);
    }
    free(conn->proxy->host);
    conn->proxy->host = strndup(host, n);
    conn->proxy->port = port;
    conn->proxy->auth = tryconfig(conn->remote->host, "proxyauth");
  }
}

REGPARM(2)
static const char* addrstr(char *dst, int af, struct sockaddr *addr)
{
  union {
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;
    struct sockaddr *a;
  } ptr = { .a = addr };
  char *ret = NULL;

  if (af == AF_INET6) {
    ret = inet_ntop(af, &ptr.in6->sin6_addr, dst, INET6_ADDRSTRLEN);
  } else {
    ret = inet_ntop(af, &ptr.in->sin_addr, dst, INET6_ADDRSTRLEN);
  }
  /* Work around a bug in dietlibc on 64bit systems */
  return ret ? dst : NULL;
}

REGPARM(1)
static void do_connect(connection_t * conn)
{
  char *host;
  int sfd = -1, succeeded = 0;
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  char service[FMT_ULONG] = { 0 };
  char __addrstr[INET6_ADDRSTRLEN] = { 0 };

  setup_proxy(conn);
  if (conn->flags & GTGET_FLAG_DOSSL)
    gtget_ssl_init(conn);

  setup_io_funcs(conn, 0);

  if (conn->proxy->host) {
    host = conn->proxy->host;
    service[fmt_ulong(service, conn->proxy->port)] = '\0';
    if (conn->verbosity >= 2)
      write2f(" => using proxy at %s:%d\n", host, (unsigned long) service);
  } else {
    host = conn->remote->host;
    service[fmt_ulong(service, conn->remote->port)] = '\0';
  }

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  if (0 != getaddrinfo(host, service, &hints, &result)) {
    die(conn, "can't resolve ", host);
  }

  timer_start(&conn->connect_timer);
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    if (conn->verbosity)
      write2f(" => trying %s: ", addrstr(__addrstr, rp->ai_family, rp->ai_addr));

    if ((sfd = socket(rp->ai_family, rp->ai_socktype,rp->ai_protocol)) < 0)
      continue;

    alarm(conn->timeout);
    if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == -1) {
      if (conn->verbosity)
	write2f("FAILED %s\n", strerror(errno));
    } else {
      if (conn->verbosity)
	write2f("OK\n");
      succeeded = 1;
      break;
    }
    alarm(0);
  }
  timer_stop(&conn->connect_timer);

  if (!succeeded)
    die(conn, "can't connect to remote host ", host);

  if (conn->verbosity)
    write2f(" => connected to %s:%s <%s>\n", host, service,
	addrstr(__addrstr, rp->ai_family, rp->ai_addr));

  freeaddrinfo(result);

  conn->sockfd = sfd;
  if (conn->flags & GTGET_FLAG_DOSSL)
    gtget_ssl_connect(conn);
}

/* TODO: needs some investigation
 * correctly parse chunk-ext (See 3.6 Transfer Codings)
**/
REGPARM(2)
static int scan_chunksize(connection_t * conn, char *buf)
{
  char *end, *eoc = buf;
  int len = (int) strtol(buf, &end, 16);

  if (conn->verbosity >= 4)
    write2f("CHUNKLEN: %d\n", len);

  if (buf == end) {
    write2f("<<<%s>>>\n", buf);
    die(conn, "Error parsing chunk length, NaN", NULL);
  }

  if (!(str_endofline(end, &eoc)))
    die(conn, "Error parsing chunk length", NULL);

  conn->response->chunklength = len + 2;
  return eoc - buf;
}

/** \brief parse the response headers
 *
 * @param conn - a valid connection handle
 * @param buf - the buffer to parse
 * @param len - the length of \a buf
 *
 * @return the total header size
**/
static int parse_response(connection_t * conn, char *buf, int len, int *eoh)
{
  char *tmp, *end, *pos = buf;
  int retval = 0;

#ifdef DEBUG
  write2f("%s: ", __FUNCTION__);
  write(2, buf, len);
#endif

  if (!conn->response->reasonstr) {

    if (!strncmp(buf, "HTTP/", 5) && ((tmp = str_endofline(buf, NULL))))
      conn->response->reasonstr = str_ndup(buf, tmp - buf);
    else
      die(conn, "Invalid response", NULL);

    conn->response->reason = atoi(buf + 8);
  }

  while (1) {
    if (!(tmp = str_endofline(pos, &end)))
      break;

    if (conn->verbosity >= 3)
      write(2, pos, end - pos);
    if (pos == tmp) {
      *eoh = 1;
      pos = end;
      /* Content-MD5 was forced but no such header found -> bail out */
      if (conn->flags & GTGET_FLAG_FORCEMD5 && !conn->response->digest)
	die(conn,
	    "FATAL: MD5 digest checking forced but no such header received.",
	    NULL);
      break;
    } else if (!strncmp(pos, "Content-Length: ", 16)) {
      conn->response->contentlength = (size_t) atoi(pos + 16);
    } else if (!strncmp(pos, "Location: ", 10)) {
      *tmp = '\0';
      conn->response->location = str_ndup(pos + 10, tmp - pos + 10);
    } else if (!strncmp(pos, "Content-MD5: ", 13)) {
      *tmp = '\0';
      conn->response->digest = str_ndup(pos + 13, tmp - pos + 13);
      conn->flags |= GTGET_FLAG_DOMD5;
    } else if (!strncmp(pos, "Transfer-Encoding: ", 19)) {
      if ((pos = strstr(pos + 19, "chunked")) && pos < tmp)
	conn->response->chunked = 1;
    }
    pos = end;
  }

  /* When Transfer-Encoding is chunked set contentlength to 0 even
   * if contentlength was provided */
  if (conn->response->chunked)
    conn->response->contentlength = 0;

  if (conn->verbosity >= 2 && conn->response->contentlength)
    write2f(" => %d bytes to retrieve\n", conn->response->contentlength);

  if (conn->flags & GTGET_FLAG_PROGRESS && conn->response->reason == 200) {
    if (conn->response->contentlength)
      print_progress = print_recv_of;
    else
      print_progress = print_recv;
  }
  retval = pos - buf;
  return retval;
}

static int read_answer(connection_t * conn)
{
  char buf[BUFSIZE + 1];
  int len, eoh = 0, result = 0;
  MD5_CTX ctx;

  MD5Init(&ctx);

  /* seek to the beginning of the output file */
  if (conn->outfd > STDERR_FILENO)
    lseek(conn->outfd, 0, SEEK_SET);

  while ((len = conn->read(conn, buf, BUFSIZE)) > 0) {
    char *pos = buf;
    pos[len] = '\0';
    if (conn->verbosity >= 4)
      write2f("READ: got %d bytes (chunklen %d)\n", len,
	      conn->response->chunklength);
    conn->response->totallength += len;

    if (!eoh) {
      int ret = parse_response(conn, pos, len, &eoh);

      len -= ret;
      pos += ret;
      conn->response->headerlength += ret;

      if (eoh) {
	if (conn->verbosity >= 2)
	  write2f("header size: %d bytes \n", conn->response->headerlength);

	if (conn->method == METHOD_CONNECT)
	  return 0;
      }

      if (!len)
	continue;
    }

/*
    RFC 2068, 4.4 Message Length

    Messages MUST NOT include both a Content-Length header field and the
    "chunked" transfer coding. If both are received, the Content-Length
    MUST be ignored.
*/
    if (conn->response->chunked) {
      int written, n;
    writemore:
      if ((size_t)len <= conn->response->chunklength) {
	written = do_write(conn, &ctx, pos, len);
	result += written;
	len -= written;
	pos += written;
	conn->response->chunklength -= written;
      } else {

	if (conn->response->chunklength) {
	  written = do_write(conn, &ctx, pos, conn->response->chunklength);
	  result += written;
	  pos += conn->response->chunklength;
	  len -= conn->response->chunklength;
	  conn->response->chunklength -= written;
	}

	if (len) {
	  /* TODO: handle partially received chunkrecords */
	  if ((n = scan_chunksize(conn, pos)) == 0)
	    break;
	  pos += n;
	  len -= n;
	  if (len > 0)
	    goto writemore;
	}
      }
    } else
      result += do_write(conn, &ctx, pos, len);

#ifndef DEBUG
    if (print_progress)
      print_progress(result, conn->response->contentlength);
#endif

    if (conn->response->contentlength
	&& (size_t)result >= conn->response->contentlength)
      break;
  }

  if (len < 0) {
    if (timedout)
      die_sys(conn, "connection timed out");
    else
      die_sys(conn, "read error");
  }

  if (conn->flags & GTGET_FLAG_DOMD5) {
    unsigned char buf[256];
    unsigned char hash[16];
    MD5Final(hash, &ctx);
    fmt_base64(buf, hash, 16);

    if (strcmp((char *) buf, conn->response->digest)) {
      if (conn->flags & GTGET_FLAG_FORCEMD5)
	die(conn, "FATAL: MD5 digest checksumming failed.", NULL);
      else
	write2f("WARNING: should be: '%s', but is: '%s'\n",
		conn->response->digest, buf);
    } else if (conn->verbosity)
      write2f("%s", "- MD5 Checksum OK.\n");
  }

  conn->response->bodylength = result;
  return result;
}

static void make_http_request(connection_t * conn, strbuf_t * req)
{
  int dossl = conn->flags & GTGET_FLAG_DOSSL;

  if (conn->method == METHOD_CONNECT) {
    strbuf_appends(req, "CONNECT ");
    strbuf_appends(req, conn->remote->host);
    strbuf_appends(req, ":");
    strbuf_appendi(req, conn->remote->port);
  } else {
    strbuf_appends(req, (conn->method == METHOD_POST) ? "POST " : "GET ");
    if (conn->proxy->host && !dossl)
      strbuf_appends(req, conn->uri);
    else
      strbuf_appends(req, conn->ressource);
  }

  /* 14.23 Host: required in HTTP/1.1, nice in HTTP/1.0 */
  strbuf_appends(req, " HTTP/1.");
  strbuf_appendi(req, conn->httpversion);
  strbuf_appends(req, "\r\nHost: ");
  strbuf_appends(req, conn->remote->host);

  /* only append the port if it differs from the standard ports */
  if (!(conn->remote->port == 80)
      || (dossl && conn->remote->port == 443)) {
    strbuf_appends(req, ":");
    strbuf_appendi(req, conn->remote->port);
  }

  /* for POST requests add the Content-Length and Content-Type headers */
  if (conn->method == METHOD_POST) {
    strbuf_appends(req, "\r\nContent-Length: ");
    strbuf_appendi(req, conn->postlen);
    strbuf_appends(req, "\r\nContent-Type: application/x-www-form-urlencoded");
  }

  if (conn->proxy->auth && !dossl) {
    strbuf_appends(req, "\r\nProxy-Authorization: Basic ");
    strbuf_appends(req, conn->proxy->auth);
  }

  if (conn->remote->auth) {
    strbuf_appends(req, "\r\nAuthorization: Basic ");
    strbuf_appends(req, conn->remote->auth);
  }

  strbuf_appends(req,
		 "\r\nUser-Agent: gtget-" VERSION "\r\nConnection: close\r\n\r\n");
}

int do_get(connection_t * conn)
{
  strbuf_t req = STRBUF_ZERO;

  int len;

  make_http_request(conn, &req);

  if (conn->verbosity >= 3)
    strbuf_write(&req, 2);

  if (conn->write(conn, req.s, req.len) < 0)
    die_write(conn);

  strbuf_nullify(&req);

  timer_start(&conn->timer);
  /* read and send the post data */
  if (conn->method == METHOD_POST) {
    if (conn->postfd) {
      while ((len = read(conn->postfd, iobuf, SSL_MAX_PLAINTEXT_LEN)) > 0)
	if (conn->write(conn, iobuf, len) < 0)
	  die_write(conn);
    } else {
      if (conn->write(conn, conn->postdata, conn->postlen) < 0)
	die_write(conn);
    }
  }

  len = read_answer(conn);
  timer_stop(&conn->timer);
  return len;
}

static void usage(void)
{
  write2f("%s", "\n\
 gtget (" VERSION ")\n\n\
 Copyright (C) 2004-2011 - Gernot Tenchio <gernot@tenchio.de>\n\
 This program may be freely redistributed under the terms of the GNU GPL\n\
\n\
 usage: gtget [ options ] URL\n\
   -0            use HTTP 1.0\n\
   -5            force Content-MD5 checking\n\
   -c <dir>      path to configuration directory - /etc/gtget\n\
   -C <file>     SSL: client certificate file - <confdir>/clientcert.pem\n\
   -h            this help text\n\
   -i            SSL: insecure, allow to connect to SSL sites without certs\n\
   -K <file>     SSL: private key file name - <confdir>/clientkey.pem\n\
   -o <file>     write output to 'file', use '-o -' to write to stdout\n\
   -p <@file>    use POST instead of GET and send postdata from 'file'\n\
   -p <string>   use POST instead of GET and send postdata from 'string'\n\
   -q            quiet operation (overwrites -v)\n\
   -s            open output for synchronous I/O\n\
   -S <file>     SSL: CA certificate to verify peer - <confdir>/cacerts.pem\n\
   -t <seconds>  timeout for connect/read/write attempts\n\
   -v            verbose output\n\
");
  _exit(0);
}

int main(int argc, char **argv)
{
  int retval, quiet = 0;
  connection_t conn;
  response_header_t resp;
  destination_t remote, proxy;
  char cwd[PATH_MAX + 1];
  char *postfile = NULL;
  int openflags = O_CREAT | O_RDWR | O_TRUNC;

  if (getcwd(cwd, PATH_MAX) == NULL) {
    write2f("can't get current working directory: %s\n", strerror(errno));
    exit(1);
  }

  SETNULL(conn);
  SETNULL(resp);
  SETNULL(proxy);
  SETNULL(remote);
  (void) signal(SIGALRM, sighandler);
  (void) signal(SIGPIPE, SIG_IGN);

  conn.cwd = cwd;
  conn.method = METHOD_GET;
  conn.flags = GTGET_FLAG_PROGRESS;
  conn.outfd = -1;
  conn.timeout = 120;
  conn.response = &resp;
  conn.proxy = &proxy;
  conn.remote = &remote;
  conn.httpversion = 1;
  conn.verbosity = 1;

  while ((retval = getopt(argc, argv, "05c:C:hiK:no:p:qsS:t:v")) != -1)
    switch (retval) {
    case '0':
      conn.httpversion = 0;
      break;
    case '5':
      conn.flags |= GTGET_FLAG_FORCEMD5;
      break;
    case 'c':
      configdir = optarg;
      break;
    case 'h':
      usage();
      break;
    case 'o':
      conn.outfile = optarg;
      break;
    case 'p':
      if (*optarg == '@')
	postfile = optarg + 1;
      else {
	conn.postdata = optarg;
	conn.postlen = str_len(optarg);
      }
      conn.method = METHOD_POST;
      break;
    case 'i':
      conn.flags |= GTGET_FLAG_INSECURE;
      break;
    case 'n':
      conn.flags &= ~GTGET_FLAG_PROGRESS;
      break;
    case 'q':
      conn.flags &= ~GTGET_FLAG_PROGRESS;
      quiet = 1;
      break;
    case 's':
      openflags |= O_SYNC;
      break;
    case 'C':
      conn.ccFile = optarg;
      break;
    case 'K':
      conn.ckFile = optarg;
      break;
    case 'S':
      conn.caFile = optarg;
      break;
    case 't':
      conn.timeout = atoi(optarg);
      break;
    case 'v':
      ++conn.verbosity;
      break;
    default:
      usage();
    }

  if (!configdir)
    configdir = "/etc/gtget";
  argc -= optind;
  argv += optind;
  if (!argc)
    usage();
  conn.uri = *argv++;

  if (quiet)
    conn.verbosity = 0;

  if (conn.verbosity)
    write2f("%s\n", conn.uri);

  parseurl(&conn);

  if (postfile) {
    struct stat st;
    if (stat(postfile, &st) == 0) {
      conn.postlen = (int) st.st_size;
      if ((conn.postfd = open(postfile, O_RDONLY)) < 0)
	die(&conn, "can't open ", postfile);
    } else
      die(&conn, "can't stat ", postfile);
  }

  /**
   * try to open the output file if any.
  **/
  if (conn.outfile && strcmp(conn.outfile, "-")) {
    if ((conn.outfd = open(conn.outfile, openflags, 0644)) < 0)
      die(&conn, "can't open ", conn.outfile);
  } else {
    conn.outfile = "STDOUT";
    conn.outfd = 1;
    conn.flags &= ~GTGET_FLAG_PROGRESS;
  }

  if (chdir(configdir))
    die(&conn, "can't chdir to ", configdir);

  /**
   * Setup the connection and try to get the requested source.
  **/
  do_connect(&conn);
  retval = do_get(&conn);

  while ((resp.reason == 301 || resp.reason == 302 || resp.reason == 307)
	 && resp.location) {
    conn.uri = strdup(conn.response->location);
    cleanup(&conn, 0);
    write2f(" => got new location: %s\n", conn.uri);
    parseurl(&conn);

    do_connect(&conn);
    retval = do_get(&conn);
  }

  if (resp.reason != 200) {
    write2f(" => %s\n", resp.reasonstr);
    cleanup(&conn, CLEANUP_AND_UNLINK);
    _exit(1);
  }

  if (conn.verbosity) {
    double bitspersec = (conn.response->totallength * 8.0) / (conn.timer.elapsed / 1000.0);
    char *suffix = "";
    int bps, rem;

#define MBIT 1048576.0
#define KBIT 1024.0

    if (bitspersec > MBIT) {
      bitspersec /= MBIT;
      suffix = "M";
    } else if (bitspersec > KBIT) {
      bitspersec /= KBIT;
      suffix = "K";
    }
    bps = (int)bitspersec;
    rem = (int)((bitspersec - bps) * 10);

    if (conn.outfile)
      write2f("%s%d bytes (%d bytes total) written to \"%s\"\n",
	      MOVE_CURSOR_LEFT, conn.response->bodylength,
	      conn.response->totallength, conn.outfile);

    write2f
	(" - connect time: %d ms\n - total time:   %d ms\n - throughput:   %d.%d %sb/s\n",
	 conn.connect_timer.elapsed, conn.timer.elapsed, bps, rem, suffix);
  }

  cleanup(&conn, 1);
  _exit(0);
}

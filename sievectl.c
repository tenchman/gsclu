#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef __dietlibc__
#include <strings.h>  /* strcasecmp */
#endif
#include <ctype.h>
#include <poll.h>
#include <sys/socket.h>
#include <polarssl/ssl.h>
#include <polarssl/base64.h>
#include <polarssl/havege.h>
#include <polarssl/error.h>
#include <polarssl/net.h>
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "tio.h"

#define PACKAGE "sievectl"
#define strequal(a,b) !strcmp(a,b)
#define strnequal(a,b,n) !strncmp(a,b,n)

/*
 * http://www.iana.org/assignments/sieve-extensions/sieve-extensions.xml
 *
 * envelope   :: http://tools.ietf.org/html/rfc5228
 * variables  :: http://tools.ietf.org/html/rfc5229
 * relational :: http://tools.ietf.org/html/rfc5231
**/

/*
 * For reference see:
 *    A Protocol for Remotely Managing Sieve Scripts
 *    http://tools.ietf.org/html/rfc5804
**/

static char iobuf[BUFSIZ];

typedef struct sv_ctx sievectx_t;
struct sv_ctx {
  char   *server;
  char   *account;  /* the account name */
  char   *user;	    /* username */
  char   *pass;	    /* password */
  char   *script;   /* script name */
  int     port;
  int     timeout;
  int     todo;	    /* command */
  int	  loggedin;
  io_ctx_t *io;
  struct {
    unsigned starttls:1;
    unsigned unauthenticate:1;
  } flags;
};

enum {
  /* commands without arguments */
  SV_CMD_LISTSCRIPTS = 1,
  /* commands which are requiring a script name */
  SV_CMD_DELETESCRIPT,
  SV_CMD_GETSCRIPT,
  SV_CMD_SETACTIVE,
  /* commands which are requiring a script name and reading from STDIN */
  SV_CMD_CHECKSCRIPT,
  SV_CMD_PUTSCRIPT
};

/* ======================================================================== */

/* Static Buffer! I know, I'm a bad guy.*/
int sv_parse_greeting(sievectx_t *ctx)
{
  int ret = -1;
  char *lbr, *pos = iobuf;

  if (-1 == (ret = tio_recv(ctx->io, iobuf, sizeof(iobuf)))) {
    fprintf(stderr, "%s: can't read response from server\n", __func__);
  } else {
    ret = 0;
    while (NULL != (lbr = strstr(pos, "\r\n"))) {
      int len = lbr - pos;
      if (strnequal(pos, "OK", 2) && isspace(pos[2])) {
	break;
      } else if (0 == strncasecmp(pos, "\"STARTTLS\"", len)) {
	ctx->flags.starttls = 1;
      } else if (0 == strncasecmp(pos, "\"UNAUTHENTICATE\"", len)) {
	ctx->flags.unauthenticate = 1;
      }
      /* fprintf(stderr, "-- %.*s\n", lbr - pos, pos); */
      /* advance to start of next line */
      pos = lbr + 2;
    }
  }
  return ret;
}

static int sv_expect(sievectx_t *ctx, const char *s)
{
  int ret = -1;
  memset(iobuf, 0, sizeof(iobuf));
  if (-1 == tio_recv(ctx->io, iobuf, sizeof(iobuf))) {
    /* */
  } else if (0 != strcasecmp(iobuf, s)) {
    /* */
  } else {
    ret = 0;
  }
  return ret;
}

static int sv_authenticate_plain(sievectx_t *ctx)
{
  unsigned char buf[BUFSIZ], *pos = buf;
  size_t dlen, n, len = snprintf(iobuf, sizeof(iobuf), "Authenticate \"PLAIN\" \"");
  int ret = -1;
 
  dlen = sizeof(iobuf) - len;
  memset(buf, 0, sizeof(buf));
  /* Account name + '\0' */
  n = strlen(ctx->account);
  memcpy(pos, ctx->account, n);
  pos += (n + 1);

  /* User name + '\0' */
  n = strlen(ctx->user);
  memcpy(pos, ctx->user, n);
  pos += (n + 1);

  /* Password */
  n = strlen(ctx->pass);
  memcpy(pos, ctx->pass, n);
  pos += n;

  base64_encode((unsigned char *)iobuf + len, &dlen, buf, pos - buf);
  len += dlen;
  len += snprintf(iobuf + len, sizeof(iobuf) - len, "\"\r\n");
  
  if (-1 == (ret = tio_send(ctx->io, iobuf, len))) {
    /* */
  } else if (-1 == (ret = sv_expect(ctx, "OK\r\n"))) {
    /* */
  } else {
    ctx->loggedin = 0;
  }

  return ret;
}

enum {
  SV_SUCCESS,
  SV_READ_ERROR,
  SV_PARSE_ERROR,
  SV_RESPONSE_NO
};

/* read and parse response from server
 *
 * returns:
 *    SV_SUCCESS ......: all fine
 *    SV_READ_ERROR ...: can't read from server
 *    SV_PARSE_ERROR ..: unexpected answer from server
 *    SV_RESPONSE_NO ..: got "NO" response
**/
static int sv_read_response(sievectx_t *ctx)
{
  int len, ret = -1;

  while (NULL != tio_gets(ctx->io, iobuf, sizeof(iobuf))) {
    if (strnequal(iobuf, "OK", 2)) {
      ret = SV_SUCCESS;
      break;
    } else if (strnequal(iobuf, "NO", 2)) {
      fputs(iobuf, stdout);
      ret = SV_RESPONSE_NO;
      break;
    } else if (1 == sscanf(iobuf, "{%d}\r\n", &len)) {
      /* nix */
    } else {
      fputs(iobuf, stdout);
    }
  }
  return ret;
}

/*
 * PUTSCRIPT / CHECKSCRIPT
 *
 * Answers:
 *   OK :: Jippy!
 *   OK (WARNINGS) "LF without preceding CR not allowed" :: Not so Jippy, but OK
 *   NO ... :: Absolutely no "Jippy"
**/
static int sv_do_script(sievectx_t *ctx, char *command)
{
  char buf[BUFSIZ], intro[128];
  int buflen, started = 0, introlen;

  while (0 < (buflen = read(0, buf, sizeof(buf)))) {
    if (started) {
      /* literal-c2s */
      introlen = snprintf(intro, sizeof(intro), "{%d+}\r\n", buflen);
    } else {
      /* command + script name + literal-c2s */
      introlen = snprintf(intro, sizeof(intro), "%s \"%s\" {%d+}\r\n", command, ctx->script, buflen);
      started++;
    }
    tio_send(ctx->io, intro, introlen); 
    tio_send(ctx->io, buf, buflen); 
  }
  tio_send(ctx->io, "\r\n", 2); 
  return sv_read_response(ctx);
}

static int sv_command(sievectx_t *ctx, char *command)
{
  int ret;
  
  if (ctx->script)
    ret = snprintf(iobuf, sizeof(iobuf), "%s \"%s\"\r\n", command, ctx->script);
  else
    ret = snprintf(iobuf, sizeof(iobuf), "%s\r\n", command);
  
  if (-1 == (ret = tio_send(ctx->io, iobuf, ret))) {
    /* */
  } else {
    ret = sv_read_response(ctx);
  }
  return ret;

}

static int sv_starttls(sievectx_t *ctx)
{
  int ret;
  if (-1 == (ret = tio_send(ctx->io, "STARTTLS\r\n", 10))) {
    fprintf(stderr, "can't send STARTTLS\n");
  } else if (-1 == (ret = sv_expect(ctx, "OK\r\n"))) {
    fprintf(stderr, "unexpected answer after STARTTLS: %s\n", iobuf);
  } else if (-1 == (ret = tio_tls_handshake(ctx->io))) {
    fprintf(stderr, "SSL/TLS handshake failed\n");
  } else {
    ret = 0;
  } 
  return ret;
}

static int sv_connect(sievectx_t *ctx)
{
  int ret = -1;
  const unsigned char *pers = (const unsigned char *) "sievectl";

  if (-1 == net_connect(&ctx->io->fd, ctx->server, ctx->port)) {
    fprintf(stderr, "can't connect to server @ %s/%d\n",  ctx->server, ctx->port);
  } else if (-1 == sv_parse_greeting(ctx)) {
    fprintf(stderr, "failed to read or parse server greeting\n");
  } else if (0 == ctx->flags.starttls) {
    ret = 0;
  } else if (-1 == tio_tls_init(ctx->io, pers, ctx->server)) {
    fprintf(stderr, "failed to initialize TLS\n");  
  } else if (-1 == sv_starttls(ctx)) {
    fprintf(stderr, "failed to start TLS session\n");
  } else {
    ret = 0;
  }
  return ret;
}

void sv_shutdown(sievectx_t *ctx)
{
  if (ctx->loggedin) {
    tio_send(ctx->io, "LOGOUT\r\n", 8);
    sv_expect(ctx, "OK\r\n");
    ctx->loggedin = 0;
  }
  tio_shutdown(ctx->io);
}

void sv_init(sievectx_t *ctx)
{
  memset(ctx, 0, sizeof(sievectx_t));
  ctx->timeout = 10;
  ctx->port = 2000;
  ctx->io = tio_init();
}

void sv_usage(int status, char *message)
{
  if (message)
    fprintf(stderr, message);
  fprintf(stderr, "Usage: %s [ options ] command [ name ]\n", PACKAGE);
  fprintf(stderr, "\
Options:\n\
  -s <server>   Server to operate on\n\
  -p <port>     Port to connect to\n\
  -a <account>  Accountname\n\
  -u <user>     Username\n\
  -w <pass>     passWord\n\
  -v            Display the version number.\n\
Commands:\n\
  get           get script from server\n\
  check         check script on server.\n\
  put		submit script to the server.\n\
  ls		list the scripts on the server\n\
  rm		remove script from server\n\
  set   	set a script active\n");
  exit(status);
}

int sv_parsecommand(char *cmd)
{
  int ret = -1;

  if (0 == strcmp(cmd, "ls")) {
    ret = SV_CMD_LISTSCRIPTS;
  } else if (0 == strcmp(cmd, "get")) {
    ret = SV_CMD_GETSCRIPT;
  } else if (0 == strcmp(cmd, "put")) {
    ret = SV_CMD_PUTSCRIPT;
  } else if (0 == strcmp(cmd, "rm")) {
    ret = SV_CMD_DELETESCRIPT;
  } else if (0 == strcmp(cmd, "check")) {
    ret = SV_CMD_CHECKSCRIPT;
  } else if (0 == strcmp(cmd, "set")) {
    ret = SV_CMD_SETACTIVE;
  }
  return ret;
}

int main(int argc, char **argv)
{
  sievectx_t ctx = { 0 };
  int optch;

  sv_init(&ctx);

  while (EOF != (optch = getopt(argc, argv, "a:s:p:u:w:v"))) {
    switch (optch) {
      case 'a':
	ctx.account = optarg;
	break;
      case 's':
	ctx.server = optarg;
	break;
      case 'p':
	ctx.port = atoi(optarg);
	break;
      case 'u':
	ctx.user = optarg;
	break;
      case 'w':
	ctx.pass = optarg;
	break;
      case 'v':
	puts("\n sievectl (" VERSION ")\n");
	return EXIT_SUCCESS;
      default:
	sv_usage(EXIT_SUCCESS, NULL);
    }
  }
  
  if (NULL == ctx.server)
    sv_usage(EXIT_FAILURE, "Missing server name\n\n");
  if (NULL == ctx.account)
    sv_usage(EXIT_FAILURE, "Missing account name\n\n");
  if (NULL == ctx.pass)
    sv_usage(EXIT_FAILURE, "Missing password\n\n");

  /* use account as username */
  if (NULL == ctx.user)
    ctx.user = ctx.account;

  argc -= optind;
  argv += optind;

  if (NULL == *argv)
    sv_usage(EXIT_FAILURE, "Missing command\n\n");
  
  if (0 >= (ctx.todo = sv_parsecommand(*argv++)))
    sv_usage(EXIT_FAILURE, "Unknown command\n\n");

  if (SV_CMD_LISTSCRIPTS != ctx.todo && argc == 1)
    sv_usage(EXIT_FAILURE, "Missing script name\n\n");
  else
    ctx.script = *argv;

  if (-1 == sv_connect(&ctx)) {
    fprintf(stderr, "can't connect\n");
  } else if (-1 == sv_authenticate_plain(&ctx)) {
    fprintf(stderr, "authentication failed\n");
  } else switch (ctx.todo) {
    /* commands without arguments */
    case SV_CMD_LISTSCRIPTS:
      ctx.script = NULL;
      sv_command(&ctx, "LISTSCRIPTS");
      break;
    /* commands which are requiring a script name */
    case SV_CMD_GETSCRIPT:
      sv_command(&ctx, "GETSCRIPT");
      break;
    case SV_CMD_DELETESCRIPT:
      sv_command(&ctx, "DELETESCRIPT");
      break;
    case SV_CMD_SETACTIVE:
      sv_command(&ctx, "SETACTIVE");
      break;
    /* commands which are requiring a script name and reading from STDIN */
    case SV_CMD_PUTSCRIPT:
      sv_do_script(&ctx, "PUTSCRIPT");
      break;
    case SV_CMD_CHECKSCRIPT:
      sv_do_script(&ctx, "CHECKSCRIPT");
      break;
    default:
      fputs("Hier stümmt doch wat nich. Dit Kommando kenn ick nich!", stderr);
  }

  sv_shutdown(&ctx);
  return 0;
}

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
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
  char    fd;       /* local file descriptor (get, put, check) */
  int     port;
  int     timeout;
  int     todo;	    /* command */
  int	  loggedin;
  io_ctx_t *io;
  struct {
    unsigned dostarttls:1;
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

static void die(sievectx_t *ctx, const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
  exit(EXIT_FAILURE);
}

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
	ctx->flags.starttls = ctx->flags.dostarttls;
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
  int len, ret = -1;
  int slen = strlen(s);
  memset(&iobuf, 0, sizeof(iobuf));
  if (-1 == (len = tio_recv(ctx->io, iobuf, sizeof(iobuf)))) {
    fprintf(stderr, "%s: tio_recv failed\n", __func__);
  } else if (0 != strncasecmp(iobuf + len - slen, s, slen)) {
    fprintf(stderr, "%s: unexpected answer; '%s'", __func__, iobuf);
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
    fprintf(stderr, "%s: tio_send failed\n", __func__);
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
  char cmd[128];
  int r, cmdlen, buflen = 0;

  if (0 < ctx->fd) {
    /*
     * Read script from already opened file descriptor
    **/
    struct stat st;
    char buf[BUFSIZ];
    if (-1 == fstat(ctx->fd, &st)) {
      die(ctx, "%s: stat failed\n", __func__);
    } else if (0 == st.st_size) {
      die(ctx, "%s: zero sized script\n", __func__);
    }
    /* command + script name + literal-c2s */
    cmdlen = snprintf(cmd, sizeof(cmd), "%s \"%s\" {%zu+}\r\n", command, ctx->script, (size_t)st.st_size);
    tio_send(ctx->io, cmd, cmdlen);
    while (0 < (r = read(ctx->fd, buf, BUFSIZ)))
      tio_send(ctx->io, buf, r);
    tio_send(ctx->io, "\r\n", 2);
  } else {
    /*
     * Read script from stdin
     *
     * We need to read the whole script into memory to calculate its
     * size before sending it to the server.
    **/
    char *buf, *pos;
    buf = pos = malloc(BUFSIZ);
    while (0 < (r = read(0, pos, BUFSIZ))) {
      buflen += r;
      if (NULL == (buf = realloc(buf, buflen + BUFSIZ)))
	die(ctx, "%s: out of memory\n", __func__);
      pos = buf + buflen;
    }
    /* command + script name + literal-c2s */
    cmdlen = snprintf(cmd, sizeof(cmd), "%s \"%s\" {%d+}\r\n", command, ctx->script, buflen);
    tio_send(ctx->io, cmd, cmdlen);
    tio_send(ctx->io, buf, buflen);
    tio_send(ctx->io, "\r\n", 2);
    free(buf);
  }
  return sv_read_response(ctx);
}

/*
 * send a simple command to the server and read its response
**/
static int sv_command(sievectx_t *ctx, char *command)
{
  int ret;

  if (ctx->script)
    ret = snprintf(iobuf, sizeof(iobuf), "%s \"%s\"\r\n", command, ctx->script);
  else
    ret = snprintf(iobuf, sizeof(iobuf), "%s\r\n", command);

  if (-1 == (ret = tio_send(ctx->io, iobuf, ret))) {
    fprintf(stderr, "%s: tio_send failed\n", __func__);
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

void sv_openlocalfile(sievectx_t *ctx, const char *filename)
{
  char *mode;
  int flags;

  switch (ctx->todo) {
    case SV_CMD_PUTSCRIPT:
    case SV_CMD_CHECKSCRIPT:
      flags = O_RDONLY;
      mode = "reading";
      break;
    case SV_CMD_GETSCRIPT:
      flags = O_CREAT|O_WRONLY|O_TRUNC;
      mode = "writing";
      break;
    default:
      /* ignore filename param, TODO: print warning? */
      return;
  }

  if (-1 == (ctx->fd = open(filename, flags, S_IRWXU)))
    die(ctx, "ERROR: can't open '%s' for %s: %s\n", filename, mode, strerror(errno));
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

static void process_entry(char *s, sievectx_t *ctx)
{
  char *key = NULL, *value = NULL;
  int n;
  if (2 == (n = sscanf(s, "%ms %ms", &key, &value))) {
    if (strequal("server", key)) {
      ctx->server = value;
    } else if (strequal("port", key)) {
      ctx->port = strtol(value, NULL, 10);
      free(value);
    } else if (strequal("user", key)) {
      ctx->user = value;
    } else if (strequal("account", key)) {
      ctx->account = value;
    } else if (strequal("password", key)) {
      ctx->pass = value;
    }
  }
  free(key);
}

static int readconfig(char *path, sievectx_t *ctx)
{
  FILE *fp;
  char buf[BUFSIZ];
  if (0 < (fp = fopen(path, "r"))) {
    fprintf(stderr, "using %s\n", path);
    while (fgets(buf, sizeof(buf), fp)) {
      process_entry(buf, ctx);
    }
    fclose(fp);
  }
  return -1;
}

void sv_init(sievectx_t *ctx)
{
  char *home, path[PATH_MAX];
  memset(ctx, 0, sizeof(sievectx_t));
  ctx->timeout = 10;
  ctx->port = 2000;
  ctx->io = tio_init();
  if (NULL != (home = getenv("HOME"))) {
    snprintf(path, PATH_MAX, "%s/.config/sievectl/sievectl.conf", home);
    if (0 == readconfig(path, ctx))
      return;
  }
  readconfig("/etc/sievectl/sievectl.conf", ctx);
}

void sv_usage(int status, char *message)
{
  if (message)
    fputs(message, stderr);
  fprintf(stderr, "Usage: "PACKAGE" [ options ] command [ name ]\n\n");
  fprintf(stderr, "\
Options:\n\
  -s <server>   Server to operate on\n\
  -p <port>     Port to connect to\n\
  -a <account>  Accountname\n\
  -u <user>     Username\n\
  -w <pass>     passWord\n\
  -n <name>     local fileName (get, put, check)\n\
  -t            use STARTTLS if supported\n\
  -v            Display the version number.\n\n\
Commands:\n\
  get           get script from server\n\
  check         check script on server.\n\
  put           submit script to the server.\n\
  ls            list the scripts on the server\n\
  rm            remove script from server\n\
  set           set a script active\n");
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
  char *filename = NULL;

  if (1 == argc)
    sv_usage(EXIT_SUCCESS, NULL);

  sv_init(&ctx);

  while (EOF != (optch = getopt(argc, argv, "a:n:s:p:u:w:vt"))) {
    switch (optch) {
      case 'a':
	ctx.account = optarg;
	break;
      case 's':
	ctx.server = optarg;
	break;
      case 'n':
	filename = optarg;
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
      case 't':
	ctx.flags.dostarttls = 1;
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

  /* try to open local file for writing (get) or
   * reading (put, check) */
  if (filename)
    sv_openlocalfile(&ctx, filename);
  else
    ctx.fd = -1;

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
      fputs("unknown command", stderr);
  }

  sv_shutdown(&ctx);
  return 0;
}

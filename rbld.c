#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/un.h>		/* struct sockaddr_un */
#include <sys/poll.h>		/* poll(2) */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <setjmp.h>
#include <fcntl.h>
#include <signal.h>		/* kill(2) */
#include <errno.h>		/* ESRCH */
#include "mmapfile.h"

#define RESULTMAX	0xFE
#define REVISITTIMEOUT  5 * 60	/* 5 minutes */
#define MAXFAILURES	5	/* how many tries before we consider a rbldomain is dead */
#define QUERY_TIMEOUT	15
#define DOMAINCFG	"/etc/rbldomains"
#define PIDFILE		"/var/run/rbld.pid"
#define SOCKETPATH	"/tmp/.rbldsock"
#define writeconst(msg) write(2, msg, sizeof(msg) - 1)

#ifndef NULL
#define NULL (char *)0
#endif

/* ripped from bind 8.x sources */
#ifndef NS_INT16SZ
#define NS_INT16SZ 2
#endif

#ifndef NS_INT32SZ
#define NS_INT32SZ 4
#endif

#ifndef NS_GET16
#define NS_GET16(s, cp) { \
  register unsigned char *t_cp = (unsigned char *)(cp); \
  (s) = ((unsigned short)t_cp[0] << 8) \
      | ((unsigned short)t_cp[1]); \
  (cp) += NS_INT16SZ; \
}
#endif

typedef struct rbldomain_t {
  uint8_t failcount;
  time_t lastsuccess;
  size_t len;
  char name[];
} rbldomain_t;

typedef struct {
  char *domaincfg;
  char *socketpath;
  char *pidfile;
  void *rbldomains;
  time_t timestamp;
  int clientfd;
  int serverfd;
} config_t;

static int signaled;
static jmp_buf env;

static void die(char *msg)
{
  write(2, msg, strlen(msg));
  write(2, "\n", 1);
  exit(EXIT_FAILURE);
}

static void sigalarm(int signal)
{
  longjmp(env, signal);
}

static void cleanup(int signal)
{
  signaled = 1;
}

static void write_errno(char *msg)
{
  char *err = strerror(errno);
  write(2, msg, strlen(msg));
  write(2, ": ", 2);
  write(2, err, strlen(err));
  write(2, "\n", 1);
}

static void die_errno(char *msg)
{
  write_errno(msg);
  exit(EXIT_FAILURE);
}

/* DJB's public domain fmt_ulong. */
unsigned int fmt_ulong(register char *s, register unsigned long u)
{
  register unsigned int len;
  register unsigned long q;
  len = 1;
  q = u;
  while (q > 9) {
    ++len;
    q /= 10;
  }
  if (s) {
    s += len;
    do {
      *--s = '0' + (u % 10);
      u /= 10;
    } while (u);		/* handles u == 0 */
  }
  return len;
}

/* write our pid to a file
 *
 * return:
 *  a:
 *    the pid of the currently running process if the file exists and
 *    contains a pid which we can signal via kill(pid, 0)
 *  b:
 *    0 on success or when the file exists but is stale
 *  c:
 *    -1 on any error
**/
static int writepid(config_t * c)
{
  int fd, ret;
  char buf[48];
  if ((fd = open(c->pidfile, O_RDWR | O_CREAT)) == -1)
    return -1;

  if (read(fd, buf, sizeof(buf)) > 0) {
    int pid = strtol(buf, NULL, 10);
    ret = kill(pid, 0);

    if (ret == 0 || (ret == -1 && errno != ESRCH)) {
      close(fd);
      return pid;
    }
  }

  ret = fmt_ulong(buf, (unsigned long) getpid());
  write(fd, buf, ret);
  close(fd);
  return 0;
}

static int read_rbldomains(config_t * c)
{
  char dombuf[1024];
  rbldomain_t *dom = NULL;
  char *dombufpos = dombuf;
  char *buf, *tmp;
  struct stat st;

  if ((buf = tmp = mmapfile(c->domaincfg, &st)) == NULL)
    return -1;

  while (tmp < buf + st.st_size) {
    size_t n = strcspn(tmp, "\r\n");
    if (!n)
      n = buf + st.st_size - tmp;
    dom = (rbldomain_t *) dombufpos;
    dom->failcount = 0;
    dom->lastsuccess = time(NULL);
    dom->len = n;
    strncpy(dom->name, tmp, n);
    dombufpos = dom->name + n;
    tmp += n;
    while (*tmp == '\n' || *tmp == '\r')
      ++tmp;
  }
  if (dom) {
    char *r = realloc(c->rbldomains, dombufpos - dombuf);
    if (!r) {
      munmap(buf, st.st_size);
      return -1;
    }
    memcpy(r, dombuf, dombufpos - dombuf);
    c->rbldomains = r;
  }
  c->timestamp = st.st_mtime;
  munmap(buf, st.st_size);
  return 0;
}

static char *rblcheck(struct in_addr *in, rbldomain_t * dom)
{
  unsigned char fixedans[PACKETSZ];
  unsigned char *answer = fixedans;
  unsigned char *cp;
  char *result = (char *) 0;
  char domain[dom->len + 17];	/* dotted-quad address + dom->len + 1 for null */
  int len, packetsz = PACKETSZ, type = T_A;
  time_t now = time(NULL);

  if (dom->failcount >= MAXFAILURES
      && (now - dom->lastsuccess) < REVISITTIMEOUT)
    return NULL;

  if (setjmp(env) == SIGALRM) {
    writeconst("timeout querying ");
    write(2, dom->name, dom->len);
    writeconst("\n");
    dom->failcount++;
    return NULL;
  }

  strcpy(domain, (const char *) inet_ntoa(*in));
  strncat(domain, ".", 1);
  strncat(domain, dom->name, dom->len);

tryagain:

  /* perform the DNS query. */
  alarm(QUERY_TIMEOUT);
  len = res_query(domain, C_IN, type, answer, packetsz);
  alarm(0);

  /* even if got an error, the query itself was successful (i.e. not timed out) */
  dom->lastsuccess = now;
  dom->failcount = 0;

  if (len == -1)
    return result;

  /* try again with a greater buffer */
  if (len > packetsz) {
    answer = malloc(len);
    packetsz = len;
    goto tryagain;
  }

  /* OK, we got an answer so the host is listed, we
     make another DNS query for textual data */
  if (type == T_A) {
    result = malloc(RESULTMAX + 1);
    result[0] = result[RESULTMAX] = '\0';
    type = T_TXT;
    goto tryagain;
  }

  /* Skip header */
  cp = answer + sizeof(HEADER);
  /* Skip question name */
  cp += dn_skipname(cp, answer + len);
  /* Skip QTYPE and QCLASS */
  cp += NS_INT16SZ + NS_INT16SZ;
  /* Skip answer name */
  cp += dn_skipname(cp, answer + len);
  /* Skip TYPE, CLASS and TTL */
  cp += NS_INT16SZ + NS_INT16SZ + NS_INT32SZ;
  /* Get the length of the buffer. */
  NS_GET16(len, cp);

  if (len) {
    /* We read only the first TXT record for now. */
    if ((len = (int) *cp++) > RESULTMAX)
      len = RESULTMAX;
    strncpy(result, (char *) cp, len);
    result[len] = '\0';
  }

  /* free answer if it was malloced */
  if (answer != fixedans)
    free(answer);

  return result;
}

int query(struct in_addr *in, config_t * c)
{
  void *ptr = c->rbldomains;
  rbldomain_t *dom = (rbldomain_t *) ptr;
  pid_t child;

  while (*dom->name) {
    pid_t pid = fork();
    switch (pid) {
    case -1:
      break;
    case 0:{
	char *result;
	if ((result = rblcheck(in, dom))) {
	  char outbuf[strlen(result) + 4 + dom->len];
	  strcpy(outbuf, dom->name);
	  strcat(outbuf, ": ");
	  strcat(outbuf, result);
	  strcat(outbuf, "\n");
	  write(c->clientfd, outbuf, sizeof(outbuf));
	}
      }
      exit(EXIT_SUCCESS);
    default:
      ;
    }
    ptr += sizeof(rbldomain_t) + dom->len;
    dom = (rbldomain_t *) ptr;
  };

  do {
    child = waitpid(-1, NULL, 0);
  } while (child != -1);

  return 0;
}

int listener(config_t * c)
{
  pid_t pid;
  struct sockaddr_un server;
  int sfd, cfd;

  _res.options &= ~RES_RECURSE;
  umask(0111);
  /*
     res_init();
     _res.options &= ~RES_RECURSE;
   */

  /* just in case ... */
  if (unlink(c->socketpath) == -1 && errno != ENOENT)
    die_errno("can't unlink " SOCKETPATH);

  memset((char *) &server, 0, sizeof(server));
  server.sun_family = AF_UNIX;
  strncpy(server.sun_path, c->socketpath, sizeof(server.sun_path));

  if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    die_errno("error creating listener socket");

  if (bind(sfd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) == -1) {
    close(sfd);
    die_errno("can't bind to socket");
  }

  if (listen(sfd, 10) == -1) {
    close(sfd);
    die_errno("can't listen to socket");
  }

  signal(SIGTERM, cleanup);
  signal(SIGINT, cleanup);
  signal(SIGALRM, sigalarm);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  c->serverfd = sfd;

  /* listener loop */
  while (!signaled) {
    struct stat st;
    struct pollfd pfd;

    if (stat(c->domaincfg, &st) == -1) {
      /* continue with old domain list */
      write_errno("can't stat " DOMAINCFG);
    } else if (st.st_mtime > c->timestamp) {
      writeconst("rereading " DOMAINCFG "\n");
      read_rbldomains(c);
    }

    pfd.fd = sfd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    poll(&pfd, 1, -1);

    if ((pfd.revents & POLLIN) != 0) {

      if ((cfd = accept(sfd, NULL, NULL)) == -1) {
	write_errno("accept failed");
	continue;
      }

      pid = fork();
      switch (pid) {
      case -1:
	return -1;
      case 0:{
	  struct in_addr inaddr;
	  char buf[256];
	  int retval;

	  close(sfd);
	  c->clientfd = cfd;

	  if ((retval = read(cfd, buf, sizeof(buf))) == -1)
	    die_errno("can't read from socket");

	  if (inet_aton(buf, &inaddr) == 0)
	    die("invalid ip address");

	  inaddr.s_addr = htonl(inaddr.s_addr);
	  retval = query(&inaddr, c);
	  write(cfd, "", 1);
	  close(cfd);
	  exit(retval);
	}
      default:
	waitpid(pid, NULL, 0);
      }
    }
  }
  return 0;
}

int main(int argc, char **argv)
{
  config_t config = {
    .domaincfg = DOMAINCFG,
    .socketpath = SOCKETPATH,
    .pidfile = PIDFILE,
    .rbldomains = NULL,
    .serverfd = -1
  };

  switch (writepid(&config)) {
  case -1:
    die_errno("can't write pid file");
  case 0:
    break;
  default:
    die("I'm already running!");
  }

  if (read_rbldomains(&config) == -1)
    die("can't read " DOMAINCFG);

  listener(&config);

  if (config.serverfd != -1)
    close(config.serverfd);

  unlink(config.pidfile);
  unlink(config.socketpath);

  return 0;
}

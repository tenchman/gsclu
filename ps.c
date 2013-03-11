/* $Id: ps.c 72 2009-05-29 09:02:35Z gernot $ */

#define _GNU_SOURCE
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <termios.h>		/* struct winsize */
#include <sys/ioctl.h>		/* TIOCGWINSZ */
#include <sys/param.h>
#include <pwd.h>
#include "attributes.h"
#include "read_write.h"

#define PROC_WITH_TTY	  1<<0
#define PROC_WITHOUT_TTY  1<<1
#define PROC_OTHER_USERS  1<<2
#define PROC_WITH_ARGS	  1<<3
#define PROC_USER_FMT	  1<<4
#define PROC_FULL_WIDTH	  1<<5
#define PROC_FOREST	  1<<6
#define PROC_ALL	  PROC_WITH_TTY|PROC_WITHOUT_TTY|PROC_OTHER_USERS
#define UHEADER	"USER       PID %CPU %MEM   VSZ  RSS TTY      STAT START   TIME COMMAND"

#define BUFSIZE 1024

#define ull unsigned long long

typedef struct ps_dev_t {
  int major;
  int first;
  int last;
  char *name;
} ps_dev_t;

ps_dev_t *devlist;
int devcnt;
int hertz = 0;

typedef struct proc_t proc_t;
struct proc_t {
  unsigned long uid;
  int pid;
  char *name;
  char *args;
  char *pad;
  char state;
  int ppid;
  int pgrp;
  int session;
  int tty;
  int tpgid;
#ifdef MORE_THAN_WE_NEED
  unsigned long flags;
  unsigned long min_flt;
  unsigned long cmin_flt;
  unsigned long maj_flt;
  unsigned long cmaj_flt;
#endif
  ull utime;
  ull stime;
#ifdef MORE_THAN_WE_NEED
  ull cutime;
  ull cstime;
  long priority;
#endif
  long nice;
  int nlwp;			/* number of threads, or 0 if no clue */
  long alarm;
  time_t start_time;
  unsigned long vsize;
  long rss;
#ifdef MORE_THAN_WE_NEED
  unsigned long rss_rlim;
  ull start_code;
  ull end_code;
  ull start_stack;
  ull kstk_esp;
  ull kstk_eip;
  ull wchan;
  unsigned long nswap;
  unsigned long cnswap;
  int exit_signal;
  int processor;
  unsigned long rtprio;
  unsigned long sched;
  unsigned long vm_size;
#endif
  unsigned long vm_lock;
#ifdef MORE_THAN_WE_NEED
  unsigned long vm_rss;
  unsigned long vm_data;
  unsigned long vm_stack;
  unsigned long vm_exe;
  unsigned long vm_lib;
#endif
  proc_t *next;
  proc_t *last;
};

proc_t *processes = NULL;
proc_t *last = NULL;

char buffer[BUFSIZE];
char buf2[BUFSIZE];

time_t boot_time;
time_t seconds_since_boot;
time_t seconds_since_1970;
ull kb_main_total;
int screen_width = 80;
int total_width = 80;
uid_t my_uid;
int my_tty;

/* write at most 'max' characters to STDOUT */
REGPARM(2)
int write_stdout(char *str, char *end)
{
  int len;
  len = end - str;
  if (total_width && len > total_width)
    len = total_width;
  str[len] = '\n';
  len = write(1, str, len + 1);
  return len;
}

REGPARM(2)
static int write_two_digits(char *s, int val)
{
  *s++ = val / 10 + '0';
  *s++ = val % 10 + '0';
  return 2;
}

/**
 * write a formatted timestring (5 chars) to 's'
 * the format is as follows:
 *    hh:mm - 23:01 or
 *    MMMDD - Sep01
 * Return value is 5 in any case
**/
REGPARM(3)
static int write_start_time(char *s, char *e, time_t val)
{
  char month[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
  time_t t = val / hertz + boot_time;
  struct tm timestruct;
  struct tm *tm = &timestruct;

  tm = localtime((time_t *) & t);

  if ((seconds_since_1970 - t) > 86400) {
    writestring(s, e, month + tm->tm_mon * 3, 3);
    /* misuse of tm->tm_min */
    tm->tm_min = tm->tm_mday;
  } else {
    write_two_digits(s, tm->tm_hour);
    *(s + 2) = ':';
  }
  write_two_digits(s + 3, tm->tm_min);
  return 5;
}

REGPARM(3)
static int write_percent(char *s, char *e, unsigned int p)
{
  if (p > 999U)
    p = 999U;
  if (p > 99U) {
    *s++ = p / 100 + '0';
    p %= 100;
  } else
    *s++ = ' ';
  *s++ = p / 10 + '0';
  *s++ = '.';
  *s++ = p % 10 + '0';
  return 4;
}

REGPARM(3)
static int write_ptime(char *s, char *e, proc_t * P, int full)
{
  unsigned long t = (P->utime + P->stime) / hertz;
  unsigned hh, mm, ss, len = 0;
  ss = t % 60;
  t /= 60;
  mm = t % 60;
  t /= 60;
  hh = t % 24;
  t /= 24;
  if (full) {
    len += write_two_digits(s + len, hh);
    s[len++] = ':';
    len += write_two_digits(s + len, mm);
  } else {
    mm += hh * 60;
    len += writeulonglong(s + len, e, (ull) mm, 3, RIGHT);
  }
  s[len++] = ':';
  len += write_two_digits(s + len, ss);
  return len;
}

/* format %CPU */
REGPARM(3)
static int write_pcpu(char *s, char *e, proc_t * P)
{
  ull total_time;		/* jiffies used by this process */
  unsigned pcpu = 0;		/* scaled %cpu, 999 means 99.9% */
  ull seconds;			/* seconds of process life */
  total_time = P->utime + P->stime;
  seconds = seconds_since_boot - P->start_time / hertz;
  if (seconds)
    pcpu = (total_time * 1000ULL / hertz) / seconds;
  return write_percent(s, e, pcpu);
}

/* format %MEM */
REGPARM(3)
static int write_pmem(char *s, char *e, proc_t * P)
{
  unsigned long pmem = 0;
  pmem = P->rss * 4000ULL / kb_main_total;
  return write_percent(s, e, pmem);
}

REGPARM(3)
static int write_stat(char *s, char *e, proc_t * P)
{
  int len = 0;

  s[len++] = P->state;
  /* 1. nice */
  if (P->nice < 0)
    s[len++] = '<';
  else if (P->nice > 0)
    s[len++] = 'N';

  /* 2. locked */
  if (P->vm_lock)
    s[len++] = 'L';

  /* 3. session leader */
  if (P->session == P->pid)	/* FIXME: should P->tgid */
    s[len++] = 's';

  /* 4. multi-threaded */
  if (P->nlwp > 1)
    s[len++] = 'l';

  /* 5. in foreground process group */
  if (P->pgrp == P->tpgid)
    s[len++] = '+';

  while (len < 4)
    s[len++] = ' ';

  return len;
}

REGPARM(3)
static int write_pad(char *s, char *e, int pad)
{
  char *tmp = s;
  if (pad) {
    while (--pad)
      tmp += writestring(tmp, e, "    ", 0);
    tmp += writestring(tmp, e, " \\_ ", 0);
  }
  return tmp - s;
}

/*
 * @param s - start of buffer to write to
 * @param e - end of buffer to write to
 * @param tty - tty number
**/
REGPARM(3)
static int write_tty(char *s, char *e, int tty)
{
  int major, minor;
  int i;
  char buf[16];
  char *tmp = buf;
  char *ttname = NULL;

  if (!tty)
    return writestring(s, e, "?", 8);

  minor = (((unsigned) tty & 0xffu) | (((unsigned) tty & 0xfff00000u) >> 12u));
  major = ((unsigned) tty >> 8u) & 0xfffu;
  for (i = 0; i < devcnt; i++) {
    if (devlist[i].major == major &&
	devlist[i].first <= minor && devlist[i].last >= minor) {
      ttname = devlist[i].name;
      if (devlist[i].first > 1)
	minor -= devlist[i].first;
      break;
    }
  }
  if (ttname)
    tmp += writestring(tmp, tmp + 15, ttname, 0);
  else
    *tmp++ = '?';
  tmp += writeulonglong(tmp, e, (ull) minor, 1, LEFT);
  *tmp = '\0';
  return writestring(s, e, buf, 8);
}

/* hardcoded format needed by snmpd(8) */
REGPARM(2)
static int write_format_e(proc_t * P, int pad)
{
  char *buf = buffer;
  char *end = buffer + BUFSIZE - 1;

  buf += writeulonglong(buf, end, (ull) P->pid, 5, RIGHT);
  *buf++ = ' ';
  buf += write_tty(buf, end, P->tty);
  *buf++ = ' ';
  buf += write_ptime(buf, end, P, 1);
  *buf++ = ' ';
  buf += write_pad(buf, end, pad);
  buf += writestring(buf, end, P->name, 0);

  return write_stdout(buffer, buf);
}

REGPARM(2)
static int write_process_info(proc_t * P, int pad)
{
  char *buf = buffer;
  char *end = buffer + BUFSIZE - 1;
  struct passwd *passwd;

  passwd = getpwuid(P->uid);

  buf += writestring(buf, end, passwd->pw_name, 8);
  *buf++ = ' ';
  buf += writeulonglong(buf, end, (ull) P->pid, 5, RIGHT);
  *buf++ = ' ';
  buf += write_pcpu(buf, end, P);
  *buf++ = ' ';
  buf += write_pmem(buf, end, P);
  *buf++ = ' ';
  buf += writeulonglong(buf, end, (ull) P->vsize / 1024, 6, RIGHT);
  *buf++ = ' ';
  /* RSS */
  buf += writeulonglong(buf, end, (ull) P->rss * 4, 5, RIGHT);
  *buf++ = ' ';
  /* TTY */
  buf += write_tty(buf, end, P->tty);
  buf = buffer + 44;
  *buf++ = ' ';
  /* STAT */
  buf += write_stat(buf, end, P);
  *buf++ = ' ';
  /* START */
  buf += write_start_time(buf, end, P->start_time);
  *buf++ = ' ';
  /* TIME */
  buf += write_ptime(buf, end, P, 0);
  *buf++ = ' ';
  buf += write_pad(buf, end, pad);
  /* COMMAND */
  buf += writestring(buf, end, P->name, 0);
  if (P->state == 'Z')
    buf += writestring(buf, end, " <defunct>", 0);

  return write_stdout(buffer, buf);
}

/**
 * read a file from /proc/pid/filename
**/
REGPARM(3)
static int read_proc_pid_XXX(char *buf, int buflen, char *pid, char *filename)
{
  char file[256] = "/proc/";
  int fd, retval;

  strcat(file, pid);
  strcat(file, "/");
  strcat(file, filename);
  if ((fd = open(file, O_RDONLY)) <= 0)
    return -1;

  retval = read(fd, buf, buflen - 1);
  close(fd);
  return retval;
}

static time_t read_boottime()
{
  int fd;
  char *buf = buffer;

  if ((fd = open("/proc/uptime", O_RDONLY)) <= 0)
    return 1;
  if ((read(fd, buf, BUFSIZE - 1) <= 0)) {
    close(fd);
    return 1;
  }
  close(fd);
  readlong(buf, &seconds_since_boot);
  time(&seconds_since_1970);
  return seconds_since_1970 - seconds_since_boot;
}

static int read_memtotal()
{
  int fd;
  char *buf = buffer;
  char *strbuf = buf2;
  if ((fd = open("/proc/meminfo", O_RDONLY)) <= 0)
    return 1;
  if ((read(fd, buf, BUFSIZE - 1) <= 0)) {
    close(fd);
    return 1;
  }
  close(fd);
  if ((buf = strstr(buf, "MemTotal"))) {
    buf += readstring(buf, &strbuf);
    readulonglong(buf, &kb_main_total);
  }
  return 0;
}

REGPARM(2)
static int read_process_status(proc_t * P, char *pid)
{
  char *buf = buffer;

  if ((read_proc_pid_XXX(buf, BUFSIZE, pid, "status") <= 0))
    return -1;
  if ((buf = strstr(buf, "Uid:"))) {
    buf += skip(buf, 2);
    buf += readulong(buf, &P->uid);
    if ((buf = strstr(buf, "\nVmLck:"))) {
      buf += 8;
      buf += readulong(buf, &P->vm_lock);
    }
  }
  return 0;
}


REGPARM(3)
static int read_process_stat(proc_t * P, char *pid, unsigned long flags)
{
  char *strbuf = buf2;
  char *buf = buffer;
  int len;

  if ((read_proc_pid_XXX(buf, BUFSIZE, pid, "stat") <= 0))
    return -1;

  buf += readint(buf, &P->pid);
  /* will be overwritten if /proc/#/cmdline is available */
  len = readprocname(buf, &strbuf);
  P->name = strndup(strbuf, len - 1);
  buf += len;
  buf += readchar(buf, &P->state);
  buf += readint(buf, &P->ppid);
  buf += readint(buf, &P->pgrp);	/* process group id */
  buf += readint(buf, &P->session);	/* session id */
  buf += readint(buf, &P->tty);	/* full device number of controlling terminal */


  buf += readint(buf, &P->tpgid);	/* terminal process group id */
#ifdef MORE_THAN_WE_NEED
  buf += readulong(buf, &P->flags);	/* kernel flags for the process */
  buf += readulong(buf, &P->min_flt);	/* number of minor page faults since process start */
  buf += readulong(buf, &P->cmin_flt);	/* cumulative min_flt of process and child processes */
  buf += readulong(buf, &P->maj_flt);	/* number of major page faults since process start */
  buf += readulong(buf, &P->cmaj_flt);	/* cumulative maj_flt of process and child processes */
#else
  buf += skip(buf, 5);
#endif
  buf += readulonglong(buf, &P->utime);	/* user-mode CPU time accumulated by process */
  buf += readulonglong(buf, &P->stime);	/* kernel-mode CPU time accumulated by process */
#ifdef MORE_THAN_WE_NEED
  buf += readulonglong(buf, &P->cutime);	/* cumulative utime of process and reaped children */
  buf += readulonglong(buf, &P->cstime);	/* cumulative stime of process and reaped children */
  buf += readlong(buf, &P->priority);	/* kernel scheduling priority */
#else
  buf += skip(buf, 3);
#endif
  buf += readlong(buf, &P->nice);	/* standard unix nice level of process */
  buf += readint(buf, &P->nlwp);
  buf += readlong(buf, &P->alarm);
  buf += readlong(buf, &P->start_time);	/* start time of process -- seconds since 1-1-70 */
  buf += readulong(buf, &P->vsize);	/* number of pages of virtual memory ... */
  buf += readlong(buf, &P->rss);	/* resident set size from /proc/#/stat (pages) */
#ifdef MORE_THAN_WE_NEED
  buf += readulong(buf, &P->rss_rlim);	/* resident set size limit? */
  buf += readulonglong(buf, &P->start_code);	/* address of beginning of code segment */
  buf += readulonglong(buf, &P->end_code);	/* address of end of code segment */
  buf += readulonglong(buf, &P->start_stack);	/* address of the bottom of stack for the process */
  buf += readulonglong(buf, &P->kstk_esp);	/* kernel stack pointer */
  buf += readulonglong(buf, &P->kstk_eip);	/* kernel instruction pointer */
  buf += readulonglong(buf, &P->wchan);	/* address of kernel wait channel proc is sleeping in */
  buf += readulong(buf, &P->nswap);	/* ? */
  buf += readulong(buf, &P->cnswap);	/* cumulative nswap? */
  buf += readint(buf, &P->exit_signal);	/* might not be SIGCHLD */
  buf += readint(buf, &P->processor);	/* current (or most recent?) CPU */
  buf += readulong(buf, &P->rtprio);	/* real-time priority */
  buf += readulong(buf, &P->sched);	/* scheduling class */
#endif
  return 0;
}

REGPARM(2)
static int read_process_info(proc_t * P, char *pid, unsigned long flags)
{
  int len;
  char *buf = buffer;

  if (read_process_status(P, pid) == -1)
    return -1;

  // if (!(flags & PROC_OTHER_USERS) && my_uid != P->uid) return 0;

  if (read_process_stat(P, pid, flags) == -1)
    return -1;

  /* read /proc/#/cmdline */
  buf = buffer;
  if ((len = read_proc_pid_XXX(buf, BUFSIZE, pid, "cmdline")) > 0) {
    buf[len--] = '\0';
    free(P->name);
    if (flags & PROC_WITH_ARGS) {
      while (len--)
	if (buf[len] == '\0')
	  buf[len] = ' ';
    } else {
      char *tmp = strrchr(buf, '/');
      if (tmp)
	buf = tmp + 1;
      if (*buf == '-')
	buf++;
    }
    P->name = strdup(buf);
  }

  return 0;
}

REGPARM(1)
static int read_process_list(unsigned long flags)
{
  DIR *dir;
  proc_t *P;
  if ((dir = opendir("/proc"))) {
    struct dirent *de;
    while ((de = readdir(dir))) {
      if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
	P = malloc(sizeof(proc_t));
	P->next = NULL;
	P->last = NULL;
	if (read_process_info(P, de->d_name, flags) == -1)
	  continue;
	if (!processes)
	  processes = P;
	if (last) {
	  P->last = last;
	  last->next = P;
	}
	last = P;
      }
    }
    closedir(dir);
  }
  return 0;
}

REGPARM(1)
proc_t *find_child(int pid)
{
  proc_t *P = processes;
  while (P) {
    if (P->pid && (pid == P->ppid))
      break;
    P = P->next;
  }
  return P;
}

REGPARM(1)
proc_t *find_pid(int pid)
{
  proc_t *P = processes;
  while (P) {
    if (P->pid && (pid == P->pid))
      break;
    P = P->next;
  }
  return P;
}

void forest(proc_t * P, unsigned long flags, int pad)
{
  while (P && P->pid) {
    int pid = P->pid;
    int ppid = P->ppid;

    if (flags & PROC_USER_FMT) {
      write_process_info(P, pad);
    } else {
      write_format_e(P, pad);
    }
    P->pid = 0;
    if (!P->ppid)
      break;			/* init */
    ++pad;
    P = find_child(pid);
    if (P)
      forest(P, flags, pad);
    --pad;
    P = find_child(ppid);
    if (P)
      forest(P, flags, pad);

  };
}

REGPARM(1)
static void show_process_list(unsigned long flags)
{
  proc_t *P = processes;
  int pad = 0;
  while (P) {
    if (flags & PROC_FOREST) {
      if (P->pid && (P->ppid <= 1)) {
	forest(P, flags, pad);
      }
    } else if (!(flags & PROC_OTHER_USERS) && my_uid != P->uid) {
      /* */
    } else if (!flags && P->tty != my_tty) {
      /* */
    } else if (!(flags & PROC_WITHOUT_TTY) && !P->tty) {
      /* */
    } else if (flags & PROC_USER_FMT) {
      write_process_info(P, pad);
    } else {
      write_format_e(P, 0);
    }
    P = P->next;
  }
}

/*
 * /dev/tty             /dev/tty        5       0 system:/dev/tty
 * /dev/console         /dev/console    5       1 system:console
 * /dev/ptmx            /dev/ptmx       5       2 system
 * /dev/vc/0            /dev/vc/0       4       0 system:vtmaster
 * serial               /dev/ttyS       4 64-95 serial
 * pty_slave            /dev/pts      136 0-1048575 pty:slave
 * pty_master           /dev/ptm      128 0-1048575 pty:master
 * unknown              /dev/tty        4 1-63 console
*/
int read_device_names(ps_dev_t * list)
{
  int i, len, num = 0;
  char *buf = buffer;

  if ((i = open("/proc/tty/drivers", O_RDONLY)) <= 0)
    return 1;
  if ((len = read(i, buf, BUFSIZE - 1)) <= 0) {
    close(i);
    return -1;
  }
  buf[len] = '\0';
  close(i);

  /* goto the first character device */
  while ((buf = strstr(buf, " /dev/"))) {
    char *strbuf = buf2;
    int major, first, last;

    buf += 6;
    buf += readstring(buf, &strbuf);
    buf += readint(buf, &major);
    /* first device minor */
    buf += readint(buf, &first);
    /* check for instance for 1-63 console */
    if (*buf == '-') {
      ++buf;
      buf += readint(buf, &last);
    } else
      last = first;

    if (list) {
      char *tmp = strstr(strbuf, "%d");
      if (tmp)
	*tmp = '\0';
      /* 136 ... 143 are /dev/pts/0, /dev/pts/1, /dev/pts/2 ... */
      if (major >= 136 && major <= 143)
	strcat(strbuf, "/");
      list[num].first = first;
      list[num].last = last;
      list[num].major = major;
      list[num].name = strdup(strbuf);
    }
    ++num;
  }
  return num;
}

#define PROC_HELP "ps [-e | aux]"

/*
 * -e all processes
 * a  all w/ tty, including other users
 * x  processes w/o controlling ttys
 * u  user-oriented
 * j  job control
 */
int main(int argc, char **argv)
{
  struct winsize win;
  int args = argc - 1;
  unsigned long flags = 0;
  proc_t P;

  if (ioctl(1, TIOCGWINSZ, &win) != -1 && win.ws_col > 0)
    total_width = screen_width = win.ws_col;

  hertz = sysconf(_SC_CLK_TCK);
  /* Jallaah!, Gernots very own getopt() */
  while (args) {
    while (*argv[args]) {
      switch (*argv[args]) {
      case '-':
	break;
      case 'a':
	flags |= PROC_WITH_TTY | PROC_OTHER_USERS | PROC_WITH_ARGS;
	break;
      case 'e':
	flags |= PROC_ALL;
	break;
      case 'x':
	flags |= PROC_WITH_TTY | PROC_WITHOUT_TTY | PROC_WITH_ARGS;
	break;
      case 'u':
	flags |= PROC_USER_FMT | PROC_WITH_ARGS;
	break;
      case 'f':
	flags |= PROC_FOREST;
	break;
      case 'w':
	total_width += screen_width;
      }
      argv[args]++;
    }
    args--;
  }

  if ((devcnt = read_device_names(NULL)) > 0) {
    devlist = malloc(devcnt * sizeof(ps_dev_t));
    read_device_names(devlist);
    read_process_stat(&P, "self", 0);
    my_tty = P.tty;
    my_uid = getuid();
    read_memtotal();
    boot_time = read_boottime();
    read_process_list(flags);
    show_process_list(flags);
  }

  exit(0);
}

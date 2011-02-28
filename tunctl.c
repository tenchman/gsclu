/* Copyright 2002 Jeff Dike
 * Licensed under the GPL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

void write1(char *s)
{
  write(2, s, strlen(s));
}

void write2(char *s)
{
  write(2, s, strlen(s));
}

static void Usage(void)
{
  write2
      ("Create: tunctl [-b] [-u owner] [-t device-name] [-f tun-clone-device]\n"
       "Delete: tunctl -d device-name [-f tun-clone-device]\n\n"
       "The default tun clone device is /dev/net/tun - some systems use\n"
       "/dev/misc/net/tun instead\n\n"
       "-b will result in brief output (just the device name)\n");
  exit(1);
}

int main(int argc, char **argv)
{
  struct ifreq ifr;
  struct passwd *pw;
  char *strowner = NULL;
  long owner = geteuid();
  int tap_fd, opt, delete = 0, brief = 0;
  char *tun = "", *file = "/dev/net/tun", *end;

  while ((opt = getopt(argc, argv, "bd:f:t:u:")) > 0) {
    switch (opt) {
    case 'b':
      brief = 1;
      break;
    case 'd':
      delete = 1;
      tun = optarg;
      break;
    case 'f':
      file = optarg;
      break;
    case 'u':
      strowner = optarg;
      pw = getpwnam(optarg);
      if (pw != NULL) {
	owner = pw->pw_uid;
	break;
      }
      owner = strtol(optarg, &end, 0);
      if (*end != '\0') {
	write2(optarg);
	write2(": is neither a username nor a numeric uid.\n");
	Usage();
      }
      break;
    case 't':
      tun = optarg;
      break;
    case 'h':
    default:
      Usage();
    }
  }

  argv += optind;
  argc -= optind;

  if (argc > 0)
    Usage();

  if ((tap_fd = open(file, O_RDWR)) < 0) {
    write2("Failed to open - ");
    write2(file);
    exit(1);
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy(ifr.ifr_name, tun, sizeof(ifr.ifr_name) - 1);
  if (ioctl(tap_fd, TUNSETIFF, (void *) &ifr) < 0) {
    perror("TUNSETIFF");
    exit(1);
  }

  if (delete) {
    if (ioctl(tap_fd, TUNSETPERSIST, 0) < 0) {
      perror("TUNSETPERSIST");
      exit(1);
    }
    write1("Set '");
    write1(ifr.ifr_name);
    write1("' nonpersistent\n");
  } else {
    if (ioctl(tap_fd, TUNSETPERSIST, 1) < 0) {
      perror("TUNSETPERSIST");
      exit(1);
    }
    if (ioctl(tap_fd, TUNSETOWNER, owner) < 0) {
      perror("TUNSETPERSIST");
      exit(1);
    }
    if (brief) {
      write1(ifr.ifr_name);
    } else {
      write1("Set '");
      write1(ifr.ifr_name);
      write1("' persistent");
      if (strowner) {
	write1(" and owned by ");
	write1(strowner);
      }
    }
    write1("\n");
  }
  return (0);
}

/* -------------------------------------------------------------------- */
/*                                                                      */
/* Copyright (C) 2003 Gernot Tenchio (gernot@tenchio.de)                */
/*                                                                      */
/* This program is free software; you can redistribute it and/or        */
/* modify it under the terms of the GNU Library General Public License  */
/* as published by the Free Software Foundation; either version 2       */
/* of the License, or (at your option) any later version.               */
/*                                                                      */
/* This program is distributed in the hope that it will be useful,      */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU Library General Public License for more details.                 */
/* -------------------------------------------------------------------- */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/poll.h>

#define write_const(s) write(STDERR_FILENO, s, sizeof(s) - 1)

int main(int argc, char **argv)
{
  char buf[1024];
  struct sockaddr_un addr;
  int sockfd;
  int size;
  int retval = 0;

  if (argc == 1) {
    write_const("Usage: rblquery IP-Address\n");
    return EXIT_FAILURE;
  }

  if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
    write_const("err: Failed to create unix domain socket!\n");
    return EXIT_FAILURE;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_LOCAL;
  strncpy(addr.sun_path, "/tmp/.rbldsock", sizeof(addr.sun_path));

  /* connect to the "orange filter cache daemon" */
  if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
    write_const("err: Failed to connect rbld!\n");
    close(sockfd);
    return EXIT_FAILURE;
  }

  if ((size_t) send(sockfd, (void *) argv[1], strlen(argv[1]), 0) !=
      strlen(argv[1])) {
    write_const("err: Failed to send request to daemon!\n");
    close(sockfd);
    return EXIT_FAILURE;
  }

  fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);

  while (1) {
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    poll(&pfd, 1, -1);
    if ((pfd.revents & POLLIN) != 0) {
      if ((size = read(sockfd, buf, sizeof(buf))) == -1) {
	retval = EXIT_FAILURE;
	break;
      }
      /* rbld sends a single '\0' when finished */
      if (!buf[0])
	break;
      write(STDOUT_FILENO, buf, size);
      retval = 2;
    } else {
      retval = EXIT_FAILURE;
      break;
    }
  }
  close(sockfd);
  return retval;
}

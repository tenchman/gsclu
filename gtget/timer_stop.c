/* gtget is Copyright (c) 2004 - XXXX Gernot Tenchio

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* $Id: timer_stop.c 18 2005-11-09 07:43:26Z gernot $ */
#include "timer.h"

void timer_stop(GTtimer_t * timer)
{
  gettimeofday(&timer->stop, (struct timezone *) 0);
  if (timer->stop.tv_usec < timer->start.tv_usec) {
    timer->stop.tv_usec += 1000000;
    timer->stop.tv_sec--;
  }
  timer->elapsed = (timer->stop.tv_usec - timer->start.tv_usec) / 1000;
  timer->elapsed += (timer->stop.tv_sec - timer->start.tv_sec) * 1000;
}

/* gtget is Copyright (c) 2004 - XXXX Gernot Tenchio

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* $Id: timer_start.c 18 2005-11-09 07:43:26Z gernot $ */
#include "timer.h"

void timer_start(GTtimer_t * timer)
{
  timer->elapsed = 0;
  gettimeofday(&timer->start, (struct timezone *) 0);
}

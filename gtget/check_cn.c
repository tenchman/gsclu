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
#include "str.h"
/* check_cn()
 *
 * Check if the given commonname matches the full qualified hostname
 * of the target host.
 *
 * Basic wildcard matching is supported (i.e. "*.ccc.de")
 *
 * For a full list of regexes see:
 * http://wp.netscape.com/eng/security/ssl_2.0_certificate.html
**/
int check_cn(char *cn, char *fqdn)
{
  int n;
  if (*cn == '*') {
    cn++;
    n = str_len(fqdn) - str_len(cn);
    if (n >= 0)
      fqdn += n;
  }
  return str_casecmp(fqdn, cn);
}

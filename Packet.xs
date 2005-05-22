/*
 * $Id: Packet.xs,v 1.1.1.1.4.3 2005/05/22 19:18:07 gomor Exp $
 *
 * AUTHOR
 *
 * Patrice <GomoR> Auffret
 *
 * COPYRIGHT AND LICENSE
 *
 * Copyright (c) 2004-2005, Patrice <GomoR> Auffret
 *
 * You may distribute this module under the terms of the Artistic license.
 * See Copying file in the source distribution archive.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <libnetpacket.h>

static int
not_here(char *s)
{
   croak("%s not implemented on this architecture", s);
   return -1;
}

static double
constant(char *name, int len, int arg)
{
   errno = EINVAL;
   return 0;
}

MODULE = Net::Packet      PACKAGE = Net::Packet

double
constant(sv,arg)
   PREINIT:
      STRLEN   len;
   INPUT:
      SV      *sv
      char    *s = SvPV(sv, len);
      int      arg
   CODE:
      RETVAL = constant(s,len,arg);
   OUTPUT:
      RETVAL

int
netpacket_open_l2(arg0)
   char * arg0

int
netpacket_tcpdump(arg0, arg1, arg2, arg3, arg4, arg5)
   char *arg0
   char *arg1
   char *arg2
   int   arg3
   int   arg4
   int   arg5

FILE *
netpacket_pcap_fp(arg0)
   pcap_t *arg0

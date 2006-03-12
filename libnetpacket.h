/*
 * $Id: libnetpacket.h,v 1.1.1.1.4.4 2006/03/11 16:32:50 gomor Exp $
 *
 * AUTHOR    
 * 
 * Patrice <GomoR> Auffret
 *          
 * COPYRIGHT AND LICENSE
 *    
 * Copyright (c) 2004-2006, Patrice <GomoR> Auffret
 *         
 * You may distribute this module under the terms of the Artistic license.
 * See Copying file in the source distribution archive.
 */

typedef struct pcap pcap_t;

int
netpacket_open_l2(char *interface);

int
netpacket_tcpdump(char *dev, char *file, char *filter, int snaplen, int promisc, int debug);

FILE *
netpacket_pcap_fp(pcap_t *pd);

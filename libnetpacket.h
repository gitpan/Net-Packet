/*
 * $Date: 2005/01/25 12:15:50 $
 * $Revision: 1.1.1.1.4.2 $
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

typedef struct pcap pcap_t;

int
netpacket_open_l2(char *interface);

int
netpacket_tcpdump(char *dev, char *file, char *filter, int snaplen, int promisc, int debug);

FILE *
netpacket_pcap_fp(pcap_t *pd);

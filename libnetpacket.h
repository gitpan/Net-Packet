typedef struct pcap pcap_t;

int
netpacket_open_l2(char *interface);

int
netpacket_tcpdump(char *dev, char *file, char *filter, int snaplen, int promis);

FILE *
netpacket_pcap_fp(pcap_t *pd);

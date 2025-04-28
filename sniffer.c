#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define APP_NAME "sn1ffer"

void
print_app_usage(void)
{
	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

int
main(int argc, char **argv)
{
    char device[256];
    char filter[256];
    int cmd_opt = 0;

    *device = 0;
    *filter = 0;

    while((cmd_opt = getopt(argc, argv, "h:i:")) != -1) {
        switch (cmd_opt) {
            case 'h':
                print_app_usage();
                exit(EXIT_FAILURE);
                break;
            case 'i':
                strcpy(device, optarg);
                break;
        }
    }

    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices = NULL;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;
    
    if (!*device) {
        if (pcap_findalldevs(&devices, errbuf)) {
            fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
            return -1;
        }
        strcpy(device, devices[0].name);
    }
    
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        return -1;
    }
    

    

}

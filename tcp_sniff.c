#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { /* IPv4 */
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            int ip_header_len = ip->iph_ihl * 4;
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = ((tcp->tcp_offx2 & 0xF0) >> 4) * 4;

            const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

            /* MAC Address from L2 Header */
            printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            /* IP Address From L3 Header */
            printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));

            /* Port Numbers From L4 Header */
            printf("Src Port: %u\n", ntohs(tcp->tcp_sport));
            printf("Dst Port: %u\n", ntohs(tcp->tcp_dport));

            /* Payload */
            if (payload_len > 0) {
                printf("Payload (%d bytes): ", payload_len);
                for (int i = 0; i < payload_len && i < 16; i++) {if (payload[i] >= 32 && payload[i] <= 126) printf("%c", payload[i]);}
                printf("\n");
            } else printf("No Payload\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    
    return 0;
}

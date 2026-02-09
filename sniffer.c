#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

struct pcap_global_header {
    unsigned int magic_number;
    unsigned short version_major;
    unsigned short version_minor;
    int thiszone;
    unsigned int sigfigs;
    unsigned int snaplen;
    unsigned int network;
};

struct pcap_packet_header {
    unsigned int ts_sec;
    unsigned int ts_usec;
    unsigned int incl_len;
    unsigned int orig_len;
};

int main() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket Error");
        return 1;
    }

    FILE* logfile = fopen("capture.pcap", "wb");
    if (!logfile) {
        perror("Unable to open file");
        return 1;
    }

    struct pcap_global_header pcap_hdr;
    pcap_hdr.magic_number = 0xa1b2c3d4;
    pcap_hdr.version_major = 2;
    pcap_hdr.version_minor = 4;
    pcap_hdr.thiszone = 0;
    pcap_hdr.sigfigs = 0;
    pcap_hdr.snaplen = 65535;
    pcap_hdr.network = 1;

    fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, logfile);

    int buffer_len = 65536;
    unsigned char* buffer = (unsigned char*)malloc(buffer_len);

    printf("Sniffer running... Waiting for TCP packets.\n");

    while (1) {
        int data_size = recvfrom(sock, buffer, buffer_len, 0, NULL, NULL);
        if (data_size < 0)
            continue;

        struct pcap_packet_header pcap_rec;
        struct timeval tv;
        gettimeofday(&tv, NULL);

        pcap_rec.ts_sec = tv.tv_sec;
        pcap_rec.ts_usec = tv.tv_usec;
        pcap_rec.incl_len = data_size;
        pcap_rec.orig_len = data_size;

        fwrite(&pcap_rec, sizeof(pcap_rec), 1, logfile);
        fwrite(buffer, data_size, 1, logfile);

        fflush(logfile);

        struct iphdr* ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

        if (ip->protocol == 6) { // 6 is TCP
            unsigned short ip_head_len = ip->ihl * 4;
            struct tcphdr* tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ip_head_len);

            struct sockaddr_in source, dest;
            source.sin_addr.s_addr = ip->saddr;
            dest.sin_addr.s_addr = ip->daddr;

            char src_ip[INET_ADDRSTRLEN];
            char dest_ip[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &(source.sin_addr), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(dest.sin_addr), dest_ip, INET_ADDRSTRLEN);

            printf("TCP Packet: %s:%d -> %s:%d\n",
                   src_ip,
                   ntohs(tcp->source),
                   dest_ip,
                   ntohs(tcp->dest));

            unsigned int tcp_head_len = tcp->doff * 4;
            int total_headers_size = sizeof(struct ethhdr) + ip_head_len + tcp_head_len;
            int payload_len = data_size - total_headers_size;

            unsigned char* payload = buffer + total_headers_size;
            if (payload_len > 0) {
                printf("   Payload (%d bytes): \n   ", payload_len);

                for (int i = 0; i < payload_len && i < 50; i++) {
                    if (payload[i] >= 32 && payload[i] <= 126) {
                        printf("%c", payload[i]);
                    } else {
                        printf(".");
                    }
                }
                printf("\n\n");
            }
        } else if (ip->protocol == 17) {

            unsigned short ip_head_len = ip->ihl * 4;

            struct udphdr* udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + ip_head_len);

            struct sockaddr_in source, dest;
            source.sin_addr.s_addr = ip->saddr;
            dest.sin_addr.s_addr = ip->daddr;

            char src_ip[INET_ADDRSTRLEN];
            char dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(source.sin_addr), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(dest.sin_addr), dest_ip, INET_ADDRSTRLEN);

            if (ntohs(udp->dest) == 53 || ntohs(udp->source) == 53) {
                printf("DNS Request: %s -> %s\n", src_ip, dest_ip);

                unsigned char* dns_payload = buffer + sizeof(struct ethhdr) + ip_head_len + sizeof(struct udphdr);

                int payload_len = ntohs(udp->len) - sizeof(struct udphdr);
                if (payload_len > 0) {
                    printf("   Query: ");
                    for (int i = 0; i < payload_len && i < 40; i++) {
                        if (dns_payload[i] >= 32 && dns_payload[i] <= 126)
                            printf("%c", dns_payload[i]);
                        else
                            printf(".");
                    }
                    printf("\n");
                }
            }
        }
    }

    close(sock);
    return 0;
}

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

struct __attribute__((packed)) pcap_global_header {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct __attribute__((packed)) pcap_packet_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

int keep_running = 1;

void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

const char* format_ip(uint32_t addr, char* buf) {
    struct in_addr in;
    in.s_addr = addr;
    return inet_ntop(AF_INET, &in, buf, INET_ADDRSTRLEN);
}

int main() {
    signal(SIGINT, handle_sigint);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket Error");
        return 1;
    }

    FILE* logfile = fopen("capture.pcap", "wb");
    if (!logfile) {
        perror("Unable to open file");
        close(sock);
        return 1;
    }

    struct pcap_global_header pcap_hdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1 // Ethernet
    };

    fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, logfile);

    int buffer_len = 65536;
    unsigned char* buffer = (unsigned char*)malloc(buffer_len);
    if (!buffer) {
        perror("Malloc failed");
        fclose(logfile);
        close(sock);
        return 1;
    }

    printf("Sniffer running... Waiting for packets (Press Ctrl+C to stop).\n");

    while (keep_running) {
        int data_size = recvfrom(sock, buffer, buffer_len, 0, NULL, NULL);
        if (data_size < 0) {
            continue;
        }

        struct pcap_packet_header pcap_rec;
        struct timeval tv;
        gettimeofday(&tv, NULL);

        pcap_rec.ts_sec = (uint32_t)tv.tv_sec;
        pcap_rec.ts_usec = (uint32_t)tv.tv_usec;
        pcap_rec.incl_len = (uint32_t)data_size;
        pcap_rec.orig_len = (uint32_t)data_size;

        fwrite(&pcap_rec, sizeof(pcap_rec), 1, logfile);
        fwrite(buffer, data_size, 1, logfile);
        fflush(logfile);

        if (data_size < (int)sizeof(struct ethhdr))
            continue;

        struct ethhdr* eth = (struct ethhdr*)buffer;
        if (ntohs(eth->h_proto) != ETH_P_IP)
            continue;

        if (data_size < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr)))
            continue;

        struct iphdr* ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        unsigned short ip_head_len = ip->ihl * 4;

        if (data_size < (int)(sizeof(struct ethhdr) + ip_head_len))
            continue;

        if (ip->protocol == IPPROTO_TCP) {
            if (data_size < (int)(sizeof(struct ethhdr) + ip_head_len + sizeof(struct tcphdr)))
                continue;

            struct tcphdr* tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ip_head_len);

            char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
            format_ip(ip->saddr, src_ip);
            format_ip(ip->daddr, dest_ip);

            printf("TCP Packet: %s:%d -> %s:%d\n",
                   src_ip, ntohs(tcp->source),
                   dest_ip, ntohs(tcp->dest));

            unsigned int tcp_head_len = tcp->doff * 4;
            int total_headers_size = sizeof(struct ethhdr) + ip_head_len + tcp_head_len;
            int payload_len = data_size - total_headers_size;

            if (payload_len > 0) {
                printf("   Payload (%d bytes): \n   ", payload_len);
                unsigned char* payload = buffer + total_headers_size;
                for (int i = 0; i < payload_len && i < 50; i++) {
                    if (payload[i] >= 32 && payload[i] <= 126)
                        printf("%c", payload[i]);
                    else
                        printf(".");
                }
                printf("\n\n");
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            if (data_size < (int)(sizeof(struct ethhdr) + ip_head_len + sizeof(struct udphdr)))
                continue;

            struct udphdr* udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + ip_head_len);

            if (ntohs(udp->dest) == 53 || ntohs(udp->source) == 53) {
                char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
                format_ip(ip->saddr, src_ip);
                format_ip(ip->daddr, dest_ip);

                printf("DNS Request: %s -> %s\n", src_ip, dest_ip);

                int header_size = sizeof(struct ethhdr) + ip_head_len + sizeof(struct udphdr);
                unsigned char* dns_payload = buffer + header_size;
                int payload_len = data_size - header_size;

                if (payload_len > 0) {
                    printf("   Query data: ");
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

    printf("\nShutting down gracefully...\n");
    fclose(logfile);
    free(buffer);
    close(sock);
    return 0;
}

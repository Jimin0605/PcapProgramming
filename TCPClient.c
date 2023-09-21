#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>

/* Ethernet header */
struct ethheader {
    u_char ethh_dmac[6]; // destination mac address
    u_char ethh_smac[6]; // source mac address
    u_short ethh_type;   // Ethernet type
};

/* IP header */
struct ipheader {
    unsigned char iph_verlen; // IP version and header length
    unsigned char iph_tos;    // Type of service
    u_short iph_len;          // Total length
    u_short iph_ident;        // Identification
    u_short iph_offset;       // Flags and Fragmentation offset
    unsigned char iph_ttl;    // Time to live (TTL)
    unsigned char iph_protocol; // Protocol
    u_short iph_chksum;        // Header checksum
    struct in_addr iph_source; // Source IP address
    struct in_addr iph_dest;   // Destination IP address
};

/* TCP header */
struct tcpheader {
    u_short tcph_sport;       // Source port
    u_short tcph_dport;       // Destination port
    u_int tcph_seqnum;        // Sequence number
    u_int tcph_acknum;        // Acknowledgment number
    unsigned char tcph_offset; // Data offset and reserved bits
    unsigned char tcph_flags;  // TCP flags
    u_short tcph_win;         // Window size
    u_short tcph_chksum;      // Checksum
    u_short tcph_urgent;      // Urgent pointer
};

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int eth_length = sizeof(struct ethheader);     // destination mac, source mac 과 이더넷 타입의 크기를 더해 legnth 구하기
    int ip_length = sizeof(struct ipheader);        // ip header에 있는 모든 데이터의 길이를 더해서 헤더길이 구하기
    int tcp_length = pkthdr->len - eth_length - ip_length;  // 패킷의 길이에서 이더넷헤더 ip헤더의 길이를 빼면 tcp헤더가 남는다


    /* 각 헤더 시작위치 설정 */
    // Ethernet header
    struct ethheader *eth = (struct ethheader *)packet;

    // IP header
    struct ipheader *ip = (struct ipheader *)(packet + eth_length);

    // TCP header
    struct tcpheader *tcp = (struct tcpheader *)(packet + eth_length + ip_length);



    /* 패킷의 총 길이*/
    printf("Packet captured. Length: %d\n\n", pkthdr->len);

    /* 각 헤더 길이 출력 */
    printf("Ethernet Length: %d\n", eth_length);
    printf("IP Length: %d\n", ip_length);
    printf("TCP Length: %d\n\n", tcp_length);

    /* 패킷 정보 출력*/
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            eth->ethh_dmac[0], eth->ethh_dmac[1], eth->ethh_dmac[2],
            eth->ethh_dmac[3], eth->ethh_dmac[4], eth->ethh_dmac[5]);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
       eth->ethh_smac[0], eth->ethh_smac[1], eth->ethh_smac[2],
       eth->ethh_smac[3], eth->ethh_smac[4], eth->ethh_smac[5]);

    printf("Source IP: %s\n", inet_ntoa(ip->iph_source));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_dest));
    printf("Source Port: %d\n", ntohs(tcp->tcph_sport));
    printf("Destination Port: %d\n\n", ntohs(tcp->tcph_dport));

    printf("TTL: %d\n\n", ip->iph_ttl);
    printf("========================================================\n");
}


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // No specific filter, capture all packets
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);   // 나의 네트워크 이름은 eth0이기에 eth0을 넣었다.

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, packet_handler, NULL);    // 패킷 계속 캡쳐하기

    pcap_close(handle); // Close the handle
    return 0;
}
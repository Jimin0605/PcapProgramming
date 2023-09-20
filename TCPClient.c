#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int i;
    printf("Packet captured. Length: %d\n", pkthdr->len);

    // Print packet data in hexadecimal format
    for (i = 0; i < pkthdr->len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }

    printf("\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = ""; // No specific filter, capture all packets
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3 (you may need to change this)
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}

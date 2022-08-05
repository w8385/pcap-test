#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <libnet.h>
#include <stdint.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	struct libnet_ethernet_hdr *ptr_ethernet;
	struct libnet_ipv4_hdr*	ptr_ipv4;
	struct libnet_tcp_hdr* ptr_tcp;

	while (true) {
		struct pcap_pkthdr* header; //time & length
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		
		ptr_ethernet = header;
		printf("ether_dhost : %x\n", *ptr_ethernet->ether_dhost);
		printf("ether_dhost : %x\n", *ptr_ethernet->ether_shost);
		putchar('\n');

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			//printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//printf("%u bytes captured\n", header->caplen);
		
		//printf("data : %s \n", packet);
	}

	pcap_close(pcap);
}

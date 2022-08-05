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

	while (true) {
		struct pcap_pkthdr* header; 	//time & length
		const u_char* packet;		//packet pointer
		int res = pcap_next_ex(pcap, &header, &packet);
		
		//ether_type check
		struct libnet_ethernet_hdr *ptr_ether_check = packet;
		if(ptr_ether_check->ether_type != 8){
			continue;
		}
		//tcp check
		struct libnet_ipv4_hdr *ptr_tcp_check = packet + 14;
		if(ptr_tcp_check->ip_p != 6){
			continue;
		}
		
		//ethernet
		struct libnet_ethernet_hdr *ptr_ethernet = packet;
			//src_mac
		printf("src_mac  : ");
		for(int i = 0; i < 6; i++){
			printf("%02x", *(ptr_ethernet->ether_shost + i));
			if(i < 5) putchar(':');
			else putchar('\n');
		}
			//dst_mac
		printf("dst_mac  : ");
		for(int i = 0; i < 6; i++){
			printf("%02x", *(ptr_ethernet->ether_dhost + i));
			if(i < 5) putchar(':');
			else putchar('\n');
		}

		//ip
		struct libnet_ipv4_hdr *ptr_ipv4 = packet + 14;
			//src_ip
		printf("src_ip   : ");
		uint32_t src_ip = ntohl(ptr_ipv4->ip_src.s_addr);
		printf("%u.%u.%u.%u\n", src_ip >> 24, (src_ip >> 16) & 0xff, (src_ip >> 8) & 0xff, src_ip & 0xff);
			//dst_ip
		printf("dst_ip   : ");
		uint32_t dst_ip = ntohl(ptr_ipv4->ip_dst.s_addr);
		printf("%u.%u.%u.%u\n", dst_ip >> 24, (dst_ip >> 16) & 0xff, (dst_ip >> 8) & 0xff, dst_ip & 0xff);

		//tcp
		struct libnet_tcp_hdr *ptr_tcp = packet + 34;
			//src_port
		printf("src_port : ");
		printf("%u\n", ntohs(ptr_tcp->th_sport));
			//dst_port
		printf("dst_port : ");
		printf("%u\n", ntohs(ptr_tcp->th_dport));

		//Payload
		uint32_t len_header = 34 + (ptr_tcp->th_off) * 4;
		printf("payload  : ");
		if(header->caplen == len_header){
			printf("no data\n");
		}
		else{
			for(int i = 0; i < 10 && header->caplen >= len_header + i; i++){
			       printf("%02x ", *(packet + len_header + i));
			}
	 		putchar('\n');
		}
		printf("----------------------------------------\n");		

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			break;
		}
	}

	pcap_close(pcap);
}

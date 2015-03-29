#include <pcap.h>
#include <pcap/sll.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "session.h"

void decodeTCP( session_t *s, struct tcphdr* tcpheader, int tcplen );

int readpcap( pcap_t * in ) {

	// Get link layer type
	int llheadertype = pcap_datalink(in);

	//loop over packets
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *packetdata;

	while( pcap_next_ex( in, &header, &packetdata ) == 1 ) {
		struct iphdr *ipheader;
		struct sll_header *llhead;
		switch( llheadertype ) {
			case DLT_LINUX_SLL:
				llhead = (struct sll_header*)packetdata;
				if( ntohs(llhead->sll_protocol) == ETH_P_IP ) {
					ipheader = (struct iphdr*) (packetdata + sizeof(struct sll_header));
				} else {
					continue;
				}
				break;
			default:
				continue;
		}

		switch( ipheader->version ) {
			case 4:
				break;
			default:
				printf("not ipv4\n");
				continue;
		}

		switch( ipheader->protocol ) {
			case IPPROTO_TCP:
				break;
			default:
				printf("not tcp\n");
				continue;
		}

		session_t s;
		s.counter = 0;
		s.src.ip.s_addr = ipheader->saddr;
		s.dest.ip.s_addr = ipheader->daddr;

		struct tcphdr* tcpheader = (struct tcphdr*)(((unsigned char*)ipheader) + (ipheader->ihl * 4));
		uint16_t tcplen = ntohs(ipheader->tot_len) - (ipheader->ihl * 4);
		decodeTCP( &s, tcpheader, tcplen );


	}
	return 0;
}

int main( int argc, char* argv[] ) {

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* in = pcap_open_offline( argv[1], errbuf );
	int curcount = readpcap( in );
	return 0;

}

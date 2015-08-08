#include <pcap.h>
#include <pcap/sll.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "session.h"

/* find *.{in,out} -size 0 -exec rm {} \;   */

void decodeTCP( session_t *s, void *header, int tcplen );
void decodeUDP(session_t *s, void *udpheader, uint16_t len);

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
		struct ether_header *etherhead;
		switch( llheadertype ) {
			case DLT_LINUX_SLL: //openvz container
				llhead = (struct sll_header*)packetdata;
				if( ntohs(llhead->sll_protocol) == ETH_P_IP ) {
					ipheader = (struct iphdr*) (packetdata + sizeof(struct sll_header));
				} else {
					continue;
				}
				break;

			case DLT_EN10MB: //ethernet
				etherhead = (struct ether_header*)packetdata;
				if( ntohs(etherhead->ether_type) == ETHERTYPE_IP ) {
					ipheader = (struct iphdr*) (packetdata + sizeof(struct ether_header));
				} else {
					continue;
				}
				break;

			default:
				DEBUG_PRINT(("L2 header %d\n", (int)llheadertype));
				continue;
		}

		session_t s;
		s.counter = 0;
		s.src.diskout = NULL;
		s.dest.diskout = NULL;

		switch( ipheader->version ) {
			case 4:
				s.src.ip.s_addr = ipheader->saddr;
				s.dest.ip.s_addr = ipheader->daddr;
				break;
			default:
				continue;
		}

		void *l4header = ((unsigned char*)ipheader) + (ipheader->ihl * 4);
		uint16_t l4len = ntohs(ipheader->tot_len) - (ipheader->ihl * 4);

		switch( ipheader->protocol ) {
			case IPPROTO_TCP: {
				decodeTCP( &s, l4header, l4len );
				break;
			  }
			case IPPROTO_UDP: {
				decodeUDP( &s, l4header, l4len );
				break;
			  }
			default:
				continue;
		}




	}
	return 0;
}

int main( int argc, char* argv[] ) {

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* in = pcap_open_offline( argv[1], errbuf );
	int curcount = readpcap( in );
	return 0;

}

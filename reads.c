#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap/sll.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <search.h>
#include <string.h>
#include "session.h"


session_t * getSessionID( session_t *s ) {
	static void *treeroot = NULL;
	printf("%s:%hu -> %s:%hu, id: %u ", inet_ntoa(s->srcip), ntohs(s->srcport), inet_ntoa(s->destip), ntohs(s->destport), s->id);
	printf("&: %p ", s);

	session_t **z = tfind(s, &treeroot, compare_session);
	if( z == NULL ) {
		//copy s and call tsearch
		session_t *newsession = malloc(sizeof(session_t));
		memcpy( newsession, s, sizeof(session_t) );
		z = tsearch(newsession, &treeroot, compare_session);
		s = *z;
	}

	return *z;
}

int readpcap( pcap_t * in ) {

	int id = 1;
	// Get link layer type
	int llheadertype = pcap_datalink(in);

	//loop over packets
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *packetdata;

	while( pcap_next_ex( in, &header, &packetdata ) == 1 ) {
		id += 1;
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


		if( ipheader->version != 4 ) {
			continue;
		}
		if( ipheader->protocol != IPPROTO_TCP ) {
			continue;
		}

		struct in_addr src, dest;
		src.s_addr = ipheader->saddr;
		dest.s_addr = ipheader->daddr;


		struct tcphdr* tcpheader = (struct tcphdr*)(((unsigned char*)ipheader) + (ipheader->ihl * 4));
		session_t s;
		s.srcip.s_addr = ipheader->saddr;
		s.destip.s_addr = ipheader->daddr;
		s.srcport = tcpheader->source;
		s.destport = tcpheader->dest;
		s.id = id;

		// get session struct
		session_t *sesh = getSessionID( &s );
		printf("ID: %u ", sesh->id);

		// advance session state




	printf("\n");
	}
	return 0;
}

int main( int argc, char* argv[] ) {

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* in = pcap_open_offline( argv[1], errbuf );
	int curcount = readpcap( in );
	return 0;

}

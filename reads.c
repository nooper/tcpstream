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
	static int sessionid = 0;
	//printf("%s:%hu -> %s:%hu ", inet_ntoa(s->srcip), ntohs(s->srcport), inet_ntoa(s->destip), ntohs(s->destport));

	session_t **z = tfind(s, &treeroot, compare_session);
	if( z == NULL ) {
		//copy s and call tsearch
		session_t *newsession = malloc(sizeof(session_t));
		memcpy( newsession, s, sizeof(session_t) );
		newsession->id = ++sessionid;
		newsession->srcstate = TCP_CLOSE;
		newsession->deststate = TCP_LISTEN;
		z = tsearch(newsession, &treeroot, compare_session);
	}

	return *z;
}

int setState( session_t *cur, session_t *sesh, struct tcphdr *h ) {
	int direction;  // 0 = client to server. 1 = server to client
	direction = 1; // default
	if( cur->srcip.s_addr == sesh->srcip.s_addr ) {
		if( cur->srcport == sesh->srcport ) {
			direction = 0;
		}
	}

	switch ( sesh->srcstate ) {
		case TCP_ESTABLISHED:
			if( h->fin == 1 ) {
				if( direction == 0 ) {
					if( sesh->deststate == TCP_ESTABLISHED ) {
						sesh->srcstate = TCP_FIN_WAIT1;
					}
				} else if ( direction == 1 ) {
					if( sesh->deststate == TCP_ESTABLISHED ) {
						sesh->deststate = TCP_FIN_WAIT1;
					}
				}
			} else if( h->ack == 1 ) {
				if( sesh->deststate == TCP_FIN_WAIT1 ) {
					sesh->srcstate = TCP_CLOSE_WAIT;
					sesh->deststate = TCP_FIN_WAIT2; // assuming closing party received this packet
				}
			}
			break;

		case TCP_FIN_WAIT1:
			if( direction == 0 ) {
				if( sesh->deststate == TCP_ESTABLISHED ) {
					if( h->ack == 1 ) {
						sesh->deststate = TCP_CLOSE_WAIT;
						sesh->srcstate = TCP_FIN_WAIT2;
					}
				}
			}
			break;

		case TCP_FIN_WAIT2:
			if( direction == 1 ) {
				if( h->fin == 1 ) {
					if( sesh->deststate == TCP_CLOSE_WAIT ) {
						sesh->deststate = TCP_LAST_ACK;
					}
				}
			} else if( direction == 0 ) {
				if( h->ack == 1 ) {
					if( sesh->deststate == TCP_LAST_ACK ) {
						sesh->deststate = TCP_CLOSE;
						sesh->srcstate = TCP_TIME_WAIT;
					}
				}
			}
			break;

		case TCP_CLOSE_WAIT:
			if( h->fin == 1 ) {
				if( direction == 0 ) {
					if( sesh->deststate == TCP_FIN_WAIT2 ) {
						sesh->srcstate = TCP_LAST_ACK;
					}
				}
			}
			break;

		case TCP_LAST_ACK:
			if( h->ack == 1 ) {
				if( direction == 1) {
					if( sesh->deststate == TCP_FIN_WAIT2 ) {
						sesh->deststate = TCP_TIME_WAIT;
						sesh->srcstate = TCP_CLOSE;
					}
				}
			}
			break;




		case TCP_CLOSE:
			if( h->syn == 1 ) {
				if( direction == 0) {
					if( h->ack == 0 ) {
						if( sesh->deststate == TCP_LISTEN ) {
							// src is initiating a new connection
							sesh->srcstate = TCP_SYN_SENT;
						}
					}
				}
			}
			break;
		case TCP_SYN_SENT:
			if( direction == 1) {
				if( h->syn == 1 ) {
					if( h->ack == 1 ) {
						if( sesh->deststate == TCP_LISTEN ) {
							// server sends back a syn ack
							sesh->deststate = TCP_SYN_RECV;
						}
					}
				}
			} else if ( direction == 0 ) {
				if( h->syn == 0 ) {
					if( h->ack == 1 ) {
						if( sesh->deststate == TCP_SYN_RECV ) {
							// connection is established
							sesh->srcstate = TCP_ESTABLISHED;
							sesh->deststate = TCP_ESTABLISHED;
						}
					}
				}
			}
			break;


		default:
			printf(" dunno ");
	}
	
	return direction;
}

char * getStateString( int state ) {
	switch( state ) {
		case TCP_ESTABLISHED:
			return "ESTABLISHED";
			break;
		case TCP_SYN_SENT:
			return "SYN_SENT";
			break;
		case TCP_SYN_RECV:
			return "SYN_RECV";
			break;
		case TCP_FIN_WAIT1:
			return "FIN_WAIT1";
			break;
		case TCP_FIN_WAIT2:
			return "FIN_WAIT2";
			break;
		case TCP_TIME_WAIT:
			return "TIME_WAIT";
			break;
		case TCP_CLOSE:
			return "CLOSE";
			break;
		case TCP_CLOSE_WAIT:
			return "CLOSE_WAIT";
			break;
		case TCP_LAST_ACK:
			return "LAST_ACK";
			break;
		case TCP_LISTEN:
			return "LISTEN";
			break;
		default:
			return "OH NO!";
	}
}

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

		// get session struct
		session_t *sesh = getSessionID( &s );

		int direction = setState( &s, sesh, tcpheader );
		if( direction == 0 ) {
			printf(" %s:%d -> ", inet_ntoa(src), ntohs(s.srcport));
			printf("%s:%d ", inet_ntoa(dest), ntohs(s.destport));
		} else {
			printf(" %s:%d <- ", inet_ntoa(dest), ntohs(s.destport));
			printf("%s:%d ", inet_ntoa(src), ntohs(s.srcport));
		}
		printf("ID: %u ", sesh->id);
		printf(" src: %s ", getStateString( sesh->srcstate ) );
		printf("dest: %s ", getStateString( sesh->deststate ) );
		if( sesh->srcstate == TCP_ESTABLISHED && sesh->deststate == TCP_ESTABLISHED ) {
			void *tcpdata = ((void*)tcpheader) + (tcpheader->doff * 4);
			int tcpdatalen = header->len - ((void*)tcpdata - (void*)packetdata);
			printf(" len:%d ", tcpdatalen );

		}






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

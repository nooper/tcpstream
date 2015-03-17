#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "session.h"

int tcp2disk( session_t* sesh, void* tcpdata, int len, int direction );

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

	// rule 1: The TCP states for src and dest are set as they would be after the packet is sent,
	// but before the packet is received and processed by the destination. ie. as perceived by a middle-man listening between the parties.
	// rule 2: In the session struct, 'src' and 'dest' do not refer to the source or destination of the packet being currently processed.
	// It refers to the source and destination of the first packet. 'src' is the initiator of the tcp session at the beginning.
	

	switch ( sesh->srcstate ) {
		case TCP_ESTABLISHED:
			if( direction == 0 ) {
				if( h->fin == 1 ) {
					if( sesh->deststate == TCP_ESTABLISHED ) {
						sesh->srcstate = TCP_FIN_WAIT1;
					} else if( sesh->deststate == TCP_FIN_WAIT1 ) {
						if( h->ack == 0 ) {
							sesh->srcstate = TCP_CLOSE_WAIT;
						} else if( h->ack == 1 ) {
							sesh->srcstate = TCP_LAST_ACK;
						}
					}
				}
			} else {
				if( sesh->deststate == TCP_ESTABLISHED ) {
					if( h->fin == 1 ) {
						sesh->deststate = TCP_FIN_WAIT1;
					}
				}
			}
			break;

		case TCP_FIN_WAIT1:
			if( direction == 0 ) {
				if( h->ack == 1 ) {
					if( sesh->deststate == TCP_LAST_ACK ) {
						sesh->srcstate = TCP_TIME_WAIT; // done
						sesh->deststate = TCP_CLOSE; // the only violation of rule 1 because there will never be a response to this packet
					}
				}
						
			} else {
				if( sesh->deststate == TCP_ESTABLISHED ) {
					if( h->ack == 1 ) {
						if( h->fin == 0 ) {
							sesh->deststate = TCP_CLOSE_WAIT;
						} else if( h->fin == 1 ) {
							sesh->deststate = TCP_LAST_ACK;
						}
					}
				}
			}
			break;

		case TCP_FIN_WAIT2:
			if( direction == 0 ) {
			} else {
			}
			break;

		case TCP_CLOSE_WAIT:
			if( direction == 0 ) {
			} else {
			}
			break;

		case TCP_LAST_ACK:
			if( direction == 0 ) {
			} else {
				if( sesh->deststate == TCP_FIN_WAIT1 ) {
					if( h->ack == 1 ) {
						sesh->srcstate = TCP_CLOSE;
						sesh->deststate = TCP_TIME_WAIT;
					}
				}
			}
			break;


		// Session establishment:
		case TCP_CLOSE:
			if( direction == 0) {
				if( h->syn == 1 && h->ack == 0) {
					if( sesh->deststate == TCP_LISTEN ) {
						sesh->srcstate = TCP_SYN_SENT;
					}
				}
			}
			break;

		case TCP_SYN_SENT:
			if( direction == 1) {
				if( h->syn == 1 && h->ack == 1 ) {
					if( sesh->deststate == TCP_LISTEN ) {
						sesh->deststate = TCP_SYN_RECV;
					}
				}
			} else if ( direction == 0 ) {
				if( h->syn == 0 && h->ack == 1 ) {
					if( sesh->deststate == TCP_SYN_RECV ) {
						sesh->srcstate = TCP_ESTABLISHED;
						sesh->deststate = TCP_ESTABLISHED;
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

void decodeTCP( session_t *s, struct tcphdr* tcpheader, int tcplen ) {

	uint32_t curseq, curack;
	curseq = ntohl(tcpheader->seq);
	curack = ntohl(tcpheader->ack_seq);
	printf("seq: %u ack: %u \t", curseq, curack);

	// get session struct
	s->srcport = tcpheader->source;
	s->destport = tcpheader->dest;
	session_t *sesh = getSessionID( s );
	sesh->counter++;

	int direction = setState( s, sesh, tcpheader );
	if( direction == 0 ) {
		if( tcpheader->syn == 1 ) {
			sesh->dest_nextseq = curseq + 1;
			sesh->src_needackupto = curseq + 1;
		}
	} else {
		if( tcpheader->syn == 1 ) {
			sesh->dest_needackupto = curseq + 1;
			sesh->src_nextseq = curseq + 1;
		}
	}

	//printf(" src: %s ", getStateString( sesh->srcstate ) );
	//printf("dest: %s ", getStateString( sesh->deststate ) );
	if( (sesh->srcstate == TCP_ESTABLISHED) || (sesh->deststate == TCP_ESTABLISHED) ) {
		printf("%u.%03u \t", sesh->id, sesh->counter);
		void *tcpdata = ((void*)tcpheader) + (tcpheader->doff * 4);
		int tcpdatalen = tcplen - ((void*)tcpdata - (void*)tcpheader);
		if( direction == 0 ) {
			printf("--> seq:%05i ack:%05i\t", curseq - sesh->dest_nextseq, sesh->dest_needackupto - curack);
			sesh->src_needackupto += tcpdatalen;
			sesh->dest_nextseq += tcpdatalen;
		} else {
			printf("<-- seq:%05i ack:%05i\t", curseq - sesh->src_nextseq, sesh->src_needackupto - curack);
			sesh->dest_needackupto += tcpdatalen;
			sesh->src_nextseq += tcpdatalen;
		}
		tcp2disk( sesh, tcpdata, tcpdatalen, direction );
	}
	printf("\n");
}

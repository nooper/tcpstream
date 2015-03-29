#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "session.h"

int tcp2disk( struct host* src, void* tcpdata, int len );

int setState( session_t *cur, session_t *sesh, struct tcphdr *h ) {
	int direction;  // 0 = client to server. 1 = server to client
	direction = 1; // default
	if( cur->src.ip.s_addr == sesh->src.ip.s_addr ) {
		if( cur->src.port == sesh->src.port ) {
			direction = 0;
		}
	}

	// rule 1: The TCP states for src and dest are set as they would be after the packet is sent,
	// but before the packet is received and processed by the destination. ie. as perceived by a middle-man listening between the parties.
	// rule 2: In the session struct, 'src' and 'dest' do not refer to the source or destination of the packet being currently processed.
	// It refers to the source and destination of the first packet. 'src' is the initiator of the tcp session at the beginning.
	

	switch ( sesh->src.state ) {
		case TCP_ESTABLISHED:
			if( direction == 0 ) {
				if( h->fin == 1 ) {
					if( sesh->dest.state == TCP_ESTABLISHED ) {
						sesh->src.state = TCP_FIN_WAIT1;
					} else if( sesh->dest.state == TCP_FIN_WAIT1 ) {
						if( h->ack == 0 ) {
							sesh->src.state = TCP_CLOSE_WAIT;
						} else if( h->ack == 1 ) {
							sesh->src.state = TCP_LAST_ACK;
						}
					}
				}
			} else {
				if( sesh->dest.state == TCP_ESTABLISHED ) {
					if( h->fin == 1 ) {
						sesh->dest.state = TCP_FIN_WAIT1;
					}
				}
			}
			break;

		case TCP_FIN_WAIT1:
			if( direction == 0 ) {
				if( h->ack == 1 ) {
					if( sesh->dest.state == TCP_LAST_ACK ) {
						sesh->src.state = TCP_TIME_WAIT; // done
						sesh->dest.state = TCP_CLOSE; // the only violation of rule 1 because there will never be a response to this packet
					}
				}
						
			} else {
				if( sesh->dest.state == TCP_ESTABLISHED ) {
					if( h->ack == 1 ) {
						if( h->fin == 0 ) {
							sesh->dest.state = TCP_CLOSE_WAIT;
						} else if( h->fin == 1 ) {
							sesh->dest.state = TCP_LAST_ACK;
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
				if( sesh->dest.state == TCP_FIN_WAIT1 ) {
					if( h->ack == 1 ) {
						sesh->src.state = TCP_CLOSE;
						sesh->dest.state = TCP_TIME_WAIT;
					}
				}
			}
			break;


		// Session establishment:
		case TCP_CLOSE:
			if( direction == 0) {
				if( h->syn == 1 && h->ack == 0) {
					if( sesh->dest.state == TCP_LISTEN ) {
						sesh->src.state = TCP_SYN_SENT;
					}
				}
			}
			break;

		case TCP_SYN_SENT:
			if( direction == 1) {
				if( h->syn == 1 && h->ack == 1 ) {
					if( sesh->dest.state == TCP_LISTEN ) {
						sesh->dest.state = TCP_SYN_RECV;
					}
				}
			} else if ( direction == 0 ) {
				if( h->syn == 0 && h->ack == 1 ) {
					if( sesh->dest.state == TCP_SYN_RECV ) {
						sesh->src.state = TCP_ESTABLISHED;
						sesh->dest.state = TCP_ESTABLISHED;
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

void bufferTCP( uint32_t curseq, struct host* src, struct host* dest, void* tcpdata, int len ) {
	if( curseq == src->seq ) {
		// write this packet to disk, or something
		src->seq += len;
		tcp2disk( src, tcpdata, len );
		printf(" written %i ", len);
		// check if any buffers need to be processed
		struct ll *buf = ll_get( src->seq, dest );
		if(buf != NULL) {
			src->seq += buf->len;
			printf("unbuf!");
		}
	} else if ( curseq > src->seq ) {
		// packet is early. buffer it
		ll_put( curseq, len, tcpdata, dest );
		printf(" buffered ");
	} else {
		// else if curseq < src->seq, ignore the packet because its a retransmission and i already have the data
		// rewrite this to check if the data length is high enough to include data i don't have.
		printf(" ignored ");
	}
}

void decodeTCP( session_t *s, struct tcphdr* tcpheader, int tcplen ) {

	uint32_t curseq, curack;
	curseq = ntohl(tcpheader->seq);
	curack = ntohl(tcpheader->ack_seq);
	printf("seq: %u ack: %u \t", curseq, curack);

	// get session struct
	s->src.port = tcpheader->source;
	s->dest.port = tcpheader->dest;
	session_t *sesh = getSessionID( s );
	sesh->counter++;

	int direction = setState( s, sesh, tcpheader );
	if( tcpheader->syn == 1) {
		if( direction == 0 ) {
			sesh->src.seq = curseq + 1;
		} else {
			sesh->dest.seq = curseq + 1;
		}
	}

	if( (sesh->src.state == TCP_ESTABLISHED) || (sesh->dest.state == TCP_ESTABLISHED) ) {
		printf("%u.%03u \t", sesh->id, sesh->counter);
		void *tcpdata = ((void*)tcpheader) + (tcpheader->doff * 4);
		int tcpdatalen = tcplen - ((void*)tcpdata - (void*)tcpheader);
		printf(" len: %04d  \t", tcpdatalen );
		//tcp2disk( sesh, tcpdata, tcpdatalen, direction );
		if( direction == 0 ) {
			printf(" --> ");
		} else {
			printf(" <-- ");
		}
		if( tcpdatalen > 0 ) {
			if( direction == 0 ) {
				bufferTCP( curseq, &(sesh->src), &(sesh->dest), tcpdata, tcpdatalen );
			} else {
				bufferTCP( curseq, &(sesh->dest), &(sesh->src), tcpdata, tcpdatalen );
			}
		}
	}
	printf("\n");
}

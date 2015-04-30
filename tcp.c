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

void writeBuffer( void* buf, int buflen, uint32_t bufseq, struct host* src ) {
	/* assumes curseq is in provided buffer */
	int offset = src->seq - bufseq; //rewrite this for 32 bit wraparound
	int usefulLen = buflen - offset;
	tcp2disk( src, buf + offset, usefulLen );
	printf(" written %i ", usefulLen);
	src->seq += usefulLen;
}

void bufferTCP( uint32_t curseq, struct host* src, struct host* dest, void* tcpdata, int len ) {
	if( CheckWindow(src->seq, curseq, src->seq + dest->window) ) { //if its in the window
		if( CheckWindow(curseq, src->seq, curseq + len) ) { //if this packet contains the next seq
			writeBuffer( tcpdata, len, curseq, src );
			struct ll *buf;
			while(buf = ll_get(src->seq, dest)) {
				writeBuffer( buf->tcpdata, buf->len, buf->seq, src );
				dest->bufcount--;
				free(buf->tcpdata);
				free(buf);
				//printf("unbuf %d", buf->len);
			}
		} else { // packet is early. buffer it
			ll_put( curseq, len, tcpdata, dest );
			dest->bufcount++;
			printf(" buffered ");
		}
	} else { //packet is out of window
		printf(" ignored ");
	}
	printf(" count:%d ", dest->bufcount);
}

void processOptions( struct host *sender, struct tcphdr *tcpheader) {
	char *tcpopt = ((void*)tcpheader) + 20; //options start at byte 20
	char *optend = tcpopt + ((tcpheader->doff - 5) * 4); // number of 32bit words in the options

	while(tcpopt < optend) {
		switch(*tcpopt) {
			case TCPOPT_EOL:
			case TCPOPT_NOP:
				tcpopt++;
				break;

			case TCPOPT_MAXSEG:
				tcpopt += tcpopt[1];
				break;

			case TCPOPT_WINDOW:
				sender->windowscale = (uint8_t)tcpopt[2];
				printf(" WINDOW %hhu ", sender->windowscale);
				tcpopt += tcpopt[1];
				break;

			case TCPOPT_SACK_PERMITTED:
				tcpopt += tcpopt[1];
				break;

			case TCPOPT_SACK:
				printf(" SACK ");
				tcpopt += tcpopt[1];
				break;

			case TCPOPT_TIMESTAMP:
				tcpopt += tcpopt[1];
				break;


			default:
				printf("bad option");
				break;
		}
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
	printf("%u.%03u \t", sesh->id, sesh->counter);

	//printf("%s:%hu -> ", inet_ntoa(s->src.ip), ntohs(s->src.port));
	//printf("%s:%hu ",inet_ntoa(s->dest.ip), ntohs(s->dest.port));

	int direction = setState( s, sesh, tcpheader );
	//printf(" %d src: %s ", sesh->id, getStateString( sesh->src.state ) );
	//printf("dest: %s ", getStateString( sesh->dest.state ) );

	struct host *srchost, *desthost;
	if( direction == 0 ) {
		printf(" --> ");
		srchost = &(sesh->src);
		desthost = &(sesh->dest);
	} else {
		srchost = &(sesh->dest);
		desthost = &(sesh->src);
		printf(" <-- ");
	}
	processOptions( srchost, tcpheader );
	srchost->window = ntohs(tcpheader->window) << srchost->windowscale;

	if( tcpheader->syn == 1) {
		static char filename[20];
		if( direction == 0 ) {
			sesh->src.seq = curseq + 1;
			snprintf(filename, 20, "%d.%s", sesh->id, "out");
			sesh->src.diskout = fopen(filename, "a");
		} else {
			sesh->dest.seq = curseq + 1;
			snprintf(filename, 20, "%d.%s", sesh->id, "in");
			sesh->dest.diskout = fopen(filename, "a");
		}
	} else 	if( (sesh->src.state == TCP_ESTABLISHED) || (sesh->dest.state == TCP_ESTABLISHED) ) {
		void *tcpdata = ((void*)tcpheader) + (tcpheader->doff * 4);
		int tcpdatalen = tcplen - ((void*)tcpdata - (void*)tcpheader);
		printf(" window:%d ", srchost->window);
		printf(" len: %04d  \t", tcpdatalen );
		if( tcpdatalen > 0 ) {
			bufferTCP(curseq, srchost, desthost, tcpdata, tcpdatalen);
		}
	} else 	if( tcpheader->fin == 1 ) {
		// on FIN, close files, free(sesh)
		printf(" fin ");
		if( srchost->diskout != NULL ) {
			fclose(srchost->diskout);
			printf("CLOSE!");
		}
	} else {
		printf(" BAD ");
	}
	printf("\n");
}

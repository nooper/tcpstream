#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "session.h"

int tcp2disk( struct host* src, void* tcpdata, int len );

int setState( session_t *sesh, struct tcphdr *h, int direction ) {

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

bool CheckWindow(uint32_t left, uint32_t seq, uint32_t right) {
	if( left == seq && seq == right) return true;
	if( left <= right ) {
		if( (left <= seq) && (seq < right) ) {
			return true;
		}
	} else {
		if( !(left <= seq && seq < right ) ) {
			return true;
		}
	}
	return false;
}

bool OverLap(uint32_t L1, uint32_t R1, uint32_t L2, uint32_t R2) {
	return CheckWindow(L1, L2, R1) || CheckWindow(L2, L1, R2);
}

void writeBuffer( void* buf, int buflen, uint32_t bufseq, struct host* src ) {
	/* assumes curseq is in provided buffer */
	int offset = src->seq - bufseq;
	int usefulLen = buflen - offset;
	tcp2disk( src, buf + offset, usefulLen );
	printf(" written %i ", usefulLen);
	src->seq += usefulLen;
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

			case TCPOPT_WINDOW:
				sender->windowscale = (uint8_t)tcpopt[2];
				printf(" WINDOW %hhu ", sender->windowscale);
				tcpopt += tcpopt[1];
				break;

			case TCPOPT_MAXSEG:
			case TCPOPT_SACK_PERMITTED:
			case TCPOPT_TIMESTAMP:
				tcpopt += tcpopt[1];
				break;

			case TCPOPT_SACK:
				printf(" SACK ");
				tcpopt += tcpopt[1];
				break;

			default:
				printf("bad option");
				break;
		}
	}

}

void singlePacket( session_t *sesh, struct tcphdr *tcpheader, int tcplen, int direction) {
	uint32_t curseq, curack;
	curseq = ntohl(tcpheader->seq);
	curack = ntohl(tcpheader->ack_seq);
	//printf("seq: %u ack: %u \t", curseq, curack);

	printf("%s:%hu -> ", inet_ntoa(sesh->src.ip), sesh->src.port);
	printf("%s:%hu ",inet_ntoa(sesh->dest.ip), sesh->dest.port);

	//printf(" %d src: %s ", sesh->id, getStateString( sesh->src.state ) );
	//printf("dest: %s ", getStateString( sesh->dest.state ) );

	struct host *srchost, *desthost;
	if( direction == 0 ) {
		srchost = &(sesh->src);
		desthost = &(sesh->dest);
	} else {
		srchost = &(sesh->dest);
		desthost = &(sesh->src);
	}
	setState( sesh, tcpheader, direction );
	processOptions( srchost, tcpheader );
	srchost->window = ntohs(tcpheader->window) << srchost->windowscale;
	printf(" (%d) ", desthost->bufcount);

	if( tcpheader->syn == 1) {
		char filename[20];
		srchost->seq = curseq + 1;
		snprintf(filename, 20, "%d.%hu.%d", sesh->id, srchost->port, direction);
		srchost->diskout = fopen(filename, "a");
	} else 	if( (sesh->src.state == TCP_ESTABLISHED) || (sesh->dest.state == TCP_ESTABLISHED) ) {
		void *tcpdata = ((void*)tcpheader) + (tcpheader->doff * 4);
		int tcpdatalen = tcplen - ((void*)tcpdata - (void*)tcpheader);
		printf(" window:%d ", srchost->window);
		printf(" len: %04d  \t", tcpdatalen );
		if( tcpdatalen > 0 ) {
			writeBuffer( tcpdata, tcpdatalen, curseq, srchost );
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
}

void ll_remove2( struct ll *buffer, struct host *dest ) {
	remque(buffer);
	if( buffer->prev == NULL ) {
		dest->bufhead = buffer->next;
	}
	if( buffer->next == NULL ) {
		dest->buftail = buffer->prev;
	}
	dest->bufcount--;
}

struct ll* ll_remove(uint32_t seq, struct host* dest) {
	struct ll* buffer = dest->bufhead;
	while( buffer != NULL ) {
		uint32_t curseq = ntohl(buffer->packet->seq);
		struct tcphdr *tcpheader = buffer->packet;
		void *tcpdata = ((void*)tcpheader) + (tcpheader->doff * 4);
		int tcpdatalen = buffer->len - ((void*)tcpdata - (void*)tcpheader);
		if( CheckWindow(curseq, seq, curseq + tcpdatalen) ) {
			ll_remove2(buffer, dest);
			return buffer;
		} else {
			if( OverLap(seq, seq + dest->window, curseq, curseq + tcpdatalen) == false ) {
				ll_remove2(buffer, dest);
				struct ll *temp = buffer->next;
				free(buffer->packet);
				free(buffer);
				buffer = temp;
			} else {
				buffer = buffer->next;
			}
		}
	}
	return buffer;
}

void ll_insert(uint32_t tcplen, struct tcphdr *packet, struct host *desthost) {
	struct ll* node = (struct ll*)malloc(sizeof(struct ll));
	node->next = node->prev = NULL;
	node->len = tcplen;
	node->packet = malloc(tcplen);
	memcpy(node->packet, packet, tcplen);
	if( desthost->bufhead == NULL ) {
		desthost->bufhead = desthost->buftail = node;
	} else {
		uint32_t curseq = ntohl(packet->seq);
		struct ll *after = desthost->buftail;
		while( after != NULL ) {
			if( curseq >= ntohl(after->packet->seq) ) {
					insque(node, after);
					after = NULL;
			} else {
				after = after->prev;
			}
		}
		if(node->next == NULL) {
			desthost->buftail = node;
		}
		if(node->prev == NULL) {
			desthost->bufhead = node;
		}
	}
	desthost->bufcount++;
}

void decodeTCP( session_t *s, struct tcphdr* tcpheader, int tcplen ) {
	int direction;
	// get session struct
	s->src.port = ntohs(tcpheader->source);
	s->dest.port = ntohs(tcpheader->dest);
	session_t *sesh = getSessionID( s, &direction );
	sesh->counter++;
	printf("%u.%03u \t", sesh->id, sesh->counter);

	struct host *srchost, *desthost;
	if( direction == 0 ) {
		srchost = &(sesh->src);
		desthost = &(sesh->dest);
		printf(" --> ");
	} else {
		srchost = &(sesh->dest);
		desthost = &(sesh->src);
		printf(" <-- ");
	}

	if( tcpheader->syn == 1) {
		singlePacket( sesh, tcpheader, tcplen, direction );
		tcpheader = NULL;
		printf("\n");
	}

	int freeme = 0;
	while( tcpheader != NULL ) {
		void *tcpdata = ((void*)tcpheader) + (tcpheader->doff * 4);
		int tcpdatalen = tcplen - ((void*)tcpdata - (void*)tcpheader);
		uint32_t curseq = ntohl(tcpheader->seq);
		if( OverLap(curseq, curseq + tcpdatalen, srchost->seq, srchost->seq + desthost->window) ) { //if any part of the packet is in the window
			if( CheckWindow(curseq, srchost->seq, curseq + tcpdatalen) ) { //if this packet contains the next seq
				singlePacket( sesh, tcpheader, tcplen, direction );
				struct ll *next = ll_remove( srchost->seq, desthost);
				if( next == NULL ) {
					tcpheader = NULL;
				} else {
					if( freeme == 1 ) {
						free(tcpheader);
					}
					tcplen = next->len;
					tcpheader = next->packet;
					free(next);
					freeme = 1;
				}
			} else { // buffer this packet
				ll_insert(tcplen, tcpheader, desthost);
				printf(" buffering");
				tcpheader = NULL;
			}
		} else {
			printf(" ignored");
			tcpheader = NULL;
		}
		printf("\n");
	}
}

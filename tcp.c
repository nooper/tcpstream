#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "diskwriter.h"

int setState( session_t *sesh, struct tcphdr *h, int direction ) {
	struct host *srchost, *desthost;
	if( direction == 0 ) {
		srchost = &(sesh->src);
		desthost = &(sesh->dest);
	} else {
		srchost = &(sesh->dest);
		desthost = &(sesh->src);
	}

	uint32_t curseq = ntohl(h->seq);
	uint32_t curack = ntohl(h->ack_seq);

	switch( srchost->state ) {
		case TCP_CLOSE:
			if( h->syn == 1 && desthost->state == TCP_LISTEN ) {
				srchost->state = TCP_SYN_SENT;
				desthost->state = TCP_SYN_RECV;
			}
			break;

		case TCP_SYN_RECV:
			if( h->syn == 1 && h->ack == 1 && desthost->state == TCP_SYN_SENT ) {
				if( curack == desthost->seq ) {
					desthost->state = TCP_ESTABLISHED;
				}
			}
			break;

		case TCP_ESTABLISHED:
			if( desthost->state == TCP_SYN_RECV && h->ack == 1 ) {
				desthost->state = TCP_ESTABLISHED;
			} else if( desthost->state == TCP_ESTABLISHED && h->fin == 1 ) {
				srchost->state = TCP_FIN_WAIT1;
				desthost->state = TCP_CLOSE_WAIT;
			}
			break;

		case TCP_CLOSE_WAIT:
			if( desthost->state == TCP_FIN_WAIT1 ) {
				if( curack == desthost->seq ) {
					desthost->state = TCP_FIN_WAIT2;
				}
			}
			if( (desthost->state == TCP_FIN_WAIT2 || desthost->state == TCP_FIN_WAIT1) && h->fin == 1 ) {
				srchost->state = TCP_LAST_ACK;
				desthost->state = TCP_TIME_WAIT;
			}
			break;

		case TCP_TIME_WAIT:
			if( desthost->state == TCP_TIME_WAIT ) {
				if( curack == desthost->seq ) {
					desthost->state = TCP_CLOSE;
				}
			}
			break;



	}
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
		if( !(right <= seq && seq < left ) ) {
			return true;
		}
	}
	return false;
}

bool OverLap(uint32_t L1, uint32_t R1, uint32_t L2, uint32_t R2) {
	return CheckWindow(L1, L2, R1) || CheckWindow(L2, L1, R2);
}

void writeBuffer( session_t *sesh, int direction, void* buf, int buflen, uint32_t bufseq, struct host* src ) {
	/* assumes curseq is in provided buffer */
	int offset = src->seq - bufseq;
	int usefulLen = buflen - offset;
	disk_write( sesh, direction, src, buf + offset, usefulLen );
	DEBUG_PRINT((" written %i ", usefulLen));
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
				DEBUG_PRINT((" WS %hhu ", sender->windowscale));
				tcpopt += tcpopt[1];
				sender->supports_ws = true;
				break;

			case TCPOPT_SACK_PERMITTED:
				DEBUG_PRINT((" SACKPERM "));
				tcpopt += tcpopt[1];
				break;

			case TCPOPT_MAXSEG:
			case TCPOPT_TIMESTAMP:
				tcpopt += tcpopt[1];
				break;

			case TCPOPT_SACK:
				DEBUG_PRINT((" SACK "));
				tcpopt += tcpopt[1];
				break;

			default:
				DEBUG_PRINT(("bad option %hhu ", *(uint8_t*)tcpopt));
				return;
		}
	}

}

void singlePacket( session_t *sesh, struct tcphdr *tcpheader, int tcplen, int direction) {
	uint32_t curseq, curack;
	curseq = ntohl(tcpheader->seq);
	curack = ntohl(tcpheader->ack_seq);

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

	DEBUG_PRINT((" (%d) window:%d src: %s dest: %s ", desthost->bufcount, srchost->window, getStateString(sesh->src.state), getStateString(sesh->dest.state)));

	if( tcpheader->rst == 1 ) {
		removeSession(sesh);
		DEBUG_PRINT((" RESET "));
		return;
	}

	switch( srchost->state ) {
		case TCP_SYN_SENT:
			srchost->seq = curseq + 1;
			break;

		case TCP_SYN_RECV:
			srchost->seq = curseq + 1;
			if( srchost->supports_ws == false ) {
				desthost->windowscale = 0;
			}
			break;

		case TCP_FIN_WAIT1:
		case TCP_CLOSE_WAIT:
		case TCP_LAST_ACK:
		case TCP_ESTABLISHED: {
			srchost->window = ntohs(tcpheader->window) << srchost->windowscale;
			void *tcpdata = ((void*)tcpheader) + (tcpheader->doff * 4);
			int tcpdatalen = tcplen - ((void*)tcpdata - (void*)tcpheader);
			DEBUG_PRINT((" len: %04d  \t", tcpdatalen ));
			if( tcpdatalen > 0 ) {
				writeBuffer( sesh, direction, tcpdata, tcpdatalen, curseq, srchost );
			}
			if( tcpheader->fin == 1 ) {
				srchost->seq++;
				disk_close( srchost );
			}
			break;
		}

		case TCP_TIME_WAIT:
			DEBUG_PRINT((" done "));
			removeSession(sesh);
			break;


		default:
			if( tcpheader->rst != 1 ) {
				DEBUG_PRINT(("BAD"));
			}
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
				if( after == NULL ) { //reached the first node
					node->next = desthost->bufhead;
					node->next->prev = node;
				}
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

void decodeTCP( session_t *s, void *header, int tcplen ) {
	struct tcphdr *tcpheader = header;
	int direction;
	// get session struct
	s->src.port = ntohs(tcpheader->source);
	s->dest.port = ntohs(tcpheader->dest);
	session_t *sesh = getSessionID( s, &direction );
	if( sesh == NULL ) {
		if( tcpheader->syn == 1 ) {
			sesh = insertSession(s);
			direction = 0;
		} else {
			DEBUG_PRINT(("ignored\n"));
			return;
		}
	}
	sesh->counter++;
	DEBUG_PRINT(("%u.%03u \t", sesh->id, sesh->counter));

	DEBUG_PRINT(("%s:%hu", inet_ntoa(sesh->src.ip), sesh->src.port));
	struct host *srchost, *desthost;
	if( direction == 0 ) {
		srchost = &(sesh->src);
		desthost = &(sesh->dest);
		DEBUG_PRINT((" --> "));
	} else {
		srchost = &(sesh->dest);
		desthost = &(sesh->src);
		DEBUG_PRINT((" <-- "));
	}
	DEBUG_PRINT(("%s:%hu ",inet_ntoa(sesh->dest.ip), sesh->dest.port));

	if( tcpheader->syn == 1) {
		singlePacket( sesh, tcpheader, tcplen, direction );
		tcpheader = NULL;
		DEBUG_PRINT(("\n"));
	}

	int freeme = 0;
	while( tcpheader != NULL ) {
		void *tcpdata = ((void*)tcpheader) + (tcpheader->doff * 4);
		int tcpdatalen = tcplen - ((void*)tcpdata - (void*)tcpheader);
		uint32_t curseq = ntohl(tcpheader->seq);
		DEBUG_PRINT(("seq: %u \t", curseq));
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
				DEBUG_PRINT((" buffering"));
				tcpheader = NULL;
			}
		} else {
			uint32_t endOfWindow = srchost->seq + desthost->window;
			if( CheckWindow( endOfWindow, curseq, endOfWindow + 2147483648 ) ) {
				DEBUG_PRINT((" ignored: after window "));
			} else {
				DEBUG_PRINT((" ignored: before window "));
			}
			tcpheader = NULL;
		}
		DEBUG_PRINT(("\n"));
	}
}

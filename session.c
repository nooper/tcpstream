#include <stdlib.h>
#include <netinet/tcp.h>
#include <search.h>
#include <string.h>
#include "session.h"

int compare_host ( struct in_addr ipa, struct in_addr ipb, uint16_t porta, uint16_t portb ) {
	int32_t ip1, ip2;
	uint16_t port1, port2;

	ip1 = (int32_t) htonl(ipa.s_addr);
	ip2 = (int32_t) htonl(ipb.s_addr);
	port1 = htons(porta);
	port2 = htons(portb);

	if( ip1 < ip2 ) {
		return -1;
	} else if( ip1 == ip2 ) {
		if( port1 < port2 ) {
			return -1;
		} else if( port1 == port2 ) {
			return 0;
		} else {
			return 1;
		}
	} else {
		return 1;
	}
}


int compare_session( const void *a, const void *b ) {
	session_t *x = (session_t*) a;
	session_t *y = (session_t*) b;

	int temp = 0;

	temp = compare_host( x->src.ip, y->src.ip, x->src.port, y->src.port );
	if( temp == 0 ) {
		temp = compare_host( x->dest.ip, y->dest.ip, x->dest.port, y->dest.port );
		if( temp == 0 ) {
			// match!
			return temp;
		}
	} 

	// no match. flip hosts and check again
	temp = compare_host( x->src.ip, y->dest.ip, x->src.port, y->dest.port );
	if( temp == 0 ) {
		temp = compare_host( x->dest.ip, y->src.ip, x->dest.port, y->src.port );
		if( temp == 0 ) {
			// match!
			return temp;
		}
	}

	// no match
	return temp;

}

session_t * getSessionID( session_t *s ) {
	static session_t *sessionList = NULL;
	static int sessionid = 0;
	session_t *iterator = sessionList;
	while(iterator != NULL) {
		//search and return
		if( compare_session(s, iterator) == 0 ) {
			return iterator;
		} else {
			iterator = iterator->next;
		}
	}
	//insert
	session_t *newsession = malloc(sizeof(session_t));
	memcpy( newsession, s, sizeof(session_t) );
	newsession->next = newsession->prev = NULL;
	newsession->id = ++sessionid;
	newsession->src.state = TCP_CLOSE;
	newsession->dest.state = TCP_LISTEN;
	newsession->src.buf = newsession->dest.buf = NULL;
	newsession->src.diskout = newsession->dest.diskout = NULL;
	newsession->src.bufcount = newsession->dest.bufcount = 0;
	newsession->src.windowscale = newsession->dest.windowscale = 0;
	if( sessionList == NULL ) {
		sessionList = newsession;
	} else {
		insque( newsession, sessionList );
	}
	return newsession;
}

bool CheckWindow(uint32_t left, uint32_t seq, uint32_t right) {
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

void ll_put(uint32_t seq, int len, void* tcpdata, struct host* dest){
	struct ll* node = (struct ll*)malloc(sizeof(struct ll));
	node->next = node->prev = NULL;
	node->seq = seq;
	node->len = len;
	node->tcpdata = malloc(len);
	memcpy(node->tcpdata, tcpdata, len);
	if( dest->buf == NULL ) {
		dest->buf = node;
	} else {
		insque( node, dest->buf );
	}
}

struct ll* ll_get(uint32_t seq, struct host* dest) {
	struct ll* buffer = dest->buf;
	while( buffer != NULL ) {
		if( CheckWindow(buffer->seq, seq, buffer->seq + buffer->len) ) {
			remque(buffer);
			if( buffer->prev == NULL ) {
				dest->buf = buffer->next;
			}
			return buffer;
		} else {
			buffer = buffer->next;
		}
	}
	return buffer;
}

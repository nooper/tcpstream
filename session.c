#include <stdlib.h>
#include <netinet/tcp.h>
#include <search.h>
#include <string.h>
#include "session.h"

int compare_host ( struct in_addr ipa, struct in_addr ipb, uint16_t porta, uint16_t portb ) {
	if( ipa.s_addr == ipb.s_addr ) {
		if( porta == portb ) {
			return 0;
		} else {
			return porta - portb;
		}
	} else {
		return ipa.s_addr - ipb.s_addr;
	}
}


int compare_session( const void *a, const void *b ) {
	session_t *x = (session_t*) a;
	session_t *y = (session_t*) b;

	unsigned int temp = 0;

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
	static void *treeroot = NULL;
	static int sessionid = 0;
	//printf("%s:%hu -> %s:%hu ", inet_ntoa(s->srcip), ntohs(s->srcport), inet_ntoa(s->destip), ntohs(s->destport));

	session_t **z = tfind(s, &treeroot, compare_session);
	if( z == NULL ) {
		//copy s and call tsearch
		session_t *newsession = malloc(sizeof(session_t));
		memcpy( newsession, s, sizeof(session_t) );
		newsession->id = ++sessionid;
		newsession->src.state = TCP_CLOSE;
		newsession->dest.state = TCP_LISTEN;
		newsession->src.buf = newsession->dest.buf = NULL;
		newsession->src.diskout = newsession->dest.diskout = NULL;
		newsession->src.bufcount = newsession->dest.bufcount = 0;
		z = tsearch(newsession, &treeroot, compare_session);
	}

	return *z;
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
		if(buffer->seq == seq) {
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

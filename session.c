#include <stdlib.h>
#include <netinet/tcp.h>
#include <search.h>
#include <string.h>
#include "session.h"

static void action(const void *nodep, const VISIT which, const int depth)
{
	session_t *datap;

	switch (which) {
		case preorder:
			break;
		case postorder:
			datap = *(session_t **) nodep;
			printf(" [id:%d depth:%d] ", datap->id, depth);
			break;
		case endorder:
			break;
		case leaf:
			datap = *(session_t **) nodep;
			printf(" [id:%d depth:%d] ", datap->id, depth);
			break;
	}
}

int compare_host ( struct in_addr ipa, struct in_addr ipb, uint16_t porta, uint16_t portb ) {
	int32_t ip1, ip2;
	uint16_t port1, port2;
	ip1 = (int32_t) ipa.s_addr;
	ip2 = (int32_t) ipb.s_addr;
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
	printf(" not %d ", y->id);
	return temp;

}


session_t * getSessionID( session_t *s ) {
	static void *treeroot = NULL;
	static int sessionid = 0;
	//printf("%s:%hu -> %s:%hu ", inet_ntoa(s->srcip), ntohs(s->srcport), inet_ntoa(s->destip), ntohs(s->destport));

	session_t **z = tfind(s, &treeroot, compare_session);
	if( z == NULL ) {
		//copy s and call tsearch
		//twalk(treeroot, action);
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

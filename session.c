#include <stdlib.h>
#include <netinet/tcp.h>
#include <search.h>
#include <string.h>
#include "diskwriter.h"

session_t *sessionList = NULL;
int sessionid = 0;

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


int compare_session( const void *a, const void *b, int *direction ) {
	session_t *x = (session_t*) a;
	session_t *y = (session_t*) b;

	int temp = 0;

	temp = compare_host( x->src.ip, y->src.ip, x->src.port, y->src.port );
	if( temp == 0 ) {
		temp = compare_host( x->dest.ip, y->dest.ip, x->dest.port, y->dest.port );
		if( temp == 0 ) {
			// match!
			*direction = 0;
			return temp;
		}
	} 

	// no match. flip hosts and check again
	temp = compare_host( x->src.ip, y->dest.ip, x->src.port, y->dest.port );
	if( temp == 0 ) {
		temp = compare_host( x->dest.ip, y->src.ip, x->dest.port, y->src.port );
		if( temp == 0 ) {
			// match!
			*direction = 1;
			return temp;
		}
	}

	// no match
	return temp;

}

session_t * getSessionID( session_t *s, int *direction ) {
	session_t *iterator = sessionList;
	while(iterator != NULL) {
		//search and return
		if( compare_session(s, iterator, direction) == 0 ) {
			break;
		} else {
			iterator = iterator->next;
		}
	}
	return iterator;
}

void removeSession( session_t *sesh ) {
	session_t *iter = sessionList;
	while( iter != NULL ) {
		if( sesh == iter ) {
			remque(iter);
			if( iter->prev == NULL ) {
				sessionList = iter->next;
			}
			disk_close( &(iter->src) );
			disk_close( &(iter->dest) );
			free(iter);
			DEBUG_PRINT((" removed sesh "));
			break;
		} else {
			iter = iter->next;
		}
	}
}

session_t * insertSession( session_t *s ) {
	session_t *newsession = malloc(sizeof(session_t));
	memcpy( newsession, s, sizeof(session_t) );
	newsession->next = newsession->prev = NULL;
	newsession->id = ++sessionid;
	newsession->src.state = TCP_CLOSE;
	newsession->dest.state = TCP_LISTEN;
	newsession->src.bufhead = newsession->dest.bufhead = NULL;
	newsession->src.buftail = newsession->dest.buftail = NULL;
	newsession->src.diskout = newsession->dest.diskout = NULL;
	newsession->src.bufcount = newsession->dest.bufcount = 0;
	newsession->src.windowscale = newsession->dest.windowscale = 0;
	newsession->src.window = newsession->dest.window = 0;
	if( sessionList == NULL ) {
		sessionList = newsession;
	} else {
		insque( newsession, sessionList );
	}
	return newsession;
}

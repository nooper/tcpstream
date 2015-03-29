#include <stdint.h>
#include <netinet/ip.h>
#include "ll.h"

struct host {
	struct in_addr ip;
	uint16_t port;
	int state;
	uint32_t seq;
	struct ll *buf;
};


typedef struct tcp_session {
	int id, counter;
	struct host src, dest;
} session_t;

int compare_session( const void *a, const void *b );
session_t * getSessionID( session_t *s );

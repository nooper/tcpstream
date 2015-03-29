#include <stdint.h>
#include <netinet/ip.h>
#include <stdio.h>
#include "ll.h"

struct ll {
	struct ll* next;
	struct ll* prev;
	uint32_t seq;
	int len;
	void *tcpdata;
};

struct host {
	struct in_addr ip;
	uint16_t port;
	int state;
	uint32_t seq;
	struct ll *buf;
	FILE* diskout;
};


typedef struct tcp_session {
	int id, counter;
	struct host src, dest;
} session_t;


void ll_put(uint32_t seq, int len, void* tcpdata, struct host* dest);
struct ll* ll_get(uint32_t seq, struct host* dest);
int compare_session( const void *a, const void *b );
session_t * getSessionID( session_t *s );

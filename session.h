#include <stdint.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef DEBUG
# define DEBUG_PRINT(x) printf x
#else
# define DEBUG_PRINT(x) do {} while (0)
#endif

struct ll {
	struct ll* next;
	struct ll* prev;
	int len;
	struct tcphdr *packet;
};

struct host {
	struct in_addr ip;
	uint16_t port;
	int state;
	uint32_t seq;
	struct ll *bufhead, *buftail;
	FILE* diskout;
	int bufcount;
	int window;
	int windowscale;
};


typedef struct tcp_session {
	struct tcp_session* next;
	struct tcp_session* prev;
	int id, counter;
	struct host src, dest;
} session_t;


int compare_session( const void *a, const void *b, int *direction );
session_t * getSessionID( session_t *s, int *direction );
void removeSession( session_t *sesh );
session_t * insertSession( session_t *s );

#include <stdint.h>
#include <netinet/ip.h>



typedef struct tcp_session {
	struct in_addr srcip, destip;
	uint16_t srcport, destport;
	int id;
} session_t;

int compare_session( const void *a, const void *b );

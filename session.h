#include <stdint.h>
#include <netinet/ip.h>



typedef struct tcp_session {
	struct in_addr srcip, destip;
	uint16_t srcport, destport;
	uint32_t src_needackupto, dest_needackupto;
	uint32_t src_nextseq, dest_nextseq;
	int srcstate, deststate;
	int id, counter;
} session_t;

int compare_session( const void *a, const void *b );

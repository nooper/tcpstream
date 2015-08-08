#include <netinet/udp.h>
#include "diskwriter.h"

void decodeUDP(session_t *s, void *udpheader, uint16_t len) {
	struct udphdr *header = (struct udphdr *)udpheader;
	s->src.port = ntohs(header->source);
	s->dest.port = ntohs(header->dest);
	int direction;
	session_t *sesh = getSessionID( s, &direction );
	if( sesh == NULL ) {
		sesh = insertSession(s);
		direction = 0;
	}
	if( len != ntohs(header->len) ) {
		DEBUG_PRINT(("mismatch!\n"));
	}
	struct host *srchost, *desthost;
	if( direction == 0 ) {
		srchost = &(sesh->src);
		desthost = &(sesh->dest);
	} else {
		srchost = &(sesh->dest);
		desthost = &(sesh->src);
	}

	void *udpdata = udpheader + 8;

	disk_write( sesh, direction, srchost, udpdata, len - 8 );
	disk_close( srchost );
}

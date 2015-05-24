#include <stdio.h>
#include "session.h"

void disk_open( session_t *sesh, struct host *srchost, int direction ) {
	char filename[20];
	snprintf(filename, 20, "%d.%hu.%d", sesh->id, srchost->port, direction);
	srchost->diskout = fopen(filename, "a");
}

int disk_write( session_t *sesh, int direction, struct host* src, void* tcpdata, int len ) {
	if( src->diskout == NULL ) {
		disk_open( sesh, src, direction );
	}
	return fwrite( tcpdata, len, 1, src->diskout );
}

void disk_close( struct host* src ) {
	if( src->diskout != NULL ) {
		fclose(src->diskout);
		src->diskout = NULL;
		DEBUG_PRINT(("fclose"));
	}
}


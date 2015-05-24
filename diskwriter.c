#include <stdio.h>
#include "session.h"


int disk_write( struct host* src, void* tcpdata, int len ) {
	static int bytesWritten = 0;
	bytesWritten += fwrite( tcpdata, len, 1, src->diskout );
	return bytesWritten;
}

void disk_close( struct host* src ) {
	if( src->diskout != NULL ) {
		fclose(src->diskout);
		src->diskout = NULL;
		DEBUG_PRINT(("fclose"));
	}
}

void disk_open( session_t *sesh, struct host *srchost, int direction ) {
	char filename[20];
	snprintf(filename, 20, "%d.%hu.%d", sesh->id, srchost->port, direction);
	srchost->diskout = fopen(filename, "a");
}

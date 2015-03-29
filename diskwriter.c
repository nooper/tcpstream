#include <stdio.h>
#include "session.h"


int tcp2disk( struct host* src, void* tcpdata, int len ) {
	static int bytesWritten = 0;
	bytesWritten += fwrite( tcpdata, len, 1, src->diskout );
	return bytesWritten;
}

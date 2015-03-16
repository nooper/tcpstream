#include <stdio.h>
#include "session.h"


int tcp2disk( session_t* sesh, void* tcpdata, int len, int direction ) {
	//write it to file for now
	printf(" >%i< ", len);
	static int bytesWritten = 0;
	FILE *srcout, *destout;
	srcout = fopen("srcout", "a");
	destout = fopen("destout", "a");
	if( direction == 0 ) {
		bytesWritten += fwrite( tcpdata, len, 1, srcout );
	} else {
		bytesWritten += fwrite( tcpdata, len, 1, destout );
	}
	fclose(srcout);
	fclose(destout);
	return bytesWritten;
}

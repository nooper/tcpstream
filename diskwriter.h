#include "session.h"

int disk_write( struct host* src, void* tcpdata, int len );
void disk_open( session_t *sesh, struct host *srchost, int direction );
void disk_close( struct host* src );

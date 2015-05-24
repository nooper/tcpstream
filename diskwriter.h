#include "session.h"

int disk_write( session_t *sesh, int direction, struct host* src, void* tcpdata, int len );
void disk_close( struct host* src );

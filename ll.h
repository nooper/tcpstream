#include <stdint.h>

struct ll {
	struct ll* next;
	struct ll* prev;
	uint32_t seq;
	int len;
	void *tcpdata;
};

void ll_put(uint32_t seq, int len, void* tcpdata, struct ll* buffer);

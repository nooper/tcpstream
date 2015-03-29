#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ll.h"


void ll_put(uint32_t seq, int len, void* tcpdata, struct ll* buffer){
	struct ll* node = (struct ll*)malloc(sizeof(struct ll));
	node->next = node->prev = NULL;
	node->seq = seq;
	node->len = len;
	node->tcpdata = malloc(len);
	memcpy(node->tcpdata, tcpdata, len);
	if( buffer == NULL ) {
		buffer = node;
	} else {
		insque( node, buffer );
	}
	printf("DONE");
}

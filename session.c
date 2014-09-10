#include "session.h"

int compare_host ( struct in_addr ipa, struct in_addr ipb, uint16_t porta, uint16_t portb ) {
	if( ipa.s_addr == ipb.s_addr ) {
		if( porta == portb ) {
			return 0;
		} else {
			return porta - portb;
		}
	} else {
		return ipa.s_addr - ipb.s_addr;
	}
}


int compare_session( const void *a, const void *b ) {
	session_t *x = (session_t*) a;
	session_t *y = (session_t*) b;

	unsigned int temp = 0;

	temp = compare_host( x->srcip, y->srcip, x->srcport, y->srcport );
	if( temp == 0 ) {
		temp = compare_host( x->destip, y->destip, x->destport, y->destport );
		if( temp == 0 ) {
			// match!
			return temp;
		}
	} 

	// no match. flip hosts and check again
	temp = compare_host( x->srcip, y->destip, x->srcport, y->destport );
	if( temp == 0 ) {
		temp = compare_host( x->destip, y->srcip, x->destport, y->srcport );
		if( temp == 0 ) {
			// match!
			return temp;
		}
	}

	// no match
	return temp;

}

/*
 * akm-break-security-association.c
 *
 *  Created on: Jul 25, 2013
 *      Author: local
 */
#include "random.h"
#include "contiki.h"
#include "net/mac/nullmac.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include  "mac/akm-mac.h"
#include  "packetbuf.h"
#include "clock.h"


/*-----------------------------------------------------------------------*/
#ifdef AKM_DEBUG

char* get_break_security_association_continuation_as_string(
		bsa_continuation continuation) {
	switch (continuation) {
	case BSA_CONTINUATION_NONE:
		return " BSA_CONTINUATION_NONE";
		break;
	case BSA_CONTINUATION_INSERT_NODE :
		return " BSA_CONTINUATION_INSERT_NODE";
		break;
	default:
		return "INTERNAL ERROR -- unknown option";
	}
}

#endif
/*----------------------------------------------------------------------*/

void handle_break_security_association(
		break_security_association_request_t* pbsa) {

	nodeid_t* senderId = & AKM_DATA.sender_id;
	AKM_PRINTF("handle_break_security_association continuation = %s  sender = " ,
			GET_BSA_CONTINUATION_AS_STRING(pbsa->continuation));
	AKM_PRINTADDR(senderId);
	if (get_authentication_state(senderId) != AUTHENTICATED  &&
			get_authentication_state(senderId) != AUTH_PENDING) {
		AKM_PRINTF("Not authenticated sender!");
		return;
	}
	if ( AKM_DATA.is_dodag_root) {
		free_security_association(senderId);
	} else {
			free_security_association(senderId);
			remove_parent(senderId);
	}
}




/*----------------------------------------------------------------------*/
void send_break_security_association(nodeid_t* target, bsa_continuation continuation, nodeid_t* pnodeid) {
#ifdef AKM_DEBUG
	AKM_PRINTF("send_break_security_association : continuaiton = %s target = ",
			get_break_security_association_continuation_as_string(continuation));
	AKM_PRINTADDR(target);
#endif
	AKM_MAC_OUTPUT.data.bsa_request.continuation = continuation;
	if ( pnodeid != NULL ) {
		rimeaddr_copy(&AKM_MAC_OUTPUT.data.bsa_request.insert_node_requester,pnodeid);
	}
	if ( continuation == BSA_CONTINUATION_NONE ) {
		free_security_association(target);
	}
	akm_send(target,BREAK_SECURITY_ASSOCIATION_REQUEST,sizeof(AKM_MAC_OUTPUT.data.bsa_request));

}





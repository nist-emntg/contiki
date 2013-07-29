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

/*----------------------------------------------------------------------*/

void handle_break_security_association( nodeid_t* senderId,
		break_security_association_request_t* pbsa) {
	if (get_authentication_state(senderId) != AUTHENTICATED  &&
			get_authentication_state(senderId) != AUTH_PENDING) {
		AKM_PRINTF("Not authenticated sender!");
		return;
	}
	if ( AKM_DATA.is_dodag_root) {
		free_security_association(senderId);
		AKM_MAC_OUTPUT.data.bsa_reply.status_code = BSA_OK;
		akm_send(senderId,BREAK_SECURITY_ASSOCIATION_REPLY,sizeof(break_security_association_reply_t));
	} else {
		if(pbsa->continuation == BSA_CONTINUATION_INSERT_NODE){
			nodeid_t* requestingNodeId = &pbsa->continuation_data;
			if ( rimeaddr_cmp(&AKM_DATA.temporaryLink,requestingNodeId )) {
				send_confirm_temporary_link(requestingNodeId,getNodeId(),senderId);
			}
		} else {
			free_security_association(senderId);
			remove_parent(senderId);
		}
	}
}

/*----------------------------------------------------------------------*/
void handle_break_security_association_reply(nodeid_t* sender, break_security_association_reply_t* msg) {
	if (msg->status_code == BSA_OK) {
		/* Free the security association correspondinvg to the sender */
		free_security_association(sender);
		make_temporary_link_permanent();
		remove_parent(sender);
	} else {
		drop_temporary_link();
	}

}

/*----------------------------------------------------------------------*/
void send_break_security_association(nodeid_t* target, bsa_continuation continuation, nodeid_t* pnodeid) {
	AKM_MAC_OUTPUT.data.bsa_request.continuation = continuation;
	if ( pnodeid != NULL ) {
		rimeaddr_copy(&AKM_MAC_OUTPUT.data.bsa_request.continuation_data,pnodeid);
	}
	if ( continuation == BSA_CONTINUATION_NONE ) {
		free_security_association(target);
	}
	akm_send(target,BREAK_SECURITY_ASSOCIATION_REQUEST,sizeof(AKM_MAC_OUTPUT.data.bsa_request));

}

/*----------------------------------------------------------------------*/
void send_break_security_association_reply(nodeid_t *nodeId,
		bsa_status_code status) {
	AKM_MAC_OUTPUT.data.bsa_reply.status_code = status;
	akm_send(nodeId,BREAK_SECURITY_ASSOCIATION_REPLY,sizeof(AKM_MAC_OUTPUT.data.bsa_reply));

}





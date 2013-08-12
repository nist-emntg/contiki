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
#ifdef AKM_DEBUG
#define AKM_PRINT_BSACONTINUATION print_break_security_association_continuation
#else
#define AKM_PRINT_BSACONTINUATION
#endif

/*-----------------------------------------------------------------------*/
#ifdef AKM_DEBUG

void print_break_security_association_continuation(
		bsa_continuation continuation) {
	switch (continuation) {
	case BSA_CONTINUATION_NONE:
		AKM_PRINTF(" BSA_CONTINUATION_NONE\n");
		break;
	case BSA_CONTINUATION_INSERT_NODE :
		AKM_PRINTF(" BSA_CONTINUATION_INSERT_NODE\n");
		break;
	default:
		AKM_PRINTF("INTERNAL ERROR \n");
	}
}

#endif
/*----------------------------------------------------------------------*/

void handle_break_security_association(
		break_security_association_request_t* pbsa) {

	nodeid_t* senderId = & AKM_DATA.sender_id;
	AKM_PRINTF("handle_break_security_association ");
	AKM_PRINTADDR(senderId);
	if (get_authentication_state(senderId) != AUTHENTICATED  &&
			get_authentication_state(senderId) != AUTH_PENDING) {
		AKM_PRINTF("Not authenticated sender!");
		return;
	}
	if ( AKM_DATA.is_dodag_root) {
		free_security_association(senderId);
	} else {
		if(pbsa->continuation == BSA_CONTINUATION_INSERT_NODE){
			nodeid_t* requestingNodeId = &pbsa->insert_node_requester;
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
/* BSA reply is only sent during INSERT-ME by the parent node after confirmation
 * of link has been received.
 */
void handle_break_security_association_reply( break_security_association_reply_t* msg) {
	nodeid_t* sender = &AKM_DATA.sender_id;
	if (msg->status_code == BSA_OK) {
		/* Free the security association corresponding to the sender */
		free_security_association(sender);
		make_temporary_link_permanent();
		remove_parent(sender);
	} else {
		drop_temporary_link();
	}

}



/*----------------------------------------------------------------------*/
void send_break_security_association(nodeid_t* target, bsa_continuation continuation, nodeid_t* pnodeid) {
	AKM_PRINTF("send_break_security_association : target = ");
	AKM_PRINTADDR(target);
	AKM_PRINT_BSACONTINUATION(continuation);
	AKM_MAC_OUTPUT.data.bsa_request.continuation = continuation;
	if ( pnodeid != NULL ) {
		rimeaddr_copy(&AKM_MAC_OUTPUT.data.bsa_request.insert_node_requester,pnodeid);
	}
	if ( continuation == BSA_CONTINUATION_NONE ) {
		free_security_association(target);
	}
	akm_send(target,BREAK_SECURITY_ASSOCIATION_REQUEST,sizeof(AKM_MAC_OUTPUT.data.bsa_request));

}

/*----------------------------------------------------------------------*/
void send_break_security_association_reply(nodeid_t *nodeId,
		nodeid_t * requestingNodeId) {
	AKM_MAC_OUTPUT.data.bsa_reply.status_code = BSA_OK;
	rimeaddr_copy(&AKM_MAC_OUTPUT.data.bsa_reply.requesting_node_id,requestingNodeId);
	akm_send(nodeId,BREAK_SECURITY_ASSOCIATION_REPLY,sizeof(AKM_MAC_OUTPUT.data.bsa_reply));
	free_security_association(nodeId);
}





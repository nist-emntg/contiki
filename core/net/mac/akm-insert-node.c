/*
 * insert-node.c
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

/*---------------------------------------------------------------------------*/
void handle_insert_node_request(
		insert_node_request_t* pinsertNode) {
	nodeid_t* senderId = & AKM_DATA.sender_id;

	AKM_PRINTF("handle_insert_node_request: senderId =  ");
	AKM_PRINTADDR(senderId);
	nodeid_t* parentId = &pinsertNode->parent_id;
	nodeid_t* childId = &pinsertNode->child_id;
	nodeid_t* myId = get_node_id();
	nodeid_t* requesting_nodeId = &pinsertNode->requesting_node_id;
	AKM_PRINTF("parentId = ");
	AKM_PRINTADDR(parentId);
	AKM_PRINTF("childId = ");
	AKM_PRINTADDR(childId);


	if (rimeaddr_cmp(myId,parentId)){
		/* I am the parent node */
		AKM_PRINTF("I am the parent \n");
		if (get_authentication_state(requesting_nodeId) == AUTH_PENDING) {
			send_confirm_temporary_link(requesting_nodeId,NULL,childId);
		} else {
			AKM_PRINTF("authentication_state is %s \n",
					get_auth_state_as_string(get_authentication_state(requesting_nodeId)));
		}
	} else {
		/* I am the child - forward the request to the parent. */
		/* Child gets the request first and forwards it */
		if (is_nodeid_in_parent_list(parentId)) {
			AKM_PRINTF("I am the child -- forwarding the request \n");
			rimeaddr_copy(&AKM_MAC_OUTPUT.data.insert_node.requesting_node_id,senderId);
			rimeaddr_copy(&AKM_MAC_OUTPUT.data.insert_node.parent_id,parentId);
			rimeaddr_copy(&AKM_MAC_OUTPUT.data.insert_node.child_id,myId);
			akm_send(parentId,INSERT_NODE_REQUEST,sizeof(insert_node_request_t));
		} else {
			PRINT_ERROR("I am neither the parent nor the child! OOPS!!");
			AKM_ABORT();
		}
	}
}
/*---------------------------------------------------------------------------*/
void
send_insert_node_request(nodeid_t* target,nodeid_t* parentId) {
	AKM_PRINTF("send_insert_node_request: targetId = ");
	AKM_PRINTADDR(target);
	AKM_PRINTF("send_insert_node_request: parentId = ");
	AKM_PRINTADDR(parentId);
	memcpy(&AKM_MAC_OUTPUT.data.insert_node.requesting_node_id,get_node_id(),sizeof(nodeid_t));
	memcpy(&AKM_MAC_OUTPUT.data.insert_node.parent_id, parentId,sizeof(nodeid_t));
	memcpy(&AKM_MAC_OUTPUT.data.insert_node.child_id,target,sizeof(nodeid_t));
	akm_send(target,INSERT_NODE_REQUEST,sizeof(AKM_MAC_OUTPUT.data.insert_node));
#ifdef AKM_DEBUG
	log_msg_one_node(AKM_LOG_INSERT_NODE,"INSERT_NODE",strlen("INSERT_NODE"));
#endif
}


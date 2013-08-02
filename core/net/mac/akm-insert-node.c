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
void handle_insert_node_request(nodeid_t * senderId,
		insert_node_request_t* pinsertNode) {
	nodeid_t* parentId = &pinsertNode->parent_id;
	nodeid_t* childId = &pinsertNode->child_id;
	nodeid_t* myId = getNodeId();
	nodeid_t* requesting_nodeId = &pinsertNode->requesting_node_id;

	if (!rimeaddr_cmp(&AKM_DATA.temporaryLink,senderId) ) {
		AKM_PRINTF("Not a temporary link");
		return;
	}
	if (rimeaddr_cmp(myId,parentId)){
		/* I am the parent node */
		if (temporary_link_exists()) {
			AKM_PRINTF("temporary link exists ");
			send_confirm_temporary_link(senderId,myId,childId);
		}
	} else {
		/* I am the child - forward the request to the parent. */
		/* Child gets the request first and forwards it */
		if (is_nodeid_in_parent_list(parentId)) {
			rimeaddr_copy(&AKM_MAC_OUTPUT.data.insert_node.requesting_node_id,senderId);
			rimeaddr_copy(&AKM_MAC_OUTPUT.data.insert_node.parent_id,parentId);
			rimeaddr_copy(&AKM_MAC_OUTPUT.data.insert_node.child_id,myId);
			akm_send(parentId,INSERT_NODE_REQUEST,sizeof(insert_node_request_t));
		}
	}
}
/*---------------------------------------------------------------------------*/
void
send_insert_node_request(nodeid_t* target,nodeid_t* parentId) {
	memcpy(&AKM_MAC_OUTPUT.data.insert_node.requesting_node_id,getNodeId(),sizeof(nodeid_t));
	memcpy(&AKM_MAC_OUTPUT.data.insert_node.parent_id, parentId,sizeof(nodeid_t));
	memcpy(&AKM_MAC_OUTPUT.data.insert_node.child_id,target,sizeof(nodeid_t));
	akm_send(target,INSERT_NODE_REQUEST,sizeof(AKM_MAC_OUTPUT.data.insert_node));
}


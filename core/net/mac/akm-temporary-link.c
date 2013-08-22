/*
 * temporary-link.c
 *
 *  Created on: Jul 24, 2013
 *      Author: local
 */

#include <stdio.h>
#include "random.h"
#include "contiki.h"
#include "net/mac/nullmac.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include  "mac/akm-mac.h"
#include  "packetbuf.h"
#include "clock.h"

void schedule_temp_link_timer();
void stop_temp_link_timer();

/*----------------------------------------------------------------------*/
bool_t is_temp_link_available() {
	bool_t retval;
	retval =  is_nodeid_zero(&AKM_DATA.temporaryLink);
	AKM_PRINTF("is_temp_link_available: %d \n",retval);
	return retval;
}

/*----------------------------------------------------------------------*/
void take_temporary_link(nodeid_t *nodeId) {
	AKM_PRINTF("take_temporary_link: ");
	AKM_PRINTADDR(nodeId);
	memcpy(&AKM_DATA.temporaryLink,nodeId, sizeof(AKM_DATA.temporaryLink));
	schedule_temp_link_timer();
}

/*----------------------------------------------------------------------*/
void make_temporary_link_permanent() {
	set_authentication_state(&AKM_DATA.temporaryLink,AUTHENTICATED);
	/* Null out the temp slot so it is available */
	int i = find_authenticated_neighbor(&AKM_DATA.temporaryLink);
	if ( i != -1 ) {
		memset(&AKM_DATA.temporaryLink, sizeof(AKM_DATA.temporaryLink),0);
	}
	stop_temp_link_timer();
}

/*----------------------------------------------------------------------*/
void restart_temporary_link_timer() {
	int i = find_authenticated_neighbor(&AKM_DATA.temporaryLink);
	if (i != -1) {
		akm_timer_reset(&AKM_DATA.auth_timer[i]);

	}
}

/*---------------------------------------------------------------------------*/
void schedule_temp_link_timer() {
	AKM_PRINTF("schedule_temp_link_timer \n");
	int time = TEMP_LINK_TIMER ;
	int i = find_authenticated_neighbor(&AKM_DATA.temporaryLink);
	if (i != -1) {
		akm_timer_set(&AKM_DATA.auth_timer[i] ,time,drop_temporary_link,NULL,0,TTYPE_ONESHOT);
	}
}

/*---------------------------------------------------------------------------*/
void stop_temp_link_timer() {
	int i = find_authenticated_neighbor(&AKM_DATA.temporaryLink);
	if (i != -1) {
		akm_timer_stop(&AKM_DATA.auth_timer[i]);
	}
}
/*---------------------------------------------------------------------------*/
void send_confirm_temporary_link(nodeid_t* target, nodeid_t* parent,
		nodeid_t* child){
	memcpy(&AKM_MAC_OUTPUT.data.confirm_temp_link_request.parent_id, parent,
			sizeof(nodeid_t));
	memcpy(&AKM_MAC_OUTPUT.data.confirm_temp_link_request.child_id,child,
			sizeof(nodeid_t));
	akm_send(target,CONFIRM_TEMPORARY_LINK_REQUEST, sizeof(AKM_MAC_OUTPUT.data.confirm_temp_link_request));
}

/*----------------------------------------------------------------------*/
bool_t temporary_link_exists()
{
	return rimeaddr_cmp(&AKM_DATA.temporaryLink,&rimeaddr_null);
}
/*----------------------------------------------------------------------*/
void release_temporary_link( void* pvoid)
{

	if ( !is_nodeid_zero(&AKM_DATA.temporaryLink)) {
		send_break_security_association(&AKM_DATA.temporaryLink,
			BSA_CONTINUATION_NONE,NULL);
		release_temporary_link(NULL);
	}
}


/*----------------------------------------------------------------------*/
void handle_confirm_temporary_link( confirm_temporary_link_request_t* ctl)
{

	nodeid_t* sender_id = & AKM_DATA.sender_id;
	AKM_PRINTF("handle_confirm_temporary_link : ");
	AKM_PRINTADDR(sender_id);

	nodeid_t* parentId = &ctl->parent_id;
	nodeid_t* childId = sender_id;

	if ( get_authentication_state(parentId) == AUTH_PENDING &&
			get_authentication_state(childId) == AUTH_PENDING) {

		set_authentication_state(parentId,AUTHENTICATED);
		set_authentication_state(childId,AUTHENTICATED);
		AKM_MAC_OUTPUT.data.confirm_temp_link_response.status_code = CTL_OK;
		rimeaddr_copy(&AKM_MAC_OUTPUT.data.confirm_temp_link_response.child_id,&ctl->child_id);
		rimeaddr_copy(&AKM_MAC_OUTPUT.data.confirm_temp_link_response.parent_id,&ctl->parent_id);
		rimeaddr_copy(&AKM_MAC_OUTPUT.data.confirm_temp_link_response.requesting_node_id,getNodeId());
	}
	akm_send(sender_id,CONFIRM_TEMPORARY_LINK_RESPONSE,
			sizeof(AKM_MAC_OUTPUT.data.confirm_temp_link_response));
}

/*----------------------------------------------------------------------*/
void handle_confirm_temporary_link_response(
		confirm_temporary_link_response_t* ctlr){
	nodeid_t* sender_id = &AKM_DATA.sender_id;
	AKM_PRINTF("handle_confirm_temporary_link_response : ");
	AKM_PRINTADDR(sender_id);
	nodeid_t* parentid = &ctlr->parent_id;
	nodeid_t* childid= &ctlr->child_id;
	nodeid_t* requestingNode = &ctlr->requesting_node_id;
	make_temporary_link_permanent();
	/* now we can let go of our redundant parent. TODO -- check if we still have
	 * an association with the parent.
	 */
	/* Send a break request back to my parent */
	if ( ctlr->continuation == CTL_CONTINUATION_BREAK_SECURITY_ASSOCIATION_REPLY){
			send_break_security_association_reply(childid,requestingNode);

	}
}

/*------------------------------------------------------------------------*/
void drop_temporary_link() {
	memset(&AKM_DATA.temporaryLink,sizeof(nodeid_t),0);
}
/*------------------------------------------------------------------------*/
void handle_pending_auth_timeout(nodeid_t* pnodeid) {
	AKM_PRINTF("handle_pending_auth_timeout ");
	AKM_PRINTADDR(pnodeid);
	send_break_security_association(pnodeid,BSA_CONTINUATION_NONE,NULL);
	if (rimeaddr_cmp(pnodeid,&AKM_DATA.temporaryLink)) {
		drop_temporary_link();
	}
	free_security_association(pnodeid);
}
/*---------------------------------------------------------------------------*/
void schedule_pending_authentication_timer(nodeid_t *target)
{
	AKM_PRINTF("schedule_pending_authentication_timer : ");
	AKM_PRINTADDR(target);
	int i = find_authenticated_neighbor(target);

	if (i != -1) {
		clock_time_t time = PENDING_AUTH_TIMEOUT ;
		akm_timer_set(&AKM_DATA.auth_timer[i],time, (void (*) (void *)) handle_pending_auth_timeout,target,sizeof(*target),TTYPE_ONESHOT);
	} else {
		AKM_PRINTF("cannot find target \n");
	}
}



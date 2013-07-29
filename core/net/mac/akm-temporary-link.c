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


/*----------------------------------------------------------------------*/
bool_t is_temp_link_available() {
	return is_nodeid_zero(&AKM_DATA.temporaryLink);
}

/*----------------------------------------------------------------------*/
void take_temporary_link(nodeid_t *node_id) {
	memcpy(&AKM_DATA.temporaryLink,node_id, sizeof(nodeid_t));
}

/*----------------------------------------------------------------------*/
void make_temporary_link_permanent() {
	set_authentication_state(&AKM_DATA.temporaryLink,AUTHENTICATED);
	/* Null out the temp slot so it is available */
	memset(&AKM_DATA.temporaryLink, sizeof(AKM_DATA.temporaryLink),0);
}

/*----------------------------------------------------------------------*/
void restart_temporary_link_timer() {
	ctimer_reset(&temp_link_timer);
	ctimer_restart(&temp_link_timer);
}

/*---------------------------------------------------------------------------*/
void schedule_temp_link_timer() {
	int time = (TEMP_LINK_TIMER * CLOCK_SECOND);
	ctimer_set(&temp_link_timer ,time,drop_temporary_link,NULL);
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
void handle_confirm_temporary_link(nodeid_t* sender_id, confirm_temporary_link_request_t* ctl)
{
	nodeid_t* parentId = &ctl->parent_id;
	nodeid_t* childId = sender_id;

	if ( get_authentication_state(parentId) == AUTH_PENDING &&
			get_authentication_state(childId) == AUTH_PENDING) {

		set_authentication_state(parentId,AUTHENTICATED);
		set_authentication_state(childId,AUTHENTICATED);
		AKM_MAC_OUTPUT.data.confirm_temp_link_response.status_code = CTL_OK;
		AKM_MAC_OUTPUT.data.confirm_temp_link_response.child_id = ctl->child_id;
		AKM_MAC_OUTPUT.data.confirm_temp_link_response.parent_id = ctl->parent_id;
	}
}

/*----------------------------------------------------------------------*/
void handle_confirm_temporary_link_response(nodeid_t* sender_id,
		confirm_temporary_link_response_t* ctlr){
	nodeid_t* nodeid = &ctlr->parent_id;
	make_temporary_link_permanent();
	send_break_security_association_reply(nodeid,BSA_OK);
	/* now we can let go of our redundant parent. TODO -- check if we still have
	 * an association with the parent.
	 */
	free_security_association(nodeid);
	remove_parent(nodeid);
}

/*------------------------------------------------------------------------*/
void drop_temporary_link() {
	memset(&AKM_DATA.temporaryLink,sizeof(nodeid_t),0);
}
/*------------------------------------------------------------------------*/
void handle_pending_auth_timeout(nodeid_t* pnodeid) {
	AKM_PRINTF("handle_pending_auth_timeout ");
	PRINTADDR(pnodeid);
	PRINTADDR("\n");
	send_break_security_association(pnodeid,BSA_CONTINUATION_NONE,NULL);
	if (rimeaddr_cmp(pnodeid,&AKM_DATA.temporaryLink)) {
		drop_temporary_link();
	}
	free_security_association(pnodeid);
	reset_beacon();
}
/*---------------------------------------------------------------------------*/
void schedule_pending_authentication_timer(nodeid_t *target)
{
	int i = find_authenticated_neighbor(target);

	if (i != -1) {
		if (!ctimer_expired(&AKM_DATA.auth_timer[i])) {
			ctimer_stop(&AKM_DATA.auth_timer[i]);
		}
		clock_time_t time = PENDING_AUTH_TIMEOUT * CLOCK_SECOND;
		ctimer_set(&AKM_DATA.auth_timer[i],time , handle_pending_auth_timeout, target);
	}
}



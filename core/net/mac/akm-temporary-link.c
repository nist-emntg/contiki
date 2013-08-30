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
	retval = is_nodeid_zero(&AKM_DATA.temporaryLink);
	AKM_PRINTF("is_temp_link_available: %d \n", retval);
	return retval;
}

/*----------------------------------------------------------------------*/
void take_temporary_link(nodeid_t *nodeId) {
	AKM_PRINTF("take_temporary_link: ");
	AKM_PRINTADDR(nodeId);
	memcpy(&AKM_DATA.temporaryLink, nodeId, sizeof(AKM_DATA.temporaryLink));
	schedule_temp_link_timer();
}

/*----------------------------------------------------------------------*/
void make_temporary_link_permanent() {
	set_authentication_state(&AKM_DATA.temporaryLink, AUTHENTICATED);
	/* Null out the temp slot so it is available */
	int i = find_authenticated_neighbor(&AKM_DATA.temporaryLink);
	if (i != -1) {
		memset(&AKM_DATA.temporaryLink, sizeof(AKM_DATA.temporaryLink), 0);
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
	int time = TEMP_LINK_TIMER;
	int i = find_authenticated_neighbor(&AKM_DATA.temporaryLink);
	if (i != -1) {
		akm_timer_set(&AKM_DATA.auth_timer[i], time, drop_temporary_link, NULL,
				0, TTYPE_ONESHOT);
	} else {
		AKM_PRINTF("temporary link not in table ");
		AKM_PRINTADDR(&AKM_DATA.temporaryLink);
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
		nodeid_t* child) {
	if (child != NULL) {
		memcpy(&AKM_MAC_OUTPUT.data.confirm_temp_link_request.child_id, child,
				sizeof(nodeid_t));
	} else {
		memcpy(&AKM_MAC_OUTPUT.data.confirm_temp_link_request.child_id,
				&rimeaddr_null, sizeof(nodeid_t));
	}
	if (parent != NULL) {
		memcpy(&AKM_MAC_OUTPUT.data.confirm_temp_link_request.parent_id, parent,
				sizeof(nodeid_t));
	} else {
		memcpy(&AKM_MAC_OUTPUT.data.confirm_temp_link_request.parent_id,
				&rimeaddr_null, sizeof(nodeid_t));
	}
	if (!is_nodeid_zero(&AKM_DATA.temporaryLink)) {
		make_temporary_link_permanent();
	}
	akm_send(target, CONFIRM_TEMPORARY_LINK_REQUEST,
			sizeof(AKM_MAC_OUTPUT.data.confirm_temp_link_request));
	AKM_PRINTF("send_confirm_temporary_link: target = ");
	AKM_PRINTADDR(target);
	AKM_PRINTF("send_confirm_temporary_link: parent = ");
	AKM_PRINTADDR(parent);
	AKM_PRINTF("send_confirm_temporary_link: child = ");
	AKM_PRINTADDR(child);
	akm_send(target,CONFIRM_TEMPORARY_LINK_REQUEST, sizeof(AKM_MAC_OUTPUT.data.confirm_temp_link_request));
}

/*----------------------------------------------------------------------*/
bool_t temporary_link_exists() {
	return rimeaddr_cmp(&AKM_DATA.temporaryLink, &rimeaddr_null);
}
/*----------------------------------------------------------------------*/
void release_temporary_link(void* pvoid) {

	if (!is_nodeid_zero(&AKM_DATA.temporaryLink)) {
		send_break_security_association(&AKM_DATA.temporaryLink,
				BSA_CONTINUATION_NONE, NULL);
	}
}

/*----------------------------------------------------------------------*/
void handle_confirm_temporary_link(confirm_temporary_link_request_t* ctl) {

	nodeid_t* sender_id = &AKM_DATA.sender_id;
	AKM_PRINTF("handle_confirm_temporary_link : senderId = ");
	AKM_PRINTADDR(sender_id);

	nodeid_t* childId = &ctl->child_id;
	nodeid_t* parentId = &ctl->parent_id;

	AKM_PRINTF("handle_confirm_temporary_link : childId = ");
	AKM_PRINTADDR(childId);

	AKM_PRINTF("handle_confirm_temporary_link : parentId = ");
	AKM_PRINTADDR(parentId);

	if (get_authentication_state(sender_id) == AUTH_PENDING) {
		/* Change the state to authenticated */
		set_authentication_state(sender_id, AUTHENTICATED);
		if (!is_nodeid_zero(childId)) {
			set_authentication_state(childId, AUTHENTICATED);
			send_confirm_temporary_link(childId, sender_id, NULL);
		}
		if (!is_nodeid_zero(parentId)) {
			send_break_security_association(parentId, BSA_CONTINUATION_NONE,
					NULL);
		}
		stop_temp_link_timer();
		memset(&AKM_DATA.temporaryLink, 0, sizeof(nodeid_t));
	} else {
		AKM_PRINTF("handle_confirm_temporary_link: sender auth state  = ",
				get_auth_state_as_string(get_authentication_state(sender_id)));
	}

}

/*------------------------------------------------------------------------*/
void drop_temporary_link() {
	AKM_PRINTF("drop_temporary_link : temporaryLink = ");
	AKM_PRINTADDR(&AKM_DATA.temporaryLink);
	set_authentication_state(&AKM_DATA.temporaryLink, UNAUTHENTICATED);
	memset(&AKM_DATA.temporaryLink, sizeof(nodeid_t), 0);
}
/*------------------------------------------------------------------------*/
void handle_pending_auth_timeout(nodeid_t* pnodeid) {
	AKM_PRINTF("handle_pending_auth_timeout ");
	AKM_PRINTADDR(pnodeid);
	send_break_security_association(pnodeid, BSA_CONTINUATION_NONE, NULL);
	if (rimeaddr_cmp(pnodeid, &AKM_DATA.temporaryLink)) {
		drop_temporary_link();
	}
	free_security_association(pnodeid);
}
/*---------------------------------------------------------------------------*/
void schedule_pending_authentication_timer(nodeid_t *target) {
	AKM_PRINTF("schedule_pending_authentication_timer : ");
	AKM_PRINTADDR(target);
	int i = find_authenticated_neighbor(target);

	if (i != -1) {
		clock_time_t time = PENDING_AUTH_TIMEOUT;
		akm_timer_set(&AKM_DATA.auth_timer[i], time,
				(void (*)(void *)) handle_pending_auth_timeout, target,
				sizeof(*target), TTYPE_ONESHOT);
	} else {
		AKM_PRINTF("cannot find target \n");
	}
}


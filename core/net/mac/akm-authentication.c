/*
 * akm-authentication.c
 *
 *  Created on: Jul 24, 2013
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
#include <sys/logger.h>

struct do_send_challenge_data {
	nodeid_t sender_id;
	bool_t   is_sender_autheticated;
	auth_challenge_sc status_code;
};


/*---------------------------------------------------------------------------*/
void insert_parent(int slot, nodeid_t* parent) {
	AKM_PRINTF("insert_parent: slot %d parent =  " ,slot)
;	AKM_PRINTADDR(parent);
	rimeaddr_copy(&AKM_DATA.parent_cache[slot], parent);
}
/*--------------------------------------------------------------------------*/
void add_to_parent_cache(nodeid_t* parent) {
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.parent_cache); i++) {
		if (is_nodeid_zero(&AKM_DATA.parent_cache[i])) {
			insert_parent(i, parent);
			return;
		}
	}
	i = random_rand() % sizeof(AKM_DATA.parent_cache);
	insert_parent(i, parent);

}

/*---------------------------------------------------------------------------*/
authentication_state get_authentication_state(nodeid_t* neighbor_id) {
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (rimeaddr_cmp(&AKM_DATA.authenticated_neighbors[i].node_id,
				neighbor_id)) {
			return AKM_DATA.authenticated_neighbors[i].state;
		}
	}
	return UNAUTHENTICATED;
}

void log_link_state_change(nodeid_t* nodeId, authentication_state state) {
#ifdef AKM_DEBUG
			log_msg_two_nodes(AKM_LOG_LINK_AUTH_STATE,
									get_node_id_as_int(nodeId),
									get_auth_state_as_string(state),
									strlen(get_auth_state_as_string(state)));
#endif
}
/*---------------------------------------------------------------------------*/
bool_t set_authentication_state(nodeid_t* node_id,
		authentication_state authState) {
	int i;
	bool_t retval = False;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (rimeaddr_cmp(&AKM_DATA.authenticated_neighbors[i].node_id,
				node_id)) {
			authentication_state currentAuthState =
					AKM_DATA.authenticated_neighbors[i].state;
			if (authState != currentAuthState) {

				if (authState == AUTH_PENDING) {
					schedule_pending_authentication_timer(node_id);
				} else if (authState == OK_SENT_WAITING_FOR_ACK) {
					schedule_waiting_for_ack_timeout(node_id);
				} else if (authState == PENDING_SEND_CHALLENGE) {

				} else if (authState == CHALLENGE_SENT_WAITING_FOR_OK) {
					schedule_challenge_sent_timeout(node_id);
				} else if (authState == AUTHENTICATED) {
					stop_auth_timer(node_id);
				} else if (authState == UNAUTHENTICATED) {
					if (currentAuthState != UNAUTHENTICATED) {
						remove_parent(
								&AKM_DATA.authenticated_neighbors[i].node_id);
					}
					free_slot(i);
					if (!is_authenticated()) {
						reset_beacon();
					}
				}
			}

#ifdef AKM_DEBUG
			AKM_PRINTF("set_authentication_state : %d %s ",i, get_auth_state_as_string(authState));
			AKM_PRINTADDR(node_id);
#endif


			AKM_DATA.authenticated_neighbors[i].state = authState;


			log_link_state_change(node_id,authState);
			retval = True;
			break;
		}
	}
	if (!retval) {
		AKM_PRINTF("set_authention_state: node not found \n");
	}

#ifdef AKM_DEBUG
	if ( is_authenticated()) {
		char* authState;
		if ( is_capacity_available(NULL) ) {
			authState = "AUTHENTICATED_UNSATURATED";
		} else {
			authState = "AUTHENTICATED_SATURATED";
		}
		log_msg_one_node(AKM_LOG_NODE_AUTH_STATE,authState,strlen(authState));
	} else {
		log_msg_one_node(AKM_LOG_NODE_AUTH_STATE,"UNAUTHENTICATED",strlen("UNAUTHENTICATED"));
	}
#endif
	return retval;
}
/*---------------------------------------------------------------------------*/
session_key_t *
get_session_key(nodeid_t *neighbor_id) {
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (rimeaddr_cmp(&AKM_DATA.authenticated_neighbors[i].node_id,
				neighbor_id)) {
			return &AKM_DATA.authenticated_neighbors[i].session_key;
		}
	}
	return (session_key_t *) 0;
}

/*---------------------------------------------------------------------------*/
void do_send_challenge(void* pvoid) {

	struct do_send_challenge_data *pdata = (struct do_send_challenge_data *)pvoid;

	nodeid_t* target = (nodeid_t*) &pdata->sender_id;
	bool_t is_authenticated = pdata->is_sender_autheticated;

	AKM_PRINTF("do_send_challenge: target = ")
;	AKM_PRINTADDR(target);

	AKM_MAC_OUTPUT.data.auth_challenge.status_code = pdata->status_code;
	bool_t bSendChallenge = True;
	if ( pdata->status_code == AUTH_NO_SPACE && is_authenticated ) {
		bSendChallenge = False;
	}


	/* For later : reduce the amount of searching by defining new index methods */
	int i = find_authenticated_neighbor(target);
	akm_timer_stop(&AKM_DATA.send_challenge_delay_timer[i]);
	if (bSendChallenge) {
		akm_send(target, AUTH_CHALLENGE,
				sizeof(AKM_MAC_OUTPUT.data.auth_challenge));
		set_authentication_state(target, CHALLENGE_SENT_WAITING_FOR_OK);
	} else {
		set_authentication_state(target, UNAUTHENTICATED);
	}
}

/*---------------------------------------------------------------------------*/
void send_challenge(nodeid_t* target, beacon_t * pbeacon) {
	int time;

	AKM_PRINTF("send_challenge : target = ");
	AKM_PRINTADDR(target);
	if (is_capacity_available(NULL)) {
		time = random_rand() % SPACE_AVAILABLE_TIMER + 1;
		add_authenticated_neighbor(target, NULL, PENDING_SEND_CHALLENGE);
		schedule_send_challenge_timer(time, target, pbeacon,AUTH_SPACE_AVAILABLE);
	} else if (is_authenticated() && is_redundant_parent_available() && is_temp_link_available()) {
		add_authenticated_neighbor(target, NULL, PENDING_SEND_CHALLENGE);
		time = SPACE_AVAILABLE_TIMER
				+ random_rand() % REDUNDANT_PARENT_AVAILABLE_TIMER;
		take_temporary_link(target);
		schedule_send_challenge_timer(time, target, pbeacon,AUTH_REDUNDANT_PARENT_AVAILABLE);

	} else if ( is_temp_link_available() ) {
		add_authenticated_neighbor(target, NULL, PENDING_SEND_CHALLENGE);
		time = SPACE_AVAILABLE_TIMER + REDUNDANT_PARENT_AVAILABLE_TIMER
				+ random_rand() % NO_SPACE_TIMER;
		AKM_PRINTF("No space available delaying for %d \n ",time);
		take_temporary_link(target);
		schedule_send_challenge_timer(time, target, pbeacon, AUTH_NO_SPACE);
	} else {
		AKM_PRINTF("temporary link is not available. current value is : ");
		AKM_PRINTADDR(&AKM_DATA.temporaryLink);
	}


}

/*---------------------------------------------------------------------------*/
void handle_auth_challenge(auth_challenge_request_t* pauthChallenge) {
	nodeid_t* sender_id = &AKM_DATA.sender_id;
	AKM_PRINTF("handle_auth_challenge : ")
;	AKM_PRINTADDR(sender_id);
	if (!sec_verify_auth_request(pauthChallenge)) {
		AKM_PRINTF("Failed to verify auth challenge\n")
;		return;
	}
	if ( ! is_capacity_available(sender_id) ) {
		AKM_PRINTF("No capacity available -- not responding to challenge\n");
		return;
	}
	auth_challenge_sc sc = pauthChallenge->status_code;

	AKM_MAC_OUTPUT.data.auth_challenge_response.request_status_code = sc;
	sec_generate_session_key(sender_id);
	akm_send(sender_id, AUTH_CHALLENGE_RESPONSE,
			sizeof(AKM_MAC_OUTPUT.data.auth_challenge_response));
	add_authenticated_neighbor(sender_id,
			&AKM_MAC_OUTPUT.data.auth_challenge_response.session_key,
			OK_SENT_WAITING_FOR_ACK);

}
/*----------------------------------------------------------------------*/

void handle_auth_challenge_response(auth_challenge_response_t* pacr) {

	nodeid_t* sender_id = &AKM_DATA.sender_id;
	AKM_PRINTF("handle_auth_challenge_response ")
;	AKM_PRINTADDR(sender_id);
	auth_challenge_sc acr = pacr->request_status_code;
	AKM_PRINTF("request_status_code = %s \n",AUTH_STATUS_CODE_AS_STRING(acr));

	if (!sec_verify_auth_response(pacr)) {
		return;
	} else {
		if (AKM_DATA.is_dodag_root) {
			if (acr == AUTH_SPACE_AVAILABLE) {
				if (set_authentication_state(sender_id, AUTHENTICATED)) {
					send_auth_ack(sender_id, NULL);
				} else {
					send_break_security_association(sender_id,
							BSA_CONTINUATION_NONE, NULL);
				}
			} else {
				send_break_security_association(sender_id,
						BSA_CONTINUATION_NONE, NULL);
			}
		} else {
			if (acr == AUTH_SPACE_AVAILABLE) {
				if (get_authentication_state(sender_id)
						== CHALLENGE_SENT_WAITING_FOR_OK) {
					AKM_PRINTF("capacity is available -- take the slot.\n");
					send_auth_ack(sender_id, NULL);
					set_authentication_state(sender_id, AUTHENTICATED);
				}
			} else if (acr == AUTH_REDUNDANT_PARENT_AVAILABLE ) {
				/* A redundant paprent is available. So take that slot. */
				send_auth_ack(sender_id, NULL);
				/* Break the security assoc. with my parent.
				 * Child now owns the slot
				 */
				nodeid_t* pparent = get_parent_id();
				AKM_PRINTF(
						"breaking security association with redundant parent");
				AKM_PRINTADDR(pparent);
				set_authentication_state(sender_id, AUTHENTICATED);
				/* ask the parent to drop the SA with us */
				send_break_security_association(pparent, BSA_CONTINUATION_NONE,
						0);
			} else {
				nodeid_t* pparent = get_parent_id();
				/* Redundant parent is not available */
				AKM_PRINTF("redundant parent NOT available. parent id is \n");
				AKM_PRINTADDR(pparent);
				/* Send the parent along to the child so he may identify
				 * a pair between which to insert himself.
				 */
				set_authentication_state(sender_id, AUTH_PENDING);
				send_auth_ack(sender_id, pparent);
			}
		}
	}

}

/*---------------------------------------------------------------------------*/
void handle_auth_ack(auth_ack_t* pauthAck) {
	AKM_PRINTF("handle_auth_ack : ")
;	nodeid_t* sender = &AKM_DATA.sender_id;
	AKM_PRINTADDR(sender);

	nodeid_t *pparent = &pauthAck->parent_id;
	AKM_PRINTF("parent ID : ")
;	AKM_PRINTADDR(pparent);

	if (is_nodeid_zero(pparent)) {
		if (get_authentication_state(sender) == OK_SENT_WAITING_FOR_ACK) {
			add_authenticated_neighbor(sender, &pauthAck->session_key,
					AUTHENTICATED);
		}
	} else {
		bool_t foundInParentCache = False;
		int i = 0;
		AKM_PRINTF("checking parent cache for ");
		AKM_PRINTADDR(&pauthAck->parent_id);
		for (i = 0; i < NELEMS(AKM_DATA.parent_cache); i++) {
			if (rimeaddr_cmp(&pauthAck->parent_id, &AKM_DATA.parent_cache[i])) {
				foundInParentCache = True;
				break;
			}
		}
		if (foundInParentCache) {
			AKM_PRINTF("Found in parent cache. parent auth state is %s\n",
					get_auth_state_as_string(get_authentication_state
							(&pauthAck->parent_id)));
			if (get_authentication_state(sender) == AUTH_PENDING &&
					get_authentication_state(&pauthAck->parent_id) == AUTH_PENDING ) {
				set_authentication_state(sender, AUTH_PENDING);
				send_insert_node_request(sender, &pauthAck->parent_id);
			}
		} else {
			/* put the ID in parent cache */
			if (get_authentication_state(sender) == OK_SENT_WAITING_FOR_ACK) {
				/* put the id in the parent cache and wait for next round */
				add_to_parent_cache(sender);
				set_authentication_state(sender, AUTH_PENDING);
			}
		}
	}

}
/*----------------------------------------------------------------------*/

void send_auth_ack(nodeid_t* target_id, nodeid_t * pparent) {
	AKM_PRINTF("send_auth_ack : ")
;	AKM_PRINTADDR(target_id);
	AKM_PRINTF("parent_id = ");
	AKM_PRINTADDR(pparent);
	sec_generate_session_key(target_id);
	if (AKM_DATA.is_dodag_root) {
		memset(&AKM_MAC_OUTPUT.data.auth_ack.parent_id, 0, sizeof(nodeid_t));
		akm_send(target_id, AUTH_ACK, sizeof(AKM_MAC_OUTPUT.data.auth_ack));
	} else {
		if (pparent == NULL) {
			memset(&AKM_MAC_OUTPUT.data.auth_ack.parent_id, 0,
					sizeof(nodeid_t));
		} else {
			rimeaddr_copy(&AKM_MAC_OUTPUT.data.auth_ack.parent_id, pparent);
		}
		akm_send(target_id, AUTH_ACK, sizeof(AKM_MAC_OUTPUT.data.auth_ack));
	}
}

/*---------------------------------------------------------------------------*/
void schedule_send_challenge_timer(int time, nodeid_t* target,
		beacon_t * pbeacon,auth_challenge_sc statusCode) {
	AKM_PRINTF("schedule_send_challenge_timer %d ",time)
;	AKM_PRINTADDR(target);
	int i = find_authenticated_neighbor(target);

	if (i != -1) {
		struct do_send_challenge_data timerData;
		rimeaddr_copy(&timerData.sender_id,target);
		timerData.is_sender_autheticated = pbeacon->is_authenticated;
		timerData.status_code = statusCode;
		akm_timer_set(&AKM_DATA.send_challenge_delay_timer[i], time,
				do_send_challenge, &timerData, sizeof(timerData), TTYPE_ONESHOT);
	} else {
		AKM_PRINTF("Cannot find authenticated neighbor - not sending challenge")
;		AKM_PRINTADDR(target);
	}
}

/*---------------------------------------------------------------------------*/
void handle_authentication_timeout(void* pvoid) {

	nodeid_t* node_id = (nodeid_t*) pvoid;
	AKM_PRINTF("handle_authentication_timeout: ")
;
	AKM_PRINTADDR(node_id);
	int i = find_authenticated_neighbor(node_id);
	if (i == -1) {
		AKM_PRINTF("Cannot find neighbor.\n")
;
		return;
	}
	/* If we have not reached authenticated state then free the slot*/
	if (AKM_DATA.authenticated_neighbors[i].state != AUTHENTICATED) {
		AKM_DATA.authenticated_neighbors[i].state = UNAUTHENTICATED;
		log_link_state_change(node_id,UNAUTHENTICATED);
		free_slot(i);
	}
	if (rimeaddr_cmp(&AKM_DATA.temporaryLink,
			&AKM_DATA.authenticated_neighbors[i].node_id)) {
		memset(&AKM_DATA.temporaryLink, sizeof(AKM_DATA.temporaryLink), 0);
	} else {
		AKM_PRINTF("Temporary Link is ")
;		AKM_PRINTADDR(&AKM_DATA.temporaryLink);
	}

}
/*---------------------------------------------------------------------------*/
void schedule_challenge_sent_timeout(nodeid_t *target) {
	int i = find_authenticated_neighbor(target);

	if (i != -1) {
		clock_time_t time = CHALLENGE_SENT_TIMEOUT;
		akm_timer_set(&AKM_DATA.auth_timer[i], time,
				handle_authentication_timeout, target, sizeof(*target),
				TTYPE_ONESHOT);
	}
}

/*-----------------------------------------------------------------------*/
void schedule_waiting_for_ack_timeout(nodeid_t *target) {
	int i = find_authenticated_neighbor(target);

	if (i != -1) {
		clock_time_t time = WAITING_FOR_ACK_TIMEOUT;
		akm_timer_set(&AKM_DATA.auth_timer[i], time,
				handle_authentication_timeout, target, sizeof(*target),
				TTYPE_ONESHOT);
	}
}

/*----------------------------------------------------------------------*/
void handle_pending_authentication_timeout(nodeid_t* node_id) {
	send_break_security_association(node_id, BSA_CONTINUATION_NONE, NULL);
	free_security_association(node_id);
}

/*--------------------------------------------------------------------------*/
void stop_auth_timer(nodeid_t* target) {
	int i = find_authenticated_neighbor(target);
	if (i != -1) {
		akm_timer_stop(&AKM_DATA.auth_timer[i]);
	}
}
/*-----------------------------------------------------------------------*/
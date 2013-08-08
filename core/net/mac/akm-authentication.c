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

/*---------------------------------------------------------------------------*/
void insert_parent(int slot, nodeid_t* parent) {
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

/*---------------------------------------------------------------------------*/
bool_t set_authentication_state(nodeid_t* node_id,
		authentication_state authState) {
	int i;
	bool_t retval = False;
	AKM_PRINTF(
			"set_authentication_state : %s ",get_auth_state_as_string(authState))
;
	AKM_PRINTADDR(node_id);
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (rimeaddr_cmp(&AKM_DATA.authenticated_neighbors[i].node_id,
				node_id)) {
			if (  AKM_DATA.authenticated_neighbors[i].state != authState ) {
				if ( authState == AUTH_PENDING) {
					schedule_pending_authentication_timer(node_id);
				} else if (authState == OK_SENT_WAITING_FOR_ACK) {
					schedule_pending_authentication_timer(node_id);
				} else if ( authState == CHALLENGE_SENT_WAITING_FOR_OK) {
					schedule_challenge_sent_timer(node_id);
				} else if ( authState == AUTHENTICATED) {
					stop_auth_timer(node_id);
				}
			}
			AKM_DATA.authenticated_neighbors[i].state = authState;
			retval = True;
			break;
		}
	}
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
	nodeid_t* target = (nodeid_t*) pvoid;
	AKM_PRINTF("do_send_challenge ");
	AKM_PRINTADDR(target);
	if (is_capacity_available()) {
		AKM_MAC_OUTPUT.data.auth_challenge.status_code = AUTH_SPACE_AVAILABLE;
	} else if (is_redundant_parent_available()) {
		if (is_temp_link_available()) {
			take_temporary_link(target);
			AKM_MAC_OUTPUT.data.auth_challenge.status_code =
					AUTH_REDUNDANT_PARENT_AVAILABLE;
		} else {
			AKM_PRINTF("Temp link is not available - not sending challenge")
;		}
	} else {
		if (is_temp_link_available()) {
			take_temporary_link(target);
			AKM_MAC_OUTPUT.data.auth_challenge.status_code = AUTH_NO_SPACE;
		} else {
			AKM_PRINTF("Temp link is not available - not sending challenge");
		}
	}
	akm_send(target, AUTH_CHALLENGE,sizeof(AKM_MAC_OUTPUT.data.auth_challenge));
	set_authentication_state(target, CHALLENGE_SENT_WAITING_FOR_OK);
	int i = find_authenticated_neighbor(target);
	akm_timer_stop(&AKM_DATA.send_challenge_delay_timer[i]);

}

/*---------------------------------------------------------------------------*/
void send_challenge(nodeid_t* target) {
	int time;
	add_authenticated_neighbor(target, NULL, CHALLENGE_SENT_WAITING_FOR_OK);
	if (is_capacity_available()) {
		time = random_rand() % SPACE_AVAILABLE_TIMER;
	} else if (AKM_DATA.is_authenticated && is_redundant_parent_available()) {
		time = SPACE_AVAILABLE_TIMER
				+ random_rand() % REDUNDANT_PARENT_AVAILABLE_TIMER;
	} else {
		time = SPACE_AVAILABLE_TIMER + REDUNDANT_PARENT_AVAILABLE_TIMER
				+ random_rand() % NO_SPACE_TIMER;
	}
	schedule_send_challenge_timer(time, target);

}

/*---------------------------------------------------------------------------*/
void handle_auth_challenge(
		auth_challenge_request_t* pauthChallenge) {
	nodeid_t* sender_id = &AKM_DATA.sender_id;
	AKM_PRINTF("handle_auth_challenge : ");
	AKM_PRINTADDR(sender_id);
	if (!sec_verify_auth_request(pauthChallenge)) {
		AKM_PRINTF("Failed to verify auth challenge\n");
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

void handle_auth_challenge_response(
		auth_challenge_response_t* pacr) {

	nodeid_t* sender_id = &AKM_DATA.sender_id;
	AKM_PRINTF("handle_auth_challenge_response ")
;
	AKM_PRINTADDR(sender_id);

	if (!sec_verify_auth_response(pacr)) {
		return;
	} else {
		session_key_t* key = &pacr->session_key;
		if (AKM_DATA.is_dodag_root) {
			if (is_capacity_available()) {
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
			if (is_capacity_available()) {
				if (get_authentication_state(sender_id)
						== CHALLENGE_SENT_WAITING_FOR_OK) {
					send_auth_ack(sender_id, NULL);
					set_authentication_state(sender_id, AUTHENTICATED);
				}
			} else if (is_redundant_parent_available()) {
				memset(&AKM_MAC_OUTPUT.data.auth_ack.parent_id, 0,
						sizeof(nodeid_t));
				nodeid_t* pparent = get_parent_id();
				/* A redundant paprent is available. So take that slot. */
				send_auth_ack(sender_id, NULL);

				/* Break the security assoc. with my parent */
				send_break_security_association(pparent, BSA_CONTINUATION_NONE,
						0);
				/* Take the parent slot and give it to the sender */
				replace_authenticated_neighbor(pparent, sender_id, key);
			} else {
				/* Redundant parent is not available */
				nodeid_t* pparent = get_parent_id();
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
void handle_auth_ack( auth_ack_t* pauthAck) {
	AKM_PRINTF("handle_auth_ack : ");
	nodeid_t* sender = &AKM_DATA.sender_id;
	AKM_PRINTADDR(sender);

	nodeid_t *pparent = &pauthAck->parent_id;
	if (is_nodeid_zero(pparent)) {
		if (get_authentication_state(sender) == OK_SENT_WAITING_FOR_ACK) {
			AKM_DATA.is_authenticated = True;
			add_authenticated_neighbor(sender, &pauthAck->session_key,
					AUTHENTICATED);
		}
	} else {
		bool_t foundInParentCache = False;
		int i = 0;
		for (i = 0; i < NELEMS(AKM_DATA.parent_cache); i++) {
			if (rimeaddr_cmp(&pauthAck->parent_id, &AKM_DATA.parent_cache[i])) {
				foundInParentCache = True;
			}
		}
		if (foundInParentCache) {
			if (get_authentication_state(sender) == OK_SENT_WAITING_FOR_ACK) {
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
	AKM_PRINTF("send_auth_ack : ");
	AKM_PRINTADDR(target_id);
	sec_generate_session_key(target_id);
	if (AKM_DATA.is_dodag_root) {
		memset(&AKM_MAC_OUTPUT.data.auth_ack.parent_id, 0, sizeof(nodeid_t));
		akm_send(target_id, AUTH_ACK,  sizeof(AKM_MAC_OUTPUT.data.auth_ack));
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
void schedule_send_challenge_timer(int time, nodeid_t* target) {
	AKM_PRINTF("schedule_send_challenge_timer %d ",time);
	AKM_PRINTADDR(target);
	int i = find_authenticated_neighbor(target);
	if (i != -1) {
		akm_timer_set(&AKM_DATA.send_challenge_delay_timer[i], time,
				do_send_challenge, target);
	} else {
		AKM_PRINTF("Cannot find authenticated neighbor ");
		AKM_PRINTADDR(target);
	}
}

/*---------------------------------------------------------------------------*/
void handle_challenge_sent_timeout(void* pvoid) {

	nodeid_t* node_id = (nodeid_t*) pvoid;
	int i = find_authenticated_neighbor(node_id);

	if (i != -1 && AKM_DATA.authenticated_neighbors[i].state != AUTHENTICATED) {
		if (rimeaddr_cmp(&AKM_DATA.temporaryLink,
				&AKM_DATA.authenticated_neighbors[i].node_id)) {
			memset(&AKM_DATA.temporaryLink, sizeof(AKM_DATA.temporaryLink), 0);
		}
		AKM_DATA.authenticated_neighbors[i].state = UNAUTHENTICATED;
		free_slot(i);
	}
}
/*---------------------------------------------------------------------------*/
void schedule_challenge_sent_timer(nodeid_t *target) {
	int i = find_authenticated_neighbor(target);

	if (i != -1) {
		clock_time_t time = CHALLENGE_SENT_TIMEOUT ;
		akm_timer_set(&AKM_DATA.auth_timer[i], time,
				handle_challenge_sent_timeout, target);
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

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
#include "lib/assert.h"
#include "certificate.h"
#include "credential.h"

struct do_send_challenge_data {
	nodeid_t sender_id;
	bool_t   is_sender_authenticated;
	auth_challenge_sc status_code;
};


/*---------------------------------------------------------------------------*/
void insert_parent(int slot, nodeid_t * nodeId, nodeid_t* parent) {
	AKM_PRINTF("insert_parent: slot %d nodeId =  " ,slot);
	AKM_PRINTADDR(nodeId);
	AKM_PRINTF(" parent = ");
	AKM_PRINTADDR(parent);

	rimeaddr_copy(&AKM_DATA.parent_cache[slot].parentId, parent);
	rimeaddr_copy(&AKM_DATA.parent_cache[slot].nodeId, nodeId);

}
/*--------------------------------------------------------------------------*/
void add_to_parent_cache(nodeid_t* nodeId, nodeid_t* parent) {
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.parent_cache); i++) {
		if (is_nodeid_zero(&AKM_DATA.parent_cache[i].nodeId)) {
			insert_parent(i, nodeId, parent);
			return;
		}
	}
	i = random_rand() % NELEMS(AKM_DATA.parent_cache);
	insert_parent(i,nodeId, parent);
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
				log_link_state_change(node_id,authState);
				if (authState == AUTH_PENDING) {
					schedule_pending_authentication_timer(node_id);
				} else if (authState == OK_SENT_WAITING_FOR_ACK) {
					schedule_waiting_for_ack_timeout(node_id);
				} else if (authState == PENDING_SEND_CHALLENGE) {

				} else if (authState == CHALLENGE_SENT_WAITING_FOR_OK) {
					schedule_challenge_sent_timeout(node_id);
				} else if (authState == AUTHENTICATED) {
					stop_auth_timer(node_id);
					SCHEDULE_CYCLE_DETECT_TIMER();
					reset_beacon();

				} else if (authState == UNAUTHENTICATED) {
					if (currentAuthState != UNAUTHENTICATED) {
						remove_parent(
								&AKM_DATA.authenticated_neighbors[i].node_id);
					} else {
						STOP_CYCLE_DETECT_TIMER();
					}
					free_slot(i);
					AKM_DATA.authenticated_neighbors[i].time_since_last_ping = 0;
					reset_beacon();
				}
			}
#ifdef AKM_DEBUG
			AKM_PRINTF("set_authentication_state : %d %s ",i, get_auth_state_as_string(authState));
			AKM_PRINTADDR(node_id);
#endif


			AKM_DATA.authenticated_neighbors[i].state = authState;


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
void crypto_auth_dump_session_key(authenticated_neighbor_t * neighbor) {
#ifdef AKM_DEBUG
	int i;
	for(i=0; i< sizeof(neighbor->session_key); i++)
		printf("%x", ((uint8_t *) &neighbor->session_key)[i]);
#endif
}
/*---------------------------------------------------------------------------*/
static int crypto_auth_prepare(uint8_t buf[AUTH_MSG_LEN],
						authenticated_neighbor_t * neighbor) {
	int buf_len = 0;
	uint8_t point[2 * NUMBYTES];

	AKM_PRINTF("Preparing authentication msg\n");
	/* send in the public certificate */
	serialize_pub_cert(&cert->pub_cert, buf);
	buf_len += PUB_CERT_SIZE;

	/* compute the local ECDH secret */
	ecc_ecdh_from_host(neighbor->ecdh_secret, point);
	memcpy(buf + buf_len, point, sizeof(point));
	buf_len += sizeof(point);
	/* add the signature */
	certificate_ecdsa_sign(cert, point, sizeof(point), buf + buf_len);
	buf_len += SIG_LEN;

	return buf_len;
}
/*---------------------------------------------------------------------------*/
static void crypto_auth_extract_data(uint8_t buf[AUTH_MSG_LEN],
									 authenticated_neighbor_t * neighbor) {
	memcpy(neighbor->tmp_point, &buf[PUB_CERT_SIZE], 2*NUMBYTES);
}

/*---------------------------------------------------------------------------*/
static int crypto_auth_verify(uint8_t buf[AUTH_MSG_LEN]) {
	s_pub_certificate other_cert;

	AKM_PRINTF("Verifying authentication message\n");

	/* authentication part of the message is stored in buf */
	deserialize_pub_cert(buf, &other_cert);

	/* verify that the server certificate is valid */
	if (verify_certificate(cacert, &other_cert)) {
		AKM_PRINTF("Server certificate is not trusted\n");
		return -2;
	}

	if (certificate_ecdsa_verify(&other_cert,
								 &((uint8_t *) buf)[PUB_CERT_SIZE], /* this is the point d'.G */
								 2*NUMBYTES,
								 &((uint8_t *) buf)[PUB_CERT_SIZE + 2 * NUMBYTES] /* this is the signature */
								 )) {
		AKM_PRINTF("Signature does not match\n");
		return -1;
	} else {
		AKM_PRINTF("Signature d'.G is valid\n");
		return 1;
	}
}
/*---------------------------------------------------------------------------*/
void do_send_challenge(void* pvoid) {

	struct do_send_challenge_data *pdata = (struct do_send_challenge_data *)pvoid;

	nodeid_t* target = (nodeid_t*) &pdata->sender_id;
	bool_t is_authenticated = pdata->is_sender_authenticated;

	AKM_PRINTF("do_send_challenge: target = ");
	AKM_PRINTADDR(target);

	AKM_MAC_OUTPUT.data.auth_challenge.status_code = pdata->status_code;
	bool_t bSendChallenge = True;
	if ( pdata->status_code == AUTH_NO_SPACE && is_authenticated ) {
		bSendChallenge = False;
	}


	/* For later : reduce the amount of searching by defining new index methods */
	int i = find_authenticated_neighbor(target);
	assert(i != -1);
	akm_timer_stop(&AKM_DATA.send_challenge_delay_timer[i]);
	if (bSendChallenge) {
		crypto_auth_prepare(AKM_MAC_OUTPUT.data.auth_challenge.crypto_payload,
							&AKM_DATA.authenticated_neighbors[i]);
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
		add_authenticated_neighbor(target, PENDING_SEND_CHALLENGE);
		schedule_send_challenge_timer(time, target, pbeacon,AUTH_SPACE_AVAILABLE);
	} else if (is_authenticated() && is_redundant_parent_available() && is_temp_link_available()) {
		add_authenticated_neighbor(target, PENDING_SEND_CHALLENGE);
		time = SPACE_AVAILABLE_TIMER
				+ random_rand() % REDUNDANT_PARENT_AVAILABLE_TIMER;
		take_temporary_link(target);
		schedule_send_challenge_timer(time, target, pbeacon,AUTH_REDUNDANT_PARENT_AVAILABLE);

	} else if ( is_temp_link_available() && !pbeacon->is_authenticated ) {
		add_authenticated_neighbor(target, PENDING_SEND_CHALLENGE);
		time = SPACE_AVAILABLE_TIMER + REDUNDANT_PARENT_AVAILABLE_TIMER
				+ random_rand() % NO_SPACE_TIMER;
		AKM_PRINTF("No space available delaying for %d \n ",time);
		take_temporary_link(target);
		schedule_send_challenge_timer(time, target, pbeacon, AUTH_NO_SPACE);
	} else {
		AKM_PRINTF("temporary link is not available or sender is authenticated. current value is : ");
		AKM_PRINTADDR(&AKM_DATA.temporaryLink);
	}


}

/*---------------------------------------------------------------------------*/
void handle_auth_challenge(auth_challenge_request_t* pauthChallenge) {
	nodeid_t* sender_id = &AKM_DATA.sender_id;
	authenticated_neighbor_t * neighbor_slot = NULL;
	AKM_PRINTF("handle_auth_challenge : ");
	AKM_PRINTADDR(sender_id);
	if (crypto_auth_verify(pauthChallenge->crypto_payload) != 1) {
		AKM_PRINTF("Failed to verify auth challenge\n");
		return;
	}
	if ( ! is_capacity_available(sender_id) ) {
		AKM_PRINTF("No capacity available -- not responding to challenge\n");
		return;
	}
	if ( get_authentication_state(sender_id) != UNAUTHENTICATED) {
		AKM_PRINTF("Auth in progress. Drop request ");
		return;
	}
	auth_challenge_sc sc = pauthChallenge->status_code;

	AKM_MAC_OUTPUT.data.auth_challenge_response.request_status_code = sc;
	neighbor_slot = &AKM_DATA.authenticated_neighbors[
						add_authenticated_neighbor(sender_id,
												   OK_SENT_WAITING_FOR_ACK)];
	crypto_auth_extract_data(pauthChallenge->crypto_payload,
							 neighbor_slot);
	crypto_auth_prepare(AKM_MAC_OUTPUT.data.auth_challenge_response.crypto_payload,
						neighbor_slot);
	ecc_ecdh_from_network(neighbor_slot->ecdh_secret,
						  neighbor_slot->tmp_point,
						  neighbor_slot->shared_secret);
	ecc_ecdh_derive_key(neighbor_slot->shared_secret,
						neighbor_slot->session_key.data);
	AKM_PRINTF("Established session key with node ");
	AKM_PRINTADDR(&neighbor_slot->node_id);
	AKM_PRINTF("key: ");
	crypto_auth_dump_session_key(neighbor_slot);
#ifdef AKM_DEBUG
	printf("\n");
#endif

	akm_send(sender_id, AUTH_CHALLENGE_RESPONSE,
			sizeof(AKM_MAC_OUTPUT.data.auth_challenge_response));
}
/*----------------------------------------------------------------------*/

void handle_auth_challenge_response(auth_challenge_response_t* pacr) {
	int i;
	nodeid_t* sender_id = &AKM_DATA.sender_id;
	authenticated_neighbor_t * neighbor_slot = NULL;

	AKM_PRINTF("handle_auth_challenge_response ");
	AKM_PRINTADDR(sender_id);
	auth_challenge_sc acr = pacr->request_status_code;
	AKM_PRINTF("request_status_code = %s \n", AUTH_STATUS_CODE_AS_STRING(acr));

	if (crypto_auth_verify(pacr->crypto_payload) != 1) {
		AKM_PRINTF("Failed to verify auth challenge response\n");
		return;
	} else {
		if (AKM_DATA.is_dodag_root) {
			if (acr == AUTH_SPACE_AVAILABLE) {
				if (set_authentication_state(sender_id, AUTHENTICATED)) {
					send_auth_ack(sender_id, NULL);
				} else {
					send_break_security_association(sender_id,
							BSA_CONTINUATION_NONE, NULL);
					return;
				}
			} else {
				send_break_security_association(sender_id,
						BSA_CONTINUATION_NONE, NULL);
				return;
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
				/* A redundant parent is available. So take that slot. */
				send_auth_ack(sender_id, NULL);
				/* Break the security assoc. with my parent.
				 * Child now owns the slot
				 */
				nodeid_t* pparent = (nodeid_t *) rpl_get_redundant_parent_lladdr(get_dodag_root());
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
				return;
			}
		}
		for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
			if (rimeaddr_cmp(&AKM_DATA.authenticated_neighbors[i].node_id,
							 sender_id)) {
				neighbor_slot = &AKM_DATA.authenticated_neighbors[i];
				break;
			}
		}
		assert(neighbor_slot);
		crypto_auth_extract_data(pacr->crypto_payload,
								 neighbor_slot);
		ecc_ecdh_from_network(neighbor_slot->ecdh_secret,
							  neighbor_slot->tmp_point,
							  neighbor_slot->shared_secret);
		ecc_ecdh_derive_key(neighbor_slot->shared_secret,
							neighbor_slot->session_key.data);
		AKM_PRINTF("Established session key with node ");
		AKM_PRINTADDR(sender_id);
		AKM_PRINTF("key: ");
		crypto_auth_dump_session_key(neighbor_slot);
#ifdef AKM_DEBUG
		printf("\n");
#endif
	}
}

/*---------------------------------------------------------------------------*/
void handle_auth_ack(auth_ack_t* pauthAck) {
	AKM_PRINTF("handle_auth_ack : ");
	nodeid_t* sender = &AKM_DATA.sender_id;
	AKM_PRINTADDR(sender);

	nodeid_t *pparent = &pauthAck->parent_id;
	AKM_PRINTF("parent ID : ");
	AKM_PRINTADDR(pparent);

	if (is_nodeid_zero(pparent)) {
		if (get_authentication_state(sender) == OK_SENT_WAITING_FOR_ACK) {
			add_authenticated_neighbor(sender, AUTHENTICATED);
		}
	} else {
		bool_t foundInParentCache = False;
		int i = 0;
		AKM_PRINTF("checking parent cache for ");
		AKM_PRINTADDR(&pauthAck->parent_id);
		nodeid_t *child = NULL;
		nodeid_t *parent = NULL;
		for (i = 0; i < NELEMS(AKM_DATA.parent_cache); i++) {
			if (rimeaddr_cmp(&pauthAck->parent_id, &AKM_DATA.parent_cache[i].nodeId)) {
				foundInParentCache = True;
				child = sender;
				parent = &AKM_DATA.parent_cache[i].nodeId;
				break;
			} else if (rimeaddr_cmp(sender,&AKM_DATA.parent_cache[i].parentId)) {
				child = &AKM_DATA.parent_cache[i].nodeId;
				parent = sender;
				foundInParentCache = True;
				break;
			}
		}

		if (!is_authenticated() && get_authentication_state(sender) == OK_SENT_WAITING_FOR_ACK) {
			set_authentication_state(sender,AUTH_PENDING);
		}

		// Insert myself into the overlay if there are not other alternatives.
		if (foundInParentCache && !is_authenticated()) {
			AKM_PRINTF("parent = ");
			AKM_PRINTADDR(parent);
			AKM_PRINTF("child = ");
			AKM_PRINTADDR(child);
			AKM_PRINTF("Found in parent cache. parent auth state is %s child state %s\n",
					get_auth_state_as_string(get_authentication_state(parent)),
					get_auth_state_as_string(get_authentication_state(child)));

			if (get_authentication_state(parent) == AUTH_PENDING &&
					get_authentication_state(child) == AUTH_PENDING ) {
				send_insert_node_request(child, parent);
			}
		} else {
			/* put the id in the parent cache and wait for next round */
			add_to_parent_cache(sender,&pauthAck->parent_id);
		}
	}

}
/*----------------------------------------------------------------------*/

void send_auth_ack(nodeid_t* target_id, nodeid_t * pparent) {
	AKM_PRINTF("send_auth_ack : ");
	AKM_PRINTADDR(target_id);
	AKM_PRINTF("parent_id = ");
	AKM_PRINTADDR(pparent);
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
		timerData.is_sender_authenticated = pbeacon->is_authenticated;
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

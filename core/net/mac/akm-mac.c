/*
 * This code is in the public domain Blah blah...
 */
/**
 * akm-mac.c
 * \file
 *         A MAC protocol for AKM
 * \author
 *         M. Ranganathan
 */

#include "random.h"
#include "contiki.h"
#include "net/mac/nullmac.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include  "mac/akm-mac.h"
#include  "packetbuf.h"
#include "clock.h"
#include "rpl/rpl.h"
#include "random.h"
#include "certificate.h"
#include "credential.h"
#define NDEBUG
#include <assert.h>
#include <sys/logger.h>
extern void rpl_remove_parent(rpl_parent_t *parent);
void free_slot(int slot);
static void check_and_restart(void *ptr);
static void akm_sighandler(int signo);

int auth_seqno = 0;

akm_mac_t AKM_MAC_OUTPUT;

akm_data_t AKM_DATA;

akm_mac_t AKM_MAC_INPUT;

#define MAX_TRANSMIT_SIZE (PACKETBUF_SIZE - PACKETBUF_HDR_SIZE)

extern rimeaddr_t rimeaddr_node_addr;

bool_t is_handling_challenge() {
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (AKM_DATA.authenticated_neighbors[i].state
				!= UNAUTHENTICATED
				&& AKM_DATA.authenticated_neighbors[i].state
				!= AUTHENTICATED) {
			return True;
		}

	}
	return False;
}

/*--------------------------------------------------------------------------*/
void internal_error(char* error_message) {
	PRINT_ERROR(error_message);
}
/*--------------------------------------------------------------------------*/
void akm_set_dodag_root(rpl_dag_t *pdag) {
	AKM_PRINTF("set_dodag_root: setting dodag root \n");
	AKM_DATA.is_dodag_root = 1;
}
/*---------------------------------------------------------------------------*/
rimeaddr_t*
get_node_id() {
	return &rimeaddr_node_addr;
}

/*--------------------------------------------------------------------------*/
nodeid_t * get_parent_id() {
	if (get_dodag_root() == NULL) {
		return NULL;
	}

	return (nodeid_t *) rpl_get_parent_lladdr(get_dodag_root(),
			get_dodag_root()->preferred_parent);
}
/*--------------------------------------------------------------------------*/
bool_t is_nodeid_zero(nodeid_t* pnodeId) {
	return rimeaddr_cmp(pnodeId, &rimeaddr_null);
}

/*---------------------------------------------------------------------------*/
bool_t is_capacity_available(nodeid_t* pnode) {
	int capacityCount = 0;
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (AKM_DATA.authenticated_neighbors[i].state == UNAUTHENTICATED) {
			capacityCount++;
		} else if (pnode != NULL
				&& rimeaddr_cmp(&AKM_DATA.authenticated_neighbors[i].node_id,
						pnode)
				&& AKM_DATA.authenticated_neighbors[i].state
						== PENDING_SEND_CHALLENGE) {
			AKM_PRINTF(
					"Already assigned a state %s to the slot. Capacity count is %d  returning True\n",
					get_auth_state_as_string( AKM_DATA.authenticated_neighbors[i].state),
					capacityCount);
			AKM_PRINTF("temporaryLink = ");
			AKM_PRINTADDR(&AKM_DATA.temporaryLink);
			return True;
		}
	}
	AKM_PRINTF("is_capacity_available: capacityCount = %d \n", capacityCount); /* Note that ONE slot is reserved */
	if (capacityCount > 1) {
		return True;
	} else {
		return False;
	}
}

/*---------------------------------------------------------------------------*/
void free_slot(int slot) {
	rimeaddr_copy(&AKM_DATA.authenticated_neighbors[slot].node_id,
			&rimeaddr_null);
}

/*---------------------------------------------------------------------------*/
void free_security_association(nodeid_t* pnodeId) {
	set_authentication_state(pnodeId, UNAUTHENTICATED);
}

/*---------------------------------------------------------------------------*/
void akm_timer_set(akm_timer_t *c, clock_time_t t, void (*f)(void *), void *ptr,
		int datasize, ttype_t timerType) {
#ifdef AKM_DEBUG
	AKM_PRINTF("akm_timer_set : %s %lu \n", c->timername, t)
#endif
	;
	if (t == 0) {
		AKM_PRINTF("ERROR!! invalid param t cannot be zero!\n");
		AKM_ABORT();
		return;
	}

	if (datasize > sizeof(c->ptr)) {
		AKM_PRINTF("ERROR!! data size is too large!\n");
		AKM_ABORT();
		return;
	}
	c->f = f;
	c->current_count = 0;
	c->interval = t;
	c->timer_state = TIMER_STATE_RUNNING;
	c->ttype = timerType;
	if (datasize > 0) {
		memcpy(&c->ptr, ptr, datasize);
	}

}

void akm_timer_reset(akm_timer_t* c) {
	c->current_count = 0;
}

void akm_timer_stop(akm_timer_t* c) {
	c->timer_state = TIMER_STATE_OFF;
}

void set_master_timer() {
	ctimer_set(&AKM_DATA.master_timer, CLOCK_SECOND, check_and_restart, NULL);
#ifdef AKM_DEBUG
	int i;
	strcpy(AKM_DATA.beacon_timer.timername, "beacon");
	char buf[32];
	for (i = 0; i < NELEMS(AKM_DATA.send_challenge_delay_timer); i++) {
		sprintf(buf, "%s-%d", "challenge-delay", i);
		strcpy(AKM_DATA.send_challenge_delay_timer[i].timername, buf);
	}
	for (i = 0; i < NELEMS(AKM_DATA.auth_timer); i++) {
		sprintf(buf, "%s-%d", "auth-timeout", i);
		strcpy(AKM_DATA.auth_timer[i].timername, buf);
	}

#endif

}

static void fire_timer(akm_timer_t* pakmTimer) {
	if (pakmTimer->timer_state == TIMER_STATE_RUNNING) {
		pakmTimer->current_count = (pakmTimer->current_count + 1)
				% pakmTimer->interval;
#ifdef AKM_DEBUG
		AKM_PRINTF("timer:%s count %d\n", pakmTimer->timername,
				pakmTimer->current_count);
#endif
		if (pakmTimer->current_count == 0) {
			(*pakmTimer->f)(&pakmTimer->ptr);
			if (pakmTimer->ttype == TTYPE_ONESHOT) {
				pakmTimer->timer_state = TIMER_STATE_OFF;
			}
		}

	}

}
static void check_and_restart(void *ptr) {
	AKM_PRINTF("check_and_restart master timer\n");

	int i;
	fire_timer(&AKM_DATA.beacon_timer);

	if (is_authenticated() && IS_CYCLE_DETECTION_ENABLED) {
		fire_timer(&AKM_DATA.cycle_detect_timer);
	}

	for (i = 0; i < NELEMS(AKM_DATA.send_challenge_delay_timer); i++) {
		fire_timer(&AKM_DATA.send_challenge_delay_timer[i]);
	}
	for (i = 0; i < NELEMS(AKM_DATA.auth_timer); i++) {
		fire_timer(&AKM_DATA.auth_timer[i]);
	}

	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (AKM_DATA.authenticated_neighbors[i].state == AUTHENTICATED) {
			AKM_DATA.authenticated_neighbors[i].time_since_last_ping++;
			if (AKM_DATA.authenticated_neighbors[i].time_since_last_ping
					> 2 * BEACON_TIMER_IDLE_INTERVAL) {
				AKM_PRINTF(
						"FAILED node detected- removing him from the list : ");
				AKM_PRINTADDR(&AKM_DATA.authenticated_neighbors[i].node_id);
				AKM_DATA.authenticated_neighbors[i].time_since_last_ping = 0;
				set_authentication_state(
						&AKM_DATA.authenticated_neighbors[i].node_id,
						UNAUTHENTICATED);
			}
		}
	}

	/* schedule it again */
	if (ctimer_expired(&AKM_DATA.master_timer)) {
		ctimer_restart(&AKM_DATA.master_timer);
	} else {
		ctimer_reset(&AKM_DATA.master_timer);
	}
}
/*--------------------------------------------------------------------------*/
int add_authenticated_neighbor(nodeid_t* pnodeId,
		authentication_state authState) {

	AKM_PRINTF("add_authenticated_neighbor : authState =  %s ",
			get_auth_state_as_string(authState));
	AKM_PRINTADDR(pnodeId);
	int i = 0;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (AKM_DATA.authenticated_neighbors[i].state == UNAUTHENTICATED) {
			rimeaddr_copy(&AKM_DATA.authenticated_neighbors[i].node_id,
					pnodeId);
			set_authentication_state(pnodeId, authState);
			break;
		}
	}
	if (!AKM_DATA.is_dodag_root)
		reset_beacon();
	return i;
}

/*---------------------------------------------------------------------------*/
bool_t has_authenticated_neighbors() {
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (AKM_DATA.authenticated_neighbors[i].state == AUTHENTICATED) {
			return True;
		}
	}
	return False;
}

/*---------------------------------------------------------------------------*/
bool_t is_redundant_parent_available() {
	bool_t redundantParentFlag = get_dodag_root() != NULL
			&& rpl_get_parent_count(get_dodag_root()) > 1;
	AKM_PRINTF("is_redundant_parent_available : %d\n", redundantParentFlag);
	return redundantParentFlag;
}
/*---------------------------------------------------------------------------*/
void akm_send(nodeid_t *targetId, akm_op_t command, int size) {
	int frag_size;
	int sizeToSend;
	frag_size = sizeof(akm_mac_header_t) + size;
	AKM_MAC_OUTPUT.mac_header.command = command;
	if (frag_size <= MAX_TRANSMIT_SIZE) {
		AKM_MAC_OUTPUT.mac_header.ftype = UNFRAGMENTED;
		packetbuf_copyfrom(&AKM_MAC_OUTPUT, frag_size);
		packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, targetId);
		packetbuf_set_addr(PACKETBUF_ADDR_SENDER, get_node_id());
		NETSTACK_CONF_FRAMER.create();
		sizeToSend = packetbuf_totlen();
		NETSTACK_RADIO.send(packetbuf_hdrptr(), sizeToSend);
		packetbuf_clear();
	} else {
		/* Message needs to be fragmented */
		int i;
		for(i=0; i<frag_size; i++) {
			printf("%2.x", ((uint8_t * ) &AKM_MAC_OUTPUT)[i]);
		}
		printf("\n");

		AKM_PRINTF("Fragmentation header\n");
		int startbuf = 0;
		int chunksize = MAX_TRANSMIT_SIZE - sizeof(AKM_MAC_OUTPUT.mac_header);

		int bytes_to_copy = frag_size - sizeof(AKM_MAC_OUTPUT.mac_header);
		uint8_t fid = AKM_DATA.output_fragid++;
		AKM_MAC_OUTPUT.mac_header.protocol_id = AKM_DISPATCH_BYTE;
		AKM_MAC_OUTPUT.mac_header.ftype = FRAG1;
		AKM_MAC_OUTPUT.mac_header.frag.frag1.id = fid;
		AKM_MAC_OUTPUT.mac_header.frag.frag1.fraglength = chunksize;
		AKM_MAC_OUTPUT.mac_header.frag.frag1.total_data_length = size;
		/* Send out a burst of packets. Do we want to wait between sends?*/
		AKM_PRINTF(
				"FRAG1 header fragid = %d fraglength = %d total_data_length = %d\n",
				fid, chunksize, size);
		packetbuf_copyfrom((char*) &AKM_MAC_OUTPUT, MAX_TRANSMIT_SIZE);
		packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, targetId);
		packetbuf_set_addr(PACKETBUF_ADDR_SENDER, get_node_id());
		NETSTACK_CONF_FRAMER.create();
		sizeToSend = packetbuf_totlen();
		NETSTACK_RADIO.send(packetbuf_hdrptr(), sizeToSend);
		bytes_to_copy -= chunksize;
		startbuf += chunksize;
		packetbuf_clear();

		do {

			chunksize = (
					bytes_to_copy
							< MAX_TRANSMIT_SIZE
									- sizeof(AKM_MAC_OUTPUT.mac_header) ?
							bytes_to_copy :
							MAX_TRANSMIT_SIZE
									- sizeof(AKM_MAC_OUTPUT.mac_header));
			AKM_MAC_OUTPUT.mac_header.protocol_id = AKM_DISPATCH_BYTE;
			AKM_MAC_OUTPUT.mac_header.ftype = FRAGN;
			AKM_MAC_OUTPUT.mac_header.frag.fragn.id = fid;
			AKM_MAC_OUTPUT.mac_header.frag.fragn.offset = startbuf;
			AKM_MAC_OUTPUT.mac_header.frag.fragn.fraglength = chunksize;
			void* dataptr = packetbuf_dataptr();
			packetbuf_set_datalen(
					chunksize + sizeof(AKM_MAC_OUTPUT.mac_header));
			AKM_PRINTF("FRAGN header fragid = %d fraglength = %d offset = %d\n",
					fid, chunksize, startbuf);
			/* Copy the mac header in first */
			memcpy(dataptr, (char*) &AKM_MAC_OUTPUT,
					sizeof(AKM_MAC_OUTPUT.mac_header));
			/* copy the data part in next*/
			dataptr += sizeof(AKM_MAC_OUTPUT.mac_header);
			memcpy(dataptr, (char*) &AKM_MAC_OUTPUT.data + startbuf, chunksize);

			packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, targetId);
			packetbuf_set_addr(PACKETBUF_ADDR_SENDER, get_node_id());
			NETSTACK_CONF_FRAMER.create();
			sizeToSend = packetbuf_totlen();
			NETSTACK_RADIO.send(packetbuf_hdrptr(), sizeToSend);
			packetbuf_clear();

			bytes_to_copy -= chunksize;
			startbuf += chunksize;

		} while (bytes_to_copy > 0);

	}
	packetbuf_clear();

}
/*---------------------------------------------------------------------------*/
bool_t is_neighbor_authenticated(nodeid_t* neighbor_id) {
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (rimeaddr_cmp(&AKM_DATA.authenticated_neighbors[i].node_id,
				neighbor_id)) {
			if (AKM_DATA.authenticated_neighbors[i].state == AUTHENTICATED) {
				return True;
			} else {
				return False;
			}
		}
	}
	return False;
}
/*----------------------------------------------------------------------------*/
int find_authenticated_neighbor(nodeid_t* nodeid) {
	int i = 0;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (rimeaddr_cmp(nodeid,
				&AKM_DATA.authenticated_neighbors[i].node_id)) {
			return i;
		}
	}
	return -1;
}

/*----------------------------------------------------------------*/
void update_liveness() {
	nodeid_t* senderId = &AKM_DATA.sender_id;
	AKM_PRINTF("update_liveness : "); AKM_PRINTADDR(senderId);
	int i = find_authenticated_neighbor(senderId);
	if (-1 != i) {
		AKM_PRINTF("update_liveness: Saw a ping from ");
		AKM_PRINTADDR(senderId);
		AKM_PRINTF("update_liveness: Resetting time_since_last_ping %d \n",
				AKM_DATA.authenticated_neighbors[i].time_since_last_ping );
		AKM_DATA.authenticated_neighbors[i].time_since_last_ping = 0;
	}
}

/*-----------------------------------------------------------------------*/
bool_t is_authenticated() {
	if (AKM_DATA.is_dodag_root) {
		return True;
	} else {
		return has_authenticated_neighbors();
	}
}

bool_t is_part_of_dodag() {
	return get_dodag_root() != NULL
			&& get_dodag_root()->preferred_parent != NULL;
}

/*---------------------------------------------------------------------------*/
void akm_route_message() {
	akm_mac_t* pakm_mac = &AKM_MAC_INPUT;

	rimeaddr_copy(&AKM_DATA.sender_id,
			(nodeid_t*) packetbuf_addr(PACKETBUF_ADDR_SENDER));
	akm_op_t op = pakm_mac->mac_header.command;
	nodeid_t* receiver_id = (nodeid_t*) packetbuf_addr(PACKETBUF_ADDR_RECEIVER);
#if defined(AKM_DEBUG) && defined(CONTIKI_TARGET_NATIVE)
	LOG_PARENTS();
#endif
	AKM_PRINTF("sender_id : ");
	AKM_PRINTADDR(&AKM_DATA.sender_id);

	AKM_PRINTF("receiver_id : ");
	AKM_PRINTADDR(receiver_id);
	AKM_PRINTF("my_nodeid ");
	AKM_PRINTADDR(get_node_id());

	if (!rimeaddr_cmp(receiver_id, ALL_NEIGHBORS)
			&& !rimeaddr_cmp(receiver_id, get_node_id())) {
		AKM_PRINTF("akm_route_message: Message is not for me.\n");
		return;
	}

	if (rimeaddr_cmp(&AKM_DATA.sender_id, get_node_id())) {
		AKM_PRINTF("akm_route_message: Message originated by me -- dropping\n");
		return;
	}
	update_liveness();
	switch (op) {
	case BEACON:
		if (!is_handling_challenge()) {
			handle_beacon(&pakm_mac->data.beacon);
		}
		break;
	case AUTH_CHALLENGE:
		handle_auth_challenge(&pakm_mac->data.auth_challenge);
		break;
	case AUTH_CHALLENGE_RESPONSE:
		handle_auth_challenge_response(&pakm_mac->data.auth_challenge_response);
		break;
	case AUTH_ACK:
		handle_auth_ack(&pakm_mac->data.auth_ack);
		break;

	case BREAK_SECURITY_ASSOCIATION_REQUEST:
		handle_break_security_association(&pakm_mac->data.bsa_request);
		break;

	case CONFIRM_TEMPORARY_LINK_REQUEST:
		handle_confirm_temporary_link(
				&pakm_mac->data.confirm_temp_link_request);
		break;

	case INSERT_NODE_REQUEST:
		handle_insert_node_request(&pakm_mac->data.insert_node);
		break;

#if IS_CYCLE_DETECTION_ENABLED==1
		case CYCLE_DETECT:
		handle_cycle_detect(&pakm_mac->data.cycle_detect);
		break;
#endif

	default:
		PRINT_ERROR("akm_route_message:Not implemented\n");
		AKM_ABORT();
	}

}
/*---------------------------------------------------------------------------*/
static void init(void) {
	AKM_PRINTF("akm-mac : init()");
	AKM_PRINTADDR(get_node_id());

	init_crypto();

	AKM_MAC_OUTPUT.mac_header.protocol_id = AKM_DISPATCH_BYTE;
	/*zero out the global data block */
	memset(&AKM_DATA, 0, sizeof(AKM_DATA));
	AKM_DATA.is_dodag_root = 0;
	/*Fragment id counter */
	AKM_DATA.output_fragid = 1;

	/* set the master timer running*/
	set_master_timer();

	random_init(get_node_id_as_int(get_node_id()));
#if defined(AKM_DEBUG) && defined(CONTIKI_TARGET_NATIVE)
	set_sighandler(akm_sighandler);
#endif

	if (is_authenticated()) {
		log_msg_one_node(AKM_LOG_NODE_AUTH_STATE, "AUTHENTICATED",
				strlen("AUTHENTICATED"));
	} else {
		log_msg_one_node(AKM_LOG_NODE_AUTH_STATE, "UNAUTHENTICATED",
				strlen("UNAUTHENTICATED"));
	}

}
/*---------------------------------------------------------------------------*/
#ifdef AKM_DEBUG
char* get_auth_state_as_string(authentication_state auth_state) {
	switch (auth_state) {
		case UNAUTHENTICATED:
		return "UNAUTHENTICATED";
		case PENDING_SEND_CHALLENGE:
		return "PENDING_SEND_CHALLENGE";
		case CHALLENGE_SENT_WAITING_FOR_OK:
		return "CHALLENGE_SENT_WAITING_FOR_OK";
		case OK_SENT_WAITING_FOR_ACK:
		return "OK_SENT_WAITING_FOR_ACK";
		case AUTH_PENDING:
		return "AUTH_PENDING";
		case AUTHENTICATED:
		return "AUTHENTICATED";
		default:
		return "UNDEFINED";
	}
}
#endif

/*---------------------------------------------------------------------------*/
void remove_parent(nodeid_t* parent_nodeid) {
	AKM_PRINTF("remove_parent: ");
	AKM_PRINTADDR(parent_nodeid);
	// uip_ds6_nbr_t *nbr = uip_ds6_nbr_ll_lookup((uip_lladdr_t*) parent_nodeid);
	uip_ipaddr_t* ipAddr = uip_ds6_nbr_ipaddr_from_lladdr(
			(uip_lladdr_t*) parent_nodeid);
	if (ipAddr != NULL) {
		rpl_parent_t* parent = rpl_find_parent(get_dodag_root(), ipAddr);
		if (parent != NULL) {
			AKM_PRINTF("Found parent rank = %d \n", parent->rank);
			rpl_remove_parent(parent);
		} else {
			AKM_PRINTF("Could not find parent.\n");
		}

		log_msg_one_node(AKM_LOG_REMOVE_REDUNDANT_PARENT,
				"REMOVE_REDUNDANT_PARENT", strlen("REMOVE_REDUNDANT_PARENT"));

	} else {
		AKM_PRINTF("Could not find neighbor in cache.\n");
	}
}
/*---------------------------------------------------------------------------*/
bool_t is_nodeid_in_parent_list(nodeid_t* nodeid) {
	uip_ds6_nbr_t *nbr = uip_ds6_nbr_ll_lookup((uip_lladdr_t*) nodeid);
	if (nbr != NULL && get_dodag_root() != NULL) {
		rpl_parent_t* parent = rpl_find_parent(get_dodag_root(), &nbr->ipaddr);
		return parent != NULL;
	} else
		return False;
}
/*---------------------------------------------------------------------------*/
rpl_dag_t * get_dodag_root() {
	return rpl_get_any_dag();
}

/*---------------------------------------------------------------------------*/
static void send_packet(mac_callback_t sent, void *ptr) {
	NETSTACK_RDC.send(sent, ptr);
}
/*---------------------------------------------------------------------------*/
void akm_packet_input(void) {

	akm_mac_t* pakm_mac = packetbuf_dataptr();

	AKM_PRINTF(
			"akm_mac::datalen = %d sizeof buffer = %d  protocol_id = %#lx \n",
			packetbuf_datalen(), sizeof(AKM_MAC_INPUT),
			pakm_mac->mac_header.protocol_id);
	if (pakm_mac->mac_header.protocol_id == AKM_DISPATCH_BYTE) {
		if (pakm_mac->mac_header.ftype == UNFRAGMENTED) {
			if (packetbuf_datalen() > sizeof(AKM_MAC_INPUT)) {
				AKM_PRINTF("ERROR! size in packetbuf is too big.\n");
			} else {
				memcpy(&AKM_MAC_INPUT, pakm_mac, packetbuf_datalen());
				akm_route_message();
			}
		} else {
			if (packetbuf_datalen() <= sizeof(AKM_MAC_INPUT)) {
				nodeid_t* sender = (nodeid_t*) packetbuf_addr(
						PACKETBUF_ADDR_SENDER);
				if (pakm_mac->mac_header.ftype == FRAG1) {
					AKM_PRINTF(
							"FRAG1 header total_length =  %d fragid =  %d fraglength = %d \n",
							pakm_mac->mac_header.frag.frag1.total_data_length,
							pakm_mac->mac_header.frag.frag1.id,
							pakm_mac->mac_header.frag.frag1.fraglength);
					AKM_DATA.input_fragid = pakm_mac->mac_header.frag.frag1.id;
					rimeaddr_copy(&AKM_DATA.fragment_sender, sender);
					memcpy(&AKM_MAC_INPUT, pakm_mac,
							pakm_mac->mac_header.frag.frag1.fraglength
									+ sizeof(pakm_mac->mac_header));
					AKM_DATA.remaining_messagelen =
							pakm_mac->mac_header.frag.frag1.total_data_length
									- pakm_mac->mac_header.frag.frag1.fraglength;
				} else if (pakm_mac->mac_header.ftype == FRAGN
						&& AKM_DATA.input_fragid
								== pakm_mac->mac_header.frag.fragn.id
						&& rimeaddr_cmp(&AKM_DATA.fragment_sender, sender)) {
					AKM_PRINTF(
							"FRAGN header fragid = %d fraglength = %d offset = %d \n",
							pakm_mac->mac_header.frag.fragn.id,
							pakm_mac->mac_header.frag.fragn.fraglength,
							pakm_mac->mac_header.frag.fragn.offset);
					assert(
							pakm_mac->mac_header.frag.fragn.offset + pakm_mac->mac_header.frag.fragn.fraglength <= sizeof(AKM_MAC_INPUT));
					memcpy(
							(char*) &AKM_MAC_INPUT.data
									+ pakm_mac->mac_header.frag.fragn.offset,
							&pakm_mac->data,
							pakm_mac->mac_header.frag.fragn.fraglength);
					AKM_DATA.remaining_messagelen -=
							pakm_mac->mac_header.frag.fragn.fraglength;
					AKM_PRINTF("input_msglen = %d\n",
							AKM_DATA.remaining_messagelen);
				}
				if (AKM_DATA.remaining_messagelen == 0) {
					akm_route_message();
				}
			} else {
				AKM_PRINTF("Packetbuf is too big. DROPPING!!\n");
			}
		}
		packetbuf_clear();
	} else if (is_neighbor_authenticated(
			(nodeid_t*) packetbuf_addr(PACKETBUF_ADDR_SENDER))) {
		AKM_PRINTF("neighbor is authenticated routing directly to NETSTACK");
		NETSTACK_NETWORK.input();
	} else {
		packetbuf_clear();
	}
}

int get_node_id_as_int(nodeid_t* pnodeId) {
	return (int) pnodeId->u8[NELEMS(pnodeId->u8) - 1];
}
/*---------------------------------------------------------------------------*/
#ifdef AKM_DEBUG
void log_parents() {
	AKM_PRINTF("parents = {");
	rpl_dag_t* dodagRoot = get_dodag_root();

	if (dodagRoot != NULL) {

		int count = rpl_get_parent_count(dodagRoot);
		AKM_PRINTF(" count = %d\n",count);

		if ( count != 0) {
			rpl_parent_t** rpl_parents = (rpl_parent_t**) malloc(count*sizeof(rpl_parent_t*));
			uint16_t* p = (uint16_t*) malloc( sizeof(uint16_t) * (count + 1));
			rpl_get_parents(dodagRoot ,rpl_parents);
			int i = 0;
			for ( i = 0; i < count; i++ ) {
				p[i] = get_node_id_as_int(rpl_get_parent_lladdr(dodagRoot,rpl_parents[i]));
				AKM_PRINTADDR(rpl_get_parent_lladdr(dodagRoot,rpl_parents[i]));
				AKM_PRINTF("Parent ID = %d\n",p[i]);
			}
			p[count] = 0;
			log_msg_many_nodes(AKM_LOG_PARENT_ID,p,"RPL",3);
			free(p);
			free(rpl_parents);
		}

	}

	AKM_PRINTF("}\n");
}
#endif

/*---------------------------------------------------------------------------*/
#if defined(AKM_DEBUG) && defined(CONTIKI_TARGET_NATIVE)

static void akm_sighandler(int signo) {
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		AKM_PRINTF(
				"%d state = %s Neighbor address = ",i,get_auth_state_as_string(AKM_DATA.authenticated_neighbors[i].state))
		; AKM_PRINTADDR(&AKM_DATA.authenticated_neighbors[i]);
		char* authState = get_auth_state_as_string(AKM_DATA.authenticated_neighbors[i].state);
		//log_msg_two_nodes(AKM_LOG_LINK_AUTH_STATE, get_node_id_as_int(&AKM_DATA.authenticated_neighbors[i].node_id),authState, strlen(authState));
	}
	log_parents();
	log_msg_one_node(LOG_SIM_END, NULL, 0);
	exit(EXIT_SUCCESS);
}
#endif
/*---------------------------------------------------------------------------*/
static int on(void) {
	return NETSTACK_RDC.on();
}
/*---------------------------------------------------------------------------*/
static int off(int keep_radio_on) {
	return NETSTACK_RDC.off(keep_radio_on);
}
/*---------------------------------------------------------------------------*/
static unsigned short channel_check_interval(void) {
	return 0;
}
/*---------------------------------------------------------------------------*/
const struct mac_driver akm_mac_driver = { "akm-mac", init, send_packet,
		akm_packet_input, on, off, channel_check_interval, };
/*---------------------------------------------------------------------------*/

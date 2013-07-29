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




extern void rpl_remove_parent(rpl_dag_t *dag, rpl_parent_t *parent);
extern rpl_parent_t *rpl_select_redundant_parent(rpl_dag_t *dag);
void free_slot(int slot);

int auth_seqno = 0;

struct ctimer beacon_timer;
struct ctimer temp_link_timer;



akm_mac_t AKM_MAC_OUTPUT;

akm_data_t AKM_DATA;

akm_mac_t AKM_MAC_INPUT;

/*--------------------------------------------------------------------------*/
void internal_error(char* error_message)
{
	PRINT_ERROR(error_message);
}
/*--------------------------------------------------------------------------*/
void akm_set_dodag_root(rpl_dag_t *pdag) {
	AKM_PRINTF("set_dodag_root: setting dodag root \n");
	AKM_DATA.is_dodag_root = 1;
	AKM_DATA.is_authenticated = 1;
}


/*--------------------------------------------------------------------------*/
nodeid_t* grab_dodag_parent() {
	rpl_parent_t* parent = rpl_select_redundant_parent(get_dodag_root());
	nodeid_t* retval;
	if (parent != NULL) {
		uip_ds6_nbr_t * neighbor = uip_ds6_nbr_lookup(&parent->addr);
		//struct uip_neighbor_addr* pneighbor = uip_neighbor_lookup(&neighbor->ipaddr);
		retval = (nodeid_t*) &neighbor->lladdr;
	} else {
		retval = NULL;
	}

	rpl_remove_parent(get_dodag_root(), parent);
	return retval;
}



/*--------------------------------------------------------------------------*/
nodeid_t * get_parent_id() {
	rpl_parent_t* parent = rpl_select_redundant_parent(get_dodag_root());
	if (parent != NULL) {
		uip_ds6_nbr_t * neighbor = uip_ds6_nbr_lookup(&parent->addr);
		//struct uip_neighbor_addr* pneighbor = uip_neighbor_lookup(&neighbor->ipaddr);
		return (nodeid_t*) &neighbor->lladdr;
	} else {
		return NULL;
	}

}
/*--------------------------------------------------------------------------*/
bool_t is_nodeid_zero(nodeid_t* pnodeId) {
	return rimeaddr_cmp(pnodeId,&rimeaddr_null);
}
/*---------------------------------------------------------------------------*/
bool_t is_capacity_available() {
	int capacityCount = 0;
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (is_nodeid_zero(&AKM_DATA.authenticated_neighbors[i].node_id)) {
			 capacityCount++;
		}
	}
	if ( capacityCount > 1) {
		return True;
	} else {
		return False;
	}
}


/*---------------------------------------------------------------------------*/
void free_slot(int slot) {
	rimeaddr_copy(&AKM_DATA.authenticated_neighbors[slot].node_id,&rimeaddr_null);
}

/*---------------------------------------------------------------------------*/
void free_security_association(nodeid_t* pnodeId)
{
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (rimeaddr_cmp(pnodeId, &AKM_DATA.authenticated_neighbors[i].node_id)) {
			free_slot(i);
			if (!isAuthenticated()) {
				reset_beacon();
			}
			break;
		}
	}
}



/*---------------------------------------------------------------------------*/
static void insert_id(int location, nodeid_t* pNodeId,
		session_key_t* sessionKey, authentication_state authState) {
	rimeaddr_copy(&AKM_DATA.authenticated_neighbors[location].node_id, pNodeId);
	memcpy(&AKM_DATA.authenticated_neighbors[location].session_key,sessionKey,
			sizeof(AKM_DATA.authenticated_neighbors[location].session_key));
	AKM_DATA.authenticated_neighbors[location].state  = authState;
}

/*--------------------------------------------------------------------------*/
void add_authenticated_neighbor(nodeid_t* pnodeId,
		session_key_t* sessionKey, authentication_state authState) {

	int i = 0;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (is_nodeid_zero(&AKM_DATA.authenticated_neighbors[i].node_id)) {
			insert_id(i, pnodeId, sessionKey, authState);
			set_authentication_state(pnodeId,authState);
			break;
		}
	}
	reset_beacon();


}

/*--------------------------------------------------------------------------*/
bool_t replace_authenticated_neighbor(nodeid_t *pauthNeighbor,
		nodeid_t *newNeighbor, session_key_t* key) {
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++ ) {
		if(rimeaddr_cmp(pauthNeighbor,&AKM_DATA.authenticated_neighbors[i].node_id))
		{
			memcpy(&AKM_DATA.authenticated_neighbors[i].node_id,newNeighbor,sizeof(nodeid_t));
			memcpy(&AKM_DATA.authenticated_neighbors[i].session_key,key,sizeof(session_key_t));
			return True;
		}
	}
	internal_error("Cannot find authenticated neighbor to replace");
	return False;
}

/*---------------------------------------------------------------------------*/
bool_t has_authenticated_neighbors() {
	int i;
	for (i = 0 ; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if ( AKM_DATA.authenticated_neighbors[i].state == AUTHENTICATED ) {
			return True;
		}
	}
	return False;
}



/*---------------------------------------------------------------------------*/
bool_t is_redundant_parent_available() {
	return rpl_get_parent_count(get_dodag_root()) > 1;
}

/*---------------------------------------------------------------------------*/
void sec_generate_session_key() {
	// TODO complete this stub.
	return;
}
/*---------------------------------------------------------------------------*/
bool_t sec_verify_auth_response(auth_challenge_response_t *pauthResponse) {
	// TODO complete this stub
	return 1;
}

/*---------------------------------------------------------------------------*/
bool_t sec_verify_auth_request(auth_challenge_request_t *pauthRequest) {
	// TODO complete this stub
	return 1;
}
/*---------------------------------------------------------------------------*/
void akm_send(nodeid_t *targetId, akm_op_t command, int size) {
	int frag_size;
	int sizeToSend;
	frag_size = sizeof(akm_mac_t) + size;
	AKM_MAC_OUTPUT.mac_header.command = command;

	if ( frag_size < PACKETBUF_SIZE) {
		AKM_MAC_OUTPUT.mac_header.ftype = UNFRAGMENTED;
		packetbuf_copyfrom(&AKM_MAC_OUTPUT, sizeof(akm_mac_t) + size);
		packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, targetId);
		packetbuf_set_addr(PACKETBUF_ADDR_SENDER, getNodeId());
		NETSTACK_CONF_FRAMER.create();
		sizeToSend = packetbuf_totlen();
		NETSTACK_RADIO.prepare(packetbuf_hdrptr(), sizeToSend);
		NETSTACK_RADIO.send(packetbuf_hdrptr(), sizeToSend);
	} else {
		/* Message needs to be fragmented */
	    int startbuf = 0;
	    int bytes_to_copy = frag_size;
	    uint8_t fid = AKM_DATA.output_fragid;
	    AKM_DATA.output_fragid = (AKM_DATA.output_fragid++ % 127) + 1 ;
	    AKM_MAC_OUTPUT.mac_header.ftype = FRAG1;
	    AKM_MAC_OUTPUT.mac_header.frag.frag1.id = fid;
	    /* Send out a burst of packets. Do we want to wait between sends?*/
	    while(startbuf < frag_size) {
	    	packetbuf_copyfrom(&AKM_MAC_OUTPUT + startbuf,
	    			(bytes_to_copy< PACKETBUF_SIZE? bytes_to_copy:PACKETBUF_SIZE));
	    	startbuf += PACKETBUF_SIZE;
	    	if (bytes_to_copy > PACKETBUF_SIZE) {
	    		bytes_to_copy -= PACKETBUF_SIZE;
	    	}
	    	packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, targetId);
	    	packetbuf_set_addr(PACKETBUF_ADDR_SENDER, getNodeId());
	    	NETSTACK_CONF_FRAMER.create();
	    	sizeToSend = packetbuf_totlen();
	    	NETSTACK_RADIO.prepare(packetbuf_hdrptr(), sizeToSend);
	    	NETSTACK_RADIO.send(packetbuf_hdrptr(), sizeToSend);
	    	AKM_MAC_OUTPUT.mac_header.ftype = FRAGN;
	    	AKM_MAC_OUTPUT.mac_header.frag.fragn.id = fid;
	    	AKM_MAC_OUTPUT.mac_header.frag.fragn.offset = startbuf;
	    	AKM_MAC_OUTPUT.mac_header.frag.fragn.length =
	    			(bytes_to_copy< PACKETBUF_SIZE? bytes_to_copy:PACKETBUF_SIZE);

	    }

	}

}
/*---------------------------------------------------------------------------*/
bool_t is_neighbor_authenticated(nodeid_t* neighbor_id) {
	int i;
	for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
		if (rimeaddr_cmp(&AKM_DATA.authenticated_neighbors[i].node_id, neighbor_id)) {
			return True;
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




/*-----------------------------------------------------------------------*/
bool_t isAuthenticated() {
	if ( AKM_DATA.is_dodag_root) {
		return True;
	} else {
		return has_authenticated_neighbors();
	}
}

/*---------------------------------------------------------------------------*/
void akm_route_message() {
	akm_mac_t* pakm_mac = &AKM_MAC_INPUT;

	nodeid_t* sender_id = (nodeid_t*) packetbuf_addr(PACKETBUF_ADDR_SENDER);
	akm_op_t op = pakm_mac->mac_header.command;
	nodeid_t* receiver_id = (nodeid_t*) packetbuf_addr(PACKETBUF_ADDR_RECEIVER);

	AKM_PRINTF("sender_id ");
	PRINTADDR(sender_id);

	AKM_PRINTF("receiver_id");
	PRINTADDR(receiver_id);

	if (!rimeaddr_cmp(receiver_id, ALL_NEIGHBORS)
			&& !rimeaddr_cmp(receiver_id, getNodeId())) {
		AKM_PRINTF("akm_route_message: Message is not for me.");
		return;
	}

	/* If this is a fragmented header */
	if (pakm_mac->mac_header.ftype != UNFRAGMENTED) {
		// TODO - check if we have re-assembled everything otherwise return.
		return;
	}
	switch (op) {
	case BEACON:
		handle_beacon(sender_id, &pakm_mac->data.beacon);
		break;
	case AUTH_CHALLENGE:
		handle_auth_challenge(sender_id, &pakm_mac->data.auth_challenge);
		break;
	case AUTH_CHALLENGE_RESPONSE:
		handle_auth_challenge_response(sender_id,
				&pakm_mac->data.auth_challenge_response);
		break;
	case AUTH_ACK:
		handle_auth_ack(sender_id,&pakm_mac->data.auth_ack);
		break;

	case BREAK_SECURITY_ASSOCIATION_REQUEST:
		handle_break_security_association(sender_id,&pakm_mac->data.bsa_request);
		break;

	case BREAK_SECURITY_ASSOCIATION_REPLY:
		handle_break_security_association_reply(sender_id,&pakm_mac->data.bsa_reply);
		break;

	case CONFIRM_TEMPORARY_LINK_REQUEST:
		handle_confirm_temporary_link(sender_id,&pakm_mac->data.confirm_temp_link_request);
		break;

	case CONFIRM_TEMPORARY_LINK_RESPONSE:
		handle_confirm_temporary_link_response(sender_id,&pakm_mac->data. confirm_temp_link_response);
		break;


	default:
		AKM_PRINTF("akm_route_message:Not implemented");
	}

}
/*---------------------------------------------------------------------------*/
static void init(void) {
	AKM_PRINTF("akm-mac : init()");

	AKM_MAC_OUTPUT.mac_header.protocol_id = AKM_DISPATCH_BYTE;
	int i;
	for (i = 0; i < sizeof(AKM_DATA.authenticated_neighbors); i++) {
		free_slot(i);
	}
	/*zero out the global data block */
	memset(&AKM_DATA,0,sizeof(AKM_DATA));
	AKM_DATA.is_dodag_root = 0;
	/*Fragment id counter */
	AKM_DATA.output_fragid = 1;
}

/*---------------------------------------------------------------------------*/
void remove_parent(nodeid_t* parent_nodeid){
	uip_ds6_nbr_t *nbr = uip_ds6_nbr_ll_lookup((uip_lladdr_t*)parent_nodeid);
	rpl_parent_t* parent = rpl_find_parent(get_dodag_root(),&nbr->ipaddr);
	if (parent != NULL ) {
		rpl_remove_parent(get_dodag_root(),parent);
	}
}
/*---------------------------------------------------------------------------*/
bool_t is_nodeid_in_parent_list(nodeid_t* nodeid)
{
	uip_ds6_nbr_t *nbr = uip_ds6_nbr_ll_lookup((uip_lladdr_t*)nodeid);
	if ( nbr != NULL ) {
		rpl_parent_t* parent = rpl_find_parent(get_dodag_root(),&nbr->ipaddr);
		return parent != NULL;
	} else return False;
}
/*---------------------------------------------------------------------------*/
rpl_dag_t * get_dodag_root() {
	return rpl_get_any_dag();
}

/*---------------------------------------------------------------------------*/
bool_t is_part_of_dodag() {
	return rpl_get_parent_count(get_dodag_root()) >= 1;
}


/*---------------------------------------------------------------------------*/
static void send_packet(mac_callback_t sent, void *ptr) {
	NETSTACK_RDC.send(sent, ptr);
}
/*---------------------------------------------------------------------------*/
static void packet_input(void) {

	packetbuf_copyto(&AKM_MAC_INPUT);
	akm_mac_t* pakm_mac = &AKM_MAC_INPUT;

	AKM_PRINTF("akm_mac::datalen = %d\n", packetbuf_datalen());

	if (pakm_mac->mac_header.protocol_id == AKM_DISPATCH_BYTE) {
		akm_route_message();
	} else {
		NETSTACK_NETWORK.input();
	}
}
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
		packet_input, on, off, channel_check_interval, };
/*---------------------------------------------------------------------------*/

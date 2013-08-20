/*
 * marta.h
 *
 *  Created on: Jul 11, 2013
 *      Author: local
 */

#ifndef __AKM_MAC_H
#define __AKM_MAC_H
// MARTA specific codes.
#include <stdio.h>
#include <string.h>
#include <clock.h>

#include "rpl.h"
#include "net/mac/frame802154.h"
#include "rimeaddr.h"


#define PRINT_ERROR printf
#define AKM_DEBUG 1
#if AKM_DEBUG
#define AKM_PRINTF printf("akm:%d: ",clock()) ; printf
#define AKM_PRINTADDR(addr)\
	if ( addr == NULL) {  \
		printf ("NULL"); \
	} else {\
	printf(" %02x%02x:%02x%02x:%02x%02x:%02x%02x \n", \
	((uint8_t *)addr)[0], ((uint8_t *)addr)[1], \
	((uint8_t *)addr)[2], ((uint8_t *)addr)[3], \
	((uint8_t *)addr)[4], ((uint8_t *)addr)[5], \
	((uint8_t *)addr)[6], ((uint8_t *)addr)[7]); }
#else
#define AKM_PRINTF
#define AKM_PRINTADDR(addr)
#endif

#ifdef AKM_DEBUG
#define AKM_ABORT() exit(-1)
#else
#define AKM_ABORT
#endif

typedef enum {
	CYCLE_DETECT   = 1,
	AUTH_CHALLENGE = 2,
    AUTH_CHALLENGE_RESPONSE = 3,
    AUTH_ACK =  4,
    BREAK_SECURITY_ASSOCIATION_REQUEST = 5,
    BREAK_SECURITY_ASSOCIATION_REPLY = 6,
    INSERT_NODE_REQUEST = 7,
    CONFIRM_TEMPORARY_LINK_REQUEST = 8,
    CONFIRM_TEMPORARY_LINK_RESPONSE = 9,
    BEACON = 10,
} akm_op_t;

/* MARTA related constants */
#define BEACON_TIMER_INTERVAL     			5
#define BEACON_TIMER_AUTH_INTERVAL          10
#define TEMP_LINK_TIMER                     30
#define PENDING_AUTH_TIMEOUT         		30
#define SPACE_AVAILABLE_TIMER               5
#define REDUNDANT_PARENT_AVAILABLE_TIMER    10
#define NO_SPACE_TIMER                      15
#define CHALLENGE_SENT_TIMEOUT              5
#define WAITING_FOR_ACK_TIMEOUT             5

typedef  rimeaddr_t nodeid_t;

#define ALL_NEIGHBORS                 (nodeid_t*)&rimeaddr_null

typedef enum {
	True = 1,
	False = 0
} bool_t;

#define True 1
#define False 0


/* externally exposed functions */
bool_t is_authenticated();
nodeid_t* getNodeId();
void akm_route_message();


/* Placeholder */
typedef struct certificate{
	char dummy[32];
} certificate_t;


/* Placeholder */
typedef struct session_key {
	char dummy[32];
} session_key_t;

#define AKM_DISPATCH_BYTE 0x47 /*binary 0100111 -- reserved value in 6lowpan */

typedef enum {
	UNFRAGMENTED = 1,
	FRAG1 = 2,
	FRAGN = 3
} frag_type;
typedef struct akm_frag1 {
	uint8_t  id;        /* sequentially increasing fragid ID */
	uint8_t  fraglength;
	uint16_t total_data_length;
} akm_frag1_t;

typedef struct akm_fragn {
	uint8_t id;
	uint8_t fraglength;
	uint16_t offset;
} akm_fragn_t;

typedef struct akm_mac_header {
	uint8_t 	protocol_id;
	akm_op_t	command;
	frag_type   ftype;
	union{
		akm_frag1_t frag1;
		akm_fragn_t fragn;
	}frag;
}akm_mac_header_t;





typedef struct beacon_header {
	bool_t is_authenticated;
} beacon_t;



typedef enum  {
	AUTH_SPACE_AVAILABLE = 1,
	AUTH_REDUNDANT_PARENT_AVAILABLE = 2,
	AUTH_NO_SPACE = 3
} auth_challenge_sc;



typedef struct auth_challenge {
	auth_challenge_sc status_code; /* Indicates space availability of sender */
} auth_challenge_request_t;

typedef struct auth_challenge_response {
	auth_challenge_sc request_status_code;
	session_key_t session_key;
} auth_challenge_response_t;

typedef struct auth_ack {
	nodeid_t parent_id;
	session_key_t session_key;
} auth_ack_t;


typedef enum {
	BSA_OK=1, BSA_NOK=2
} bsa_status_code;

typedef enum {
	CTL_CONTINUATION_NONE,
	CTL_CONTINUATION_BREAK_SECURITY_ASSOCIATION_REPLY
} ctl_continuation;
typedef struct confirm_temporary_link_request {
	ctl_continuation ctl_continuation;
	nodeid_t child_id;
	nodeid_t parent_id;
} confirm_temporary_link_request_t;

typedef enum {
		CTL_OK=1,
		CTL_NOK=2
} ctl_status;

typedef struct confirm_temporary_link_response {
	ctl_status status_code;
	ctl_continuation continuation;
	nodeid_t child_id;
	nodeid_t parent_id;
	nodeid_t requesting_node_id;
} confirm_temporary_link_response_t;

typedef struct insert_node_request {
	nodeid_t parent_id;
	nodeid_t requesting_node_id;
	nodeid_t child_id;
} insert_node_request_t;

typedef enum {
     BSA_CONTINUATION_NONE = 1,
     BSA_CONTINUATION_INSERT_NODE = 2

} bsa_continuation;

typedef struct  {
	bsa_status_code status_code;
	nodeid_t requesting_node_id;
} break_security_association_reply_t;

typedef struct {
	bsa_continuation continuation;
	nodeid_t insert_node_requester;
} break_security_association_request_t;

typedef struct akm_mac {
	akm_mac_header_t mac_header;
	union {
		beacon_t beacon;
		auth_challenge_request_t auth_challenge;
		auth_challenge_response_t auth_challenge_response;
		auth_ack_t auth_ack;
		insert_node_request_t insert_node;
		break_security_association_request_t bsa_request;
		break_security_association_reply_t bsa_reply;
		confirm_temporary_link_request_t confirm_temp_link_request;
		confirm_temporary_link_response_t confirm_temp_link_response;
	}data;
}akm_mac_t;


typedef struct akm_packet
{
	frame802154_t frame;
	akm_mac_t akm_mac;
} akm_packet_t;

/* The list of neighbors for MARTA  -- we'll pass this in uding command line args*/
#ifndef NODE_KEY_CACHE_SIZE
#define NODE_KEY_CACHE_SIZE 6
#endif
#define NELEMS(x)  (sizeof(x) / sizeof(x[0]))

typedef enum {
	 UNAUTHENTICATED = 0,
	 PENDING_SEND_CHALLENGE,
	 CHALLENGE_SENT_WAITING_FOR_OK,
	 OK_SENT_WAITING_FOR_ACK,
	 AUTH_PENDING,
	 AUTHENTICATED
} authentication_state;

typedef struct
{
	nodeid_t node_id;
	session_key_t session_key;
	authentication_state state;
} authenticated_neighbor_t;

typedef enum {
	TIMER_STATE_OFF,
	TIMER_STATE_RUNNING
} akm_timer_state_t;
typedef enum {
	TTYPE_CONTINUOUS,
	TTYPE_ONESHOT
}ttype_t;
// For now, all timers have to do is deal with node ids
#define MAX_DATASIZE sizeof(nodeid_t) + sizeof(beacon_t)

typedef struct akm_timer {
#ifdef AKM_DEBUG
	 char timername[32];
#endif
	 void (*f)(void *);
	 char ptr[MAX_DATASIZE];
	 int interval;
	 int current_count;
	 ttype_t ttype;
	 akm_timer_state_t timer_state;
} akm_timer_t;


typedef struct akm_data
{
	bool_t is_dodag_root;
	nodeid_t node_id;
	uint8_t output_fragid;
	uint8_t input_fragid;
	nodeid_t sender_id;
	nodeid_t fragment_sender;
	uint16_t remaining_messagelen;
	// Node ID of temp link (if link is taken).
	nodeid_t temporaryLink;
	// One added slot for temporary link.
	authenticated_neighbor_t authenticated_neighbors[NODE_KEY_CACHE_SIZE+1];
	akm_timer_t auth_timer[NODE_KEY_CACHE_SIZE+1];
	akm_timer_t send_challenge_delay_timer[NODE_KEY_CACHE_SIZE+1];
	nodeid_t parent_cache[NODE_KEY_CACHE_SIZE+1]; /* Parent cache for "insert-me" */


	akm_timer_t beacon_timer;

	struct ctimer master_timer;


}akm_data_t;


typedef enum {
	AKM_LOG_NODE_AUTH_STATE = 4,
	AKM_LOG_PARENT_ID = 5
};


extern akm_data_t AKM_DATA;
extern akm_mac_t AKM_MAC_OUTPUT;

void free_security_association(nodeid_t* pnodeid);
int get_node_id_as_int(nodeid_t* node_id);
void schedule_beacon(void);

void handle_auth_ack(auth_ack_t* pauthAck);
void handle_auth_challenge(auth_challenge_request_t* pauthChallenge);
void handle_beacon(beacon_t *pbeacon);
void handle_auth_challenge_response(auth_challenge_response_t *pauthChallengeResponse);
void handle_break_security_association(break_security_association_request_t* pbsa);
void handle_break_security_association_reply(break_security_association_reply_t* msg);
void handle_confirm_temporary_link(confirm_temporary_link_request_t* ctl);
bool_t is_capacity_available(nodeid_t* target) ;
bool_t is_authenticated();
void akm_send(nodeid_t *targetId, akm_op_t command, int size);
bool_t is_nodeid_zero(nodeid_t* pnodeId);
bool_t is_redundant_parent_available();
bool_t is_temp_link_available();
void take_temporary_link();
void reset_beacon();
void schedule_send_challenge_timer(int time, nodeid_t* target,beacon_t* pbeacon);
bool_t replace_authenticated_neighbor(nodeid_t *pauthNeighbor,
		nodeid_t *newNeighbor, session_key_t* key);
void add_authenticated_neighbor(nodeid_t* pnodeId,
		session_key_t* sessionKey, authentication_state authState) ;
void schedule_pending_authentication_timer(nodeid_t *target);
void stop_auth_timer(nodeid_t* nodeid);
void send_insert_node_request(nodeid_t* target,nodeid_t* parentId);
void schedule_pending_authentication_timer(nodeid_t *target);
rpl_dag_t * get_dodag_root();
void send_auth_ack(nodeid_t* target_id,nodeid_t * pparent);
void free_slot(int slot);

bool_t is_authenticated();
nodeid_t* grab_dodag_parent();

nodeid_t * get_parent_id();
void schedule_challenge_sent_timeout(nodeid_t *target);
void sec_generate_session_key(nodeid_t* pnodeid);
void send_break_security_association_reply(nodeid_t *nodeId, nodeid_t* requestingNodeid);
void send_break_security_association(nodeid_t* target, bsa_continuation continuation, nodeid_t* pnodeid);
bool_t sec_verify_auth_response(auth_challenge_response_t *pauthResponse);
bool_t sec_verify_auth_request(auth_challenge_request_t* pauthChallengeRequest);
int find_authenticated_neighbor(nodeid_t* target);
void send_confirm_temporary_link(nodeid_t* target, nodeid_t* parent, nodeid_t* child);
void remove_parent(nodeid_t* parent_nodeid);
void drop_temporary_link();
bool_t set_authentication_state(nodeid_t* node_id, authentication_state authState);
void handle_confirm_temporary_link_response(
		confirm_temporary_link_response_t* ctlr);
bool_t is_neighbor_authenticated(nodeid_t* neighbor_id) ;
void send_challenge(nodeid_t* target, beacon_t* pbeacon);
rpl_parent_t *rpl_find_parent(rpl_dag_t *dag, uip_ipaddr_t *addr);
authentication_state get_authentication_state(nodeid_t* neighbor_id);
bool_t temporary_link_exists();
bool_t is_nodeid_in_parent_list(nodeid_t* nodeid);
char* get_auth_state_as_string(authentication_state authState);
void schedule_beacon(void);
void make_temporary_link_permanent();
void akm_timer_set(akm_timer_t *c, clock_time_t t, void (*f)(void *), void *ptr, int datasize, ttype_t ttype) ;
void akm_timer_reset(akm_timer_t* c);
void akm_timer_stop(akm_timer_t* c);
rpl_parent_t *rpl_get_first_parent(rpl_dag_t* dag) ;

void schedule_waiting_for_ack_timeout(nodeid_t *target);




#ifdef AKM_DEBUG
extern void set_sighandler(void (*handler)(int) );
#endif

#endif /* __AKM_MAC_H */

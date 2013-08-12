/*
 * akm-beacon.c
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
static clock_time_t get_beacon_interval();
/*---------------------------------------------------------------------------*/
void send_beacon() {
	AKM_PRINTF("send_beacon\n");
	AKM_MAC_OUTPUT.data.beacon.is_authenticated = AKM_DATA.is_authenticated;
	akm_send(ALL_NEIGHBORS, BEACON,sizeof(AKM_MAC_OUTPUT.data.beacon));
}

void handle_beacon(beacon_t *pbeacon) {
	nodeid_t* senderId = & AKM_DATA.sender_id;
	AKM_PRINTF("handle_beacon");
	AKM_PRINTADDR(senderId);
	if (AKM_DATA.is_dodag_root) {
		if (!is_neighbor_authenticated(senderId)) {
			send_challenge(senderId);
		}
	} else {
		int i;
		bool_t transientState = False;
		for (i = 0; i < NELEMS(AKM_DATA.authenticated_neighbors); i++) {
			if (AKM_DATA.authenticated_neighbors[i].state != AUTHENTICATED &&
					AKM_DATA.authenticated_neighbors[i].state != UNAUTHENTICATED) {
				transientState = True;
				break;
			}
		}

		AKM_PRINTF("is_authenticated sender = %d is_part_of_dodag = %d\n",
				pbeacon->is_authenticated,is_part_of_dodag());
		if (is_part_of_dodag() && !transientState) {
			if (get_authentication_state(senderId) == UNAUTHENTICATED &&
					(!pbeacon->is_authenticated || is_capacity_available())){
				send_challenge(senderId);
			} else if (get_authentication_state(senderId) == AUTHENTICATED &&
					rimeaddr_cmp(&AKM_DATA.temporaryLink,senderId)){
				nodeid_t* parent = get_parent_id();
				send_auth_ack(senderId,parent);
			}
		}
	}

}
/*-----------------------------------------------------------------------*/
static void handle_beacon_timer(void* ptr) {
	AKM_PRINTF("handle_beacon_timer %d \n", isAuthenticated());
	send_beacon();
	AKM_DATA.beacon_timer.interval = get_beacon_interval();
}
/*-------------------------------------------------------------------------*/
static clock_time_t get_beacon_interval() {
	/* Schedule a  beacon message */
		if (!isAuthenticated() && !isAuthenticationInPending()) {
			return BEACON_TIMER_INTERVAL ;
		} else {
			return BEACON_TIMER_AUTH_INTERVAL ;
		}
}
/*--------------------------------------------------------------------------*/
void reset_beacon( void ) {
	AKM_PRINTF("reset_beacon\n");
	if ( is_capacity_available () ) {
		AKM_DATA.beacon_timer.timer_state = TIMER_STATE_RUNNING;
		AKM_DATA.beacon_timer.current_count = 0;
		AKM_DATA.beacon_timer.interval = get_beacon_interval();
	} else {
		AKM_DATA.beacon_timer.timer_state = TIMER_STATE_OFF;
	}
}

/*---------------------------------------------------------------------------*/

void schedule_beacon(void) {
	AKM_PRINTF("schedule_beacon %d\n",get_beacon_interval());
	send_beacon();
	akm_timer_set(&AKM_DATA.beacon_timer, get_beacon_interval(), handle_beacon_timer, NULL,TTYPE_CONTINUOUS);
}


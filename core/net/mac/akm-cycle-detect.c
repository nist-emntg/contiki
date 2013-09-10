/*
 * akm-cycle-detect.c
 *
 *  Created on: Sep 10, 2013
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
#if IS_CYCLE_DETECTION_ENABLED == 1
static clock_t lastTime;
static clock_t nextTime;
void handle_cycle_detect_timer(void* pvoid) {
	clock_t currentTime = clock_seconds();
	if ( is_authenticated() ) {
		send_cycle_detect();
		if ( nextTime < 8*CYCLE_DETECT_INTERVAL) {
			nextTime = 2*nextTime;
			akm_timer_set(&AKM_DATA.cycle_detect_timer, nextTime,
					handle_cycle_detect_timer, NULL, 0, TTYPE_CONTINUOUS);
		}
	} else {
		akm_timer_stop(&AKM_DATA.cycle_detect_timer);
	}
}

void send_cycle_detect() {
	if (get_parent_id() != NULL ) {
		rimeaddr_copy(&AKM_MAC_OUTPUT.data.cycle_detect.node_id,get_node_id());
		akm_send(get_parent_id(), CYCLE_DETECT, sizeof(AKM_MAC_OUTPUT.data.cycle_detect));
	}
}

void handle_cycle_detect(cycle_detect_t* pCycleDetect) {
	if ( rimeaddr_cmp(get_node_id(),&pCycleDetect->node_id)){
		AKM_PRINTF("CYCLE detected - leaving dodag and rejoining.");
		lastTime = 0;
		rpl_local_repair(get_dodag_root()->instance);
	} else {
		// Just forward the cycle detect.
		rimeaddr_copy(&AKM_MAC_OUTPUT.data.cycle_detect.node_id,&pCycleDetect->node_id);
		akm_send(get_parent_id(), CYCLE_DETECT,sizeof(AKM_MAC_OUTPUT.data.cycle_detect));
	}
}

void schedule_cycle_detect_timer(void) {
	AKM_PRINTF("schedule_cycle_detect_timer %d\n", CYCLE_DETECT_INTERVAL);
	lastTime = 0;
	nextTime = CYCLE_DETECT_INTERVAL;
	send_cycle_detect();
	akm_timer_set(&AKM_DATA.cycle_detect_timer, nextTime,
			handle_cycle_detect_timer, NULL, 0, TTYPE_CONTINUOUS);
}

void stop_cycle_detect_timer(void) {
	AKM_DATA.cycle_detect_timer.timer_state = TIMER_STATE_OFF;
}
#endif

/*
* Conditions Of Use
*
* This software was developed by employees of the National Institute of
* Standards and Technology (NIST), and others.
* This software has been contributed to the public domain.
* Pursuant to title 15 United States Code Section 105, works of NIST
* employees are not subject to copyright protection in the United States
* and are considered to be in the public domain.
* As a result, a formal license is not needed to use this software.
*
* This software is provided "AS IS."
* NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED
* OR STATUTORY, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT
* AND DATA ACCURACY. NIST does not warrant or make any representations
* regarding the use of the software or the results thereof, including but
* not limited to the correctness, accuracy, reliability or usefulness of
* this software.
*/

/* portion of this code was borrowed from the Cooja driver
 * authors:
 * - Ranganathan Mudumbai <mranga@nist.gov>
 * - Tony Cheneau <tony.cheneau@nist.gov>
 */

#include <arpa/inet.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>


#include "contiki.h"
#include "radio.h"
#include "net/packetbuf.h"
#include "net/rime/rimestats.h"
#include "net/netstack.h"
#include "net/uip.h"
#include "udp-client-setup.h"

/* TODO: revisit max stuffed-packet size */
/* size of header + timestamp + maxpacket */
#define MAX_PACKET_SIZE (1 + sizeof(struct timeval) + 127)

#define UDP_RADIO_BUFSIZE  128
#define MAX_QUEUE_LENGTH 32
#define SIM_HEADER_LENGTH 1
#define CRC_LENGTH 2

#ifndef PRINTF
#define PRINTF printf
#endif

char simReceiving = 0;
int simInSize = 0;
int simOutSize = 0;
char simRadioHWOn = 1;
int simSignalStrength = -100;
int simLastSignalStrength = -100;
char simPower = 100;
int simRadioChannel = 26;
int queueLength = 0;
sem_t mysem;
static const void *pending_data;
static int sockfd = 0;
struct sockaddr_in cliaddr;
static struct sockaddr emuaddr;
static socklen_t emuaddr_len;


/* simulation related data */
static uint16_t identifier = 0; /* the node's identifier in the simulation */
static char *mcast_addr = NULL, *emuaddrstr = NULL;
static char *mport = NULL, *emuport = NULL;

/* for parsing command line argument */
const struct option longopt [] = {
	{ "identifier", required_argument, NULL, 'i' },
	{ "maddr", required_argument, NULL, 'm' },
	{ "mport", required_argument, NULL, 'l' },
	{ "emuaddr", required_argument, NULL, 'e' },
	{ "emuport", required_argument, NULL, 'p' },
	{ "help", no_argument, NULL, 'h'},
	{ NULL, 0, NULL, 0},
};
extern char** contiki_argv;
extern int contiki_argc;


struct Node {
	char* data_packet;
	int length;
	struct Node *next;
};
/* This will be the unchanging first node */
static struct Node* recv_queue = NULL;

PROCESS(udpradio, "udpradio process");
static int radio_read(void *buf, unsigned short bufsize);
void* radio_thread(void *args);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udpradio, ev, data) {

	PROCESS_BEGIN()
	;
	PRINTF("udpradio_process started\n");

	while (1) {
		PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
		PRINTF("Got an event %d\n", ev);
		packetbuf_clear();
		PRINTF("udpradio_process reading radio");
		int len = radio_read(packetbuf_dataptr(), PACKETBUF_SIZE);
		if (len != 0) {
			packetbuf_set_datalen(len);
			NETSTACK_RDC.input();
		} else {
			PRINTF("Nothing to read \n");
		}
	}
PROCESS_END();

}

void* radio_thread(void *args) {
struct sockaddr_in src_addr;
int src_addr_length;

char simInDataBuffer[UDP_RADIO_BUFSIZE];

PRINTF("Starting radio_thread\n");
/* TODO print out the multicast listening port */
while (1) {
	PRINTF("Waiting for something \n");
	int nbytes = recvfrom(sockfd, simInDataBuffer, 10000, 0, &src_addr,
			&src_addr_length);
	PRINTF("Got something. nbytes = %d queueLength = %d \n", nbytes,
			queueLength);
	sem_wait(&mysem);
	if (queueLength < MAX_QUEUE_LENGTH) {
		struct Node* pnode = (struct Node*) malloc(sizeof(struct Node));
		char* buffer = malloc(nbytes);
		memcpy(buffer, simInDataBuffer, nbytes);
		pnode->data_packet = buffer;
		pnode->length = nbytes - CRC_LENGTH;
		pnode->next = recv_queue;
		recv_queue = pnode;
		queueLength++;
		PRINTF("enqueued\n");
		process_poll(&udpradio);
	}
	sem_post(&mysem);
}
return (void *) NULL;
}

/*---------------------------------------------------------------------------*/
void radio_set_channel(int channel) {
PRINTF("radio_set_channel %d\n", channel);
simRadioChannel = channel;
}
/*---------------------------------------------------------------------------*/
void radio_set_txpower(unsigned char power) {
/* 1 - 100: Number indicating output power */
PRINTF("radio_set_txpower %d\n", power);
simPower = power;
}
/*--------------------------------------------------------------------*/
static void parse_command_line(void) {
	int c, opt_idx = 0;
	while((c = getopt_long(contiki_argc,
						   contiki_argv,
						   "i:m:l:e:p:h",
						   longopt,
						   &opt_idx)) != -1) {
		switch (c) {
		case 'i': /* --identifier */
			identifier = atoi(optarg);
			break;
		case 'm': /* --maddr */
			mcast_addr = optarg;
			break;
		case 'l': /* --mport */
			mport = optarg;
			break;
		case 'e': /* --emuaddr */
			emuaddrstr = optarg;
			break;
		case 'p': /* --emuport */
			emuport = optarg;
			break;
		case 'h':
		default:
		/* print usage */
fprintf(stderr, "usage: %s -i ID -m MADDR -l MPORT -e DADDR -p DPORT\n", contiki_argv[0]);
fprintf(stderr, "-h,--help          this help message\n");
fprintf(stderr, "-i,--identifier    node's identifier for the simulation\n");
fprintf(stderr, "-m,--maddr         multicast address to listen on\n");
fprintf(stderr, "-l,--mport         multicast port to listen on\n");
fprintf(stderr, "-e,--emuaddr       address of the PHY emulator (wiredto154)\n");
fprintf(stderr, "-p,--emuport       PHY emulator (wiredto154) port to connect to\n");
			exit(EXIT_FAILURE);
		}

	}

	if (optind < contiki_argc) {
		fprintf(stderr, "some arguments are not recognized, "
				"use --help for the list of valid arguements\n");
		exit(EXIT_FAILURE);
	}

	if (! identifier) {
		fprintf(stderr, "--identifier argument is mandatory\n");
		exit(EXIT_FAILURE);
	}
	if (! mcast_addr) {
		fprintf(stderr, "--maddr argument is mandatory\n");
		exit(EXIT_FAILURE);
	}
	if (! mport) {
		fprintf(stderr, "--mport argument is mandatory\n");
		exit(EXIT_FAILURE);
	}
	if (! emuaddrstr) {
		fprintf(stderr, "--emuaddr argument is mandatory\n");
		exit(EXIT_FAILURE);
	}
	if (! emuport) {
		fprintf(stderr, "--emuport argument is mandatory\n");
		exit(EXIT_FAILURE);
	}
}

/*--------------------------------------------------------------------*/
static int init(void) {
	pthread_t reader;
	/* set up the udp server */
	PRINTF("Initializing udpradio\n");
	memset(&emuaddr, 0, sizeof(emuaddr));
	sem_init(&mysem, 0, 1);

	parse_command_line();

	sockfd = udp_client_setup(&emuaddr, &emuaddr_len, emuaddrstr, mport, emuport);
	if (sockfd < 0) {
		perror("udp_client_setup()");
		exit(EXIT_FAILURE);
	}

	// ask to join the PHY emulator multicast group
	// note that the PHY emulator address as to be of the same address familly
	// as the multicast group (e.g. both must be of type AF_INET)
	if (join_multicast_group(emuaddr.sa_family, mcast_addr, sockfd)) {
		fprintf(stderr, "unable to join multicast group, exiting");
		exit(EXIT_FAILURE);
	}

	int rc = pthread_create(&reader, (void *) NULL, radio_thread, (void *) NULL);

	if (rc < 0) {
		fprintf(stderr, "pthread_create() failed: %d\n", rc);
		exit(EXIT_FAILURE);
	}
	pthread_detach(reader);
	process_start(&udpradio, NULL);

	return 1;
}
/*---------------------------------------------------------------------------*/
static int prepare_packet(const void *data, unsigned short len) {
PRINTF("prepare_packet %d\n", len);
pending_data = data;
return 0;
}
/*---------------------------------------------------------------------------*/
static int channel_clear(void) {
PRINTF("channel_clear\n");
return 0;
}

/*---------------------------------------------------------------------------*/
static int radio_send(const void *payload, unsigned short payload_len) {
	//TODO:
	// - add some debug messages
	// - compute the real CRC eventually
	//PRINTF("udpradio:radio_send servaddr %s %d \n", inet_ntoa(servaddr.sin_addr),
	//		ntohs(servaddr.sin_port));
	char realpayload[MAX_PACKET_SIZE];
	realpayload[0] = 0; /* tells the PHY emulator that this is an incoming packet */
	memcpy(realpayload + 1, payload, payload_len); // copy the payload over
	sendto(sockfd, realpayload, SIM_HEADER_LENGTH + payload_len + CRC_LENGTH, 0,
		   &emuaddr, emuaddr_len);
	return RADIO_TX_OK;
}
/*---------------------------------------------------------------------------*/
static int radio_read(void *buf, unsigned short bufsize) {
PRINTF("udpradio:radio_read %d\n", bufsize);
if (recv_queue == NULL) {
	return 0;
}
// get the last packet from the queue;
sem_wait(&mysem);
struct Node* prev = recv_queue;
struct Node* pnode = recv_queue;
for (; pnode != NULL; prev = pnode, pnode = pnode->next) {

}
if (prev == recv_queue) {
	recv_queue = NULL;
} else {
	prev->next = NULL;
}
int length = bufsize < prev->length ? bufsize : prev->length;
memcpy(buf, prev->data_packet, length);
free(prev->data_packet);
free(prev);
queueLength--;
sem_post(&mysem);
return length;
}
/*---------------------------------------------------------------------------*/
static int transmit_packet(unsigned short len) {
PRINTF("transmit_packet %d\n", len);
int ret = RADIO_TX_ERR;
if (pending_data != NULL) {
	ret = radio_send(pending_data, len);
}
return ret;

}

/*---------------------------------------------------------------------------*/
static int pending_packet(void) {
PRINTF("pending_packet returning %d \n", pending_data != NULL);
return pending_data != NULL;
}

/*---------------------------------------------------------------------------*/
static int receiving_packet(void) {
PRINTF("receiving_packet returning %d\n", simReceiving);
return simReceiving;
}
/*---------------------------------------------------------------------------*/
static int radio_on(void) {
PRINTF("radio_on \n");
simRadioHWOn = 1;
return 1;
}

/*---------------------------------------------------------------------------*/
static int radio_off(void) {
PRINTF("radio_off \n");

simRadioHWOn = 0;
return 1;
}

/*---------------------------------------------------------------------*/
const struct radio_driver udpradio_driver = { init, prepare_packet,
	transmit_packet, radio_send, radio_read, channel_clear, receiving_packet,
	pending_packet, radio_on, radio_off, };


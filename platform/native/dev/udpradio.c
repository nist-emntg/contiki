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
 * - M. Ranganathan  <mranga@nist.gov>
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
#include <signal.h>


#include "contiki.h"
#include "radio.h"
#include "net/packetbuf.h"
#include "net/rime/rimestats.h"
#include "net/netstack.h"
#include "net/uip.h"
#include "crc16.h"
#include "udp-client-setup.h"

#ifndef PRINTF
#define PRINTF printf
#endif

#define char_to_int16(tab, x) ((tab[x] << 8) + tab[x+1])

/* 250 kbps -> 31.25kBps
   time to transfer 1 byte: 32 us */
#define TRANSFER_TIME_PER_BYTE 32
#define IEEE154_MTU 127
#define CRC_LENGTH 2
/* TODO: find what's the exact maximum received data unit for UDP */
#define MAX_RECEIVED_PACKET_SIZE 65535
#define SIM_HEADER_LEN 1
#define TS_LEN 8
/* duration of the Clear Channel Assesment (in microseconds) */
#define CCA_DURATION 320
/* preamble + start of frame + frame length */
#define PHY_HEADER (6+1+1)
/* computation time includes many tiny things:
 - the time it takes for the receiver to copy the packet in the buffer
 - the time it takes to raise an interrupt
 in the end, this value is more or less arbitrary
 */
#define COMPUTATION_DURATION 2500

char simReceiving = 0;
char simRadioHWOn = 1;
int simSignalStrength = -100;
int simLastSignalStrength = -100;
char simPower = 100;
int simRadioChannel = 26;
int queueLength = 0;
sem_t mysem;
static const void *pending_data;
static int sockfd = 0;
static struct sockaddr emuaddr;
static socklen_t emuaddr_len;

/* simulation related data */
static uint16_t identifier = 0; /* the node's identifier in the simulation */
static char *mcast_addr = NULL, *emuaddrstr = NULL;
static char *mport = NULL, *emuport = NULL;

/* for parsing command line argument */
const static struct option longopt [] = {
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

enum frame_type { INBOUND_FRAME, SIM_STOP, /* from the clients */
		  OUTBOUND_FRAME, SIM_END, /* from the server */
		  MISC_DATA = 128 /* type for events registered by the simulation logger */ };

enum msg_type { SELF_PACKET, INCOMING_PACKET,
		GARBAGE_PACKET, PACKET_NOT_FOR_ME,
		UNKNOWN_PACKET = 253, MALFORMED_PACKET = 254 };

struct Packet {
	char * data[IEEE154_MTU];
	uint8_t size;
	uint8_t inuse;
};

/* size of simulation_header + timestamp + maxpacket */
#define MAX_SENT_PACKET_SIZE (SIM_HEADER_LEN + TS_LEN + IEEE154_MTU)


struct Packet packet_buf;

PROCESS(udpradio, "udpradio process");
static int radio_read(void *buf, unsigned short bufsize);
void* radio_thread(void *args);
typedef void sigfunc(int);
sigfunc *sigcatcher;

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udpradio, ev, data) {

	PROCESS_BEGIN()
	;
	PRINTF("udpradio: process() started\n");

	while (1) {
		PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
		PRINTF("udpradio: got an event (type %d)\n", ev);
		packetbuf_clear();
		PRINTF("udpradio: reading radio\n");
		int len = radio_read(packetbuf_dataptr(), PACKETBUF_SIZE);
		if (len != 0) {
			packetbuf_set_datalen(len);
			NETSTACK_RDC.input();
		} else {
			PRINTF("udpradio: nothing to read\n");
		}
	}
PROCESS_END();

}

/*----------------------------------------------------------------------------*/
void default_signal_catcher(int signo) {
	PRINTF("Caught a signal %d - exitting\n",signo);
}
/*----------------------------------------------------------------------------*/
int check_and_parse(char * packet, int size, int * offset, int * packet_size) {
	char * p = packet;
	* offset = 2;
	if (size == 0)
		return MALFORMED_PACKET;

	if (p[0] == SIM_END) {
		fprintf(stderr, "udpradio: simulation is ending\n");
		/* TODO: call some code to save simulation data */
		exit(EXIT_SUCCESS);
	}

	/* parse the packet header */
	if (p[0] == OUTBOUND_FRAME) {
		uint16_t sender_id;
		uint16_t num_good, num_bad;
		++p;
		/* the first field is the sender ID */
		/* TODO: check that the packet looped back in a timely maner */
		sender_id = char_to_int16(p, 0);
		p+=2;
		if (sender_id == identifier) {
			num_good = char_to_int16(p, 0);
			p += 2;
			/* the second field is the size of the list of nodes
			 * that will receive the packet */
			p += num_good * (sizeof(uint16_t) / sizeof(*p));
			num_bad = char_to_int16(p, 0);
			p += 2;
			/* the fourth field is the size of the list of nodes
			 * that will receive some garbage */
			p += num_bad * (sizeof(uint16_t) / sizeof(*p));
			/* at this stage p points on the timestamp structure */
			* offset = p - packet;
			* packet_size = size - (* offset);
			return SELF_PACKET;
		} else {
			int good = 0, garbage = 0, i;
			/* the second field is the size of the list of nodes
			 * that will receive the packet */
			num_good = char_to_int16(p, 0);
			p += 2;

			if (num_good * sizeof(uint16_t) > size - (p - packet))
				return MALFORMED_PACKET;

			/* the third field is the list of these nodes */
			for(i=0; i < num_good; ++i) {
				if (identifier == char_to_int16(p, 0))
					good = 1;
				p += sizeof(uint16_t);
			}

			/* the fourth field is the size of the list of nodes
			 * that will receive some garbage */
			num_bad = char_to_int16(p, 0);
			p += 2;
			if (num_bad * sizeof(uint16_t) > size - (p - packet))
				return MALFORMED_PACKET;

			/* the fifth field is the list of these nodes */
			for(i=0; i < num_bad; ++i) {
				if (identifier == char_to_int16(p, 0))
					garbage = 1;
				p += sizeof(uint16_t);
			}

			* offset = p - packet;
			* packet_size = size - (* offset);

			/* the timestamp field let us know how long we should
			 * wait until the packet should actually be delivered */
			if (good && garbage)
				return MALFORMED_PACKET;
			else if (good)
				return INCOMING_PACKET;
			else if (garbage)
				return GARBAGE_PACKET;
			else
				return PACKET_NOT_FOR_ME;
		}
	} else
		return UNKNOWN_PACKET;
}
/*----------------------------------------------------------------------------*/
void stop_simulation(void) {
	PRINTF("asking for the whole simulation to stop (due to inconsistencies)\n");
	char buffer[1];
	buffer[0] = SIM_STOP;

	sendto(sockfd, buffer, sizeof(buffer), 0, &emuaddr, emuaddr_len);
	PRINTF("node is stopping");
	(*sigcatcher)(EXIT_FAILURE);
	exit(EXIT_FAILURE);
}

/*----------------------------------------------------------------------------*/
void set_sighandler(sigfunc* sf) {
	sigcatcher = sf;
	signal(SIGINT,sf);
}

/*----------------------------------------------------------------------------*/
void* radio_thread(void *args) {
struct sockaddr src_addr;
socklen_t src_addr_length;
int type, packet_offset, packet_size;

char simInDataBuffer[MAX_RECEIVED_PACKET_SIZE];

PRINTF("udpradio: Starting radio_thread\n");
while (1) {
	PRINTF("udpradio: Listening for a new packet\n");
	int nbytes = recvfrom(sockfd,
						  simInDataBuffer,
						  MAX_RECEIVED_PACKET_SIZE,
						  0,
						  &src_addr,
						  &src_addr_length);

	/* we get the current time so that we can compare against the packet own
	 * timestamp when necessary */
	struct timeval tv;
	gettimeofday(&tv, NULL);

	PRINTF("Received %d bytes of data from the PHY emulator\n", nbytes);

	type = check_and_parse(simInDataBuffer, nbytes, &packet_offset, &packet_size);
	switch (type) {
	case SELF_PACKET: {
		PRINTF("Received a self frame\n");
		int real_packet_size = packet_size - TS_LEN;

		uint32_t sec, usec, transmission_delay = 0;
		memcpy(&sec, simInDataBuffer + packet_offset, 4);
		memcpy(&usec, simInDataBuffer + packet_offset + 4, 4);

		if (sec == tv.tv_sec) /* same second */
			transmission_delay = tv.tv_usec - usec;
		else if (sec == tv.tv_sec - 1) /* tv_sec is on the next second */
			transmission_delay = usec - tv.tv_usec;
		else {/* more than one second delay is clearly not OK */
			PRINTF("transmission delay is more than a second\n");
			stop_simulation();
		}
/*
		if ((PHY_HEADER + real_packet_size) * TRANSFER_TIME_PER_BYTE
				+ CCA_DURATION
				+ COMPUTATION_DURATION
				< transmission_delay) {
			PRINTF("transmission delay is greater than the theoritical transmission delay"
				   " (%ld > %ld)\n",
				   transmission_delay,
				   (PHY_HEADER + real_packet_size) * TRANSFER_TIME_PER_BYTE
				   + CCA_DURATION + COMPUTATION_DURATION);
			stop_simulation();
		}
*/
		break;
	}
	case INCOMING_PACKET:
		/* skip the timestamp */
		packet_offset += TS_LEN;
		packet_size -= TS_LEN;

		PRINTF("Node successfully received a new data packet\n");
		sem_wait(&mysem);
		if(packet_buf.inuse) {
			fprintf(stderr, "can't accept a new packet while the previous "
					"one has not been processed\n");
			exit(EXIT_FAILURE);
		}
		memcpy(packet_buf.data, simInDataBuffer + packet_offset, packet_size - CRC_LENGTH);
		packet_buf.size = packet_size - CRC_LENGTH;
		packet_buf.inuse = 1;
		process_poll(&udpradio);
		break;
	default:
		PRINTF("unrecognized message type: %d\n", type);
	}

}
return (void *) NULL;
}

/*---------------------------------------------------------------------------*/
void radio_set_channel(int channel) {
PRINTF("udpardio: radio_set_channel %d\n", channel);
simRadioChannel = channel;
}
/*---------------------------------------------------------------------------*/
void radio_set_txpower(unsigned char power) {
/* 1 - 100: Number indicating output power */
PRINTF("udpradio: radio_set_txpower %d\n", power);
simPower = power;
}
/*--------------------------------------------------------------------*/
static void parse_command_line(void) {
	int c, opt_idx = 0;
	optind=0; /* because we used getopt in the contiki-main.c file */
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
	PRINTF("udpradio: Initializing\n");
	sem_init(&mysem, 0, 1);
	memset(&packet_buf, 0, sizeof(packet_buf));

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
		fprintf(stderr, "udpradio: pthread_create() failed: %d\n", rc);
		exit(EXIT_FAILURE);
	}
	pthread_detach(reader);
	process_start(&udpradio, NULL);
	sigcatcher = default_signal_catcher;
	/* Register signal catcher for when a node is killed manually */
	signal(SIGINT,sigcatcher);

	return 1;
}

/*---------------------------------------------------------------------------*/
static int prepare_packet(const void *data, unsigned short len) {
PRINTF("udpradio: prepare_packet %d\n", len);
pending_data = data;
return 0;
}
/*---------------------------------------------------------------------------*/
static int channel_clear(void) {
PRINTF("udpradio: channel_clear\n");
return 0;
}

/*---------------------------------------------------------------------------*/
static int radio_send(const void *payload, unsigned short payload_len) {
	char realpayload[MAX_SENT_PACKET_SIZE];
	struct timeval tv;

	if(payload_len == 0) {
		return RADIO_TX_ERR;
	}

	PRINTF("udpradio: sending %d bytes of data\n", payload_len);


	/* tells the PHY emulator that this is an incoming packet */
	realpayload[0] = INBOUND_FRAME;

	 /* copy the payload over */
	memcpy(realpayload + SIM_HEADER_LEN + TS_LEN, payload, payload_len);

	/* add the CRC */
	uint16_t crc = crc16_data(payload, payload_len, 0);
	realpayload[SIM_HEADER_LEN + TS_LEN + payload_len] = crc & 0xff;
	realpayload[SIM_HEADER_LEN + TS_LEN + payload_len + 1] = crc >> 8;

	/* timestamp related code is done last, so as to be more accurate */
	gettimeofday(&tv, NULL);
	/* workaround when tv_sec and tv_usec are encoded on 64 bits */
	uint32_t t_sec = (uint32_t) tv.tv_sec;
	uint32_t t_usec = (uint32_t) tv.tv_usec;
	/* copy the timestamp */
	memcpy(realpayload + SIM_HEADER_LEN, &t_sec, 4);
	memcpy(realpayload + SIM_HEADER_LEN + 4, &t_usec, 4);

	sendto(sockfd, realpayload, SIM_HEADER_LEN + TS_LEN + payload_len + CRC_LENGTH, 0,
		   &emuaddr, emuaddr_len);
	pending_data = NULL;
	/* simulate the CCA delay incurred by the unslotted CSMA-CA */
	usleep(CCA_DURATION);
	return RADIO_TX_OK;
}
/*---------------------------------------------------------------------------*/
static int radio_read(void *buf, unsigned short bufsize) {
	int length = 0;
	PRINTF("udpradio:radio_read (%d on max. %d)\n", packet_buf.size, bufsize);
	length = bufsize < packet_buf.size ? bufsize : packet_buf.size;
	memcpy(buf, packet_buf.data, length);
	memset(&packet_buf, 0, sizeof(packet_buf));
	sem_post(&mysem);
	return length;
}
/*---------------------------------------------------------------------------*/
static int transmit_packet(unsigned short len) {
PRINTF("udp_radio: transmit_packet %d\n", len);
int ret = RADIO_TX_ERR;
if (pending_data != NULL) {
	ret = radio_send(pending_data, len);
}
return ret;

}

/*---------------------------------------------------------------------------*/
static int pending_packet(void) {
PRINTF("udp_radio: pending_packet returning %d \n", pending_data != NULL);
return pending_data != NULL;
}

/*---------------------------------------------------------------------------*/
static int receiving_packet(void) {
PRINTF("udp_radio: receiving_packet returning %d\n", simReceiving);
return simReceiving;
}
/*---------------------------------------------------------------------------*/
static int radio_on(void) {
PRINTF("udpradio: radio_on \n");
simRadioHWOn = 1;
return 1;
}

/*---------------------------------------------------------------------------*/
static int radio_off(void) {
PRINTF("udpradio: radio_off \n");

simRadioHWOn = 0;
return 1;
}

/*---------------------------------------------------------------------*/
const struct radio_driver udpradio_driver = { init, prepare_packet,
	transmit_packet, radio_send, radio_read, channel_clear, receiving_packet,
	pending_packet, radio_on, radio_off, };


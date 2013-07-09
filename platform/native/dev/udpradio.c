#include <stdio.h>
#include <string.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>

#include "contiki.h"
#include "radio.h"
#include "net/packetbuf.h"
#include "net/rime/rimestats.h"
#include "net/netstack.h"
#include "net/uip.h"


#define UDP_RADIO_BUFSIZE  128
#define MAX_QUEUE_LENGTH 32
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
int sockfd;
struct sockaddr_in servaddr, cliaddr;

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
static int
radio_read(void *buf, unsigned short bufsize);
void* radio_thread(void *args);

/*---------------------------------------------------------------------------*/PROCESS_THREAD(udpradio, ev, data) {

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
sockfd = socket(AF_INET, SOCK_DGRAM, 0);
cliaddr.sin_family = AF_INET;
cliaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
cliaddr.sin_port = htons(33000);

char simInDataBuffer[UDP_RADIO_BUFSIZE];
int i;
int rc;
for (i = 0; i < 100; i++) {
	if ((rc = bind(sockfd, (const struct sockaddr *) &cliaddr, sizeof(cliaddr)))
			== -1) {
		cliaddr.sin_port++;
	} else {
		break;
	}
}
if (rc == -1) {
	PRINTF(" not bind client address \n");
	exit(-1);
}
PRINTF("Starting radio_thread client port = %d\n", cliaddr.sin_port);
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
static int init(void) {



pthread_t data;
/* set up the udp server */
PRINTF("Initializing udpradio\n");
bzero(&servaddr, sizeof(servaddr));
sem_init(&mysem, 0, 1);
servaddr.sin_family = AF_INET;
servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
servaddr.sin_port = htons(32000); // default emulator port.

int i;
for (i = 0; i < contiki_argc; i++) {
	if (strcmp(contiki_argv[i], "--srvaddr") == 0) {
		servaddr.sin_addr.s_addr = inet_addr(contiki_argv[i + 1]);
		i++;
	} else if (strcmp(contiki_argv[i], "--srvport") == 0) {
		servaddr.sin_port = htons(atoi(contiki_argv[i + 1]));
		i++;
	}
}
int rc = pthread_create(&data, (void *) NULL, radio_thread, (void *) NULL);

if (rc < 0) {
	PRINTF("pthread_create failed %d\n", rc);
	exit(0);
}
pthread_detach(data);
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
PRINTF("udpradio:radio_send servaddr %s %d \n", inet_ntoa(servaddr.sin_addr),
		ntohs(servaddr.sin_port));
void* crcPayload = malloc(payload_len + CRC_LENGTH); // add CRC to end.

memcpy(crcPayload, payload, payload_len); // copy the payload over
sendto(sockfd, crcPayload, payload_len + CRC_LENGTH, 0,
		(struct sockaddr *) &servaddr, sizeof(servaddr));
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


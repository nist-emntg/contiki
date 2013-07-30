#ifndef UDPCLIENT_H
#define UDPCLIENT_H

#include <sys/socket.h>

int udp_client_setup(struct sockaddr * dest_addr, socklen_t * addr_len,
				 const char * dst, const char * lport,
				 const char * dport);

int join_multicast_group(int af, const char * group, int socket);

#endif // UDPCLIENT_H

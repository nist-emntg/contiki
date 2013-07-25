#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "udp-client-setup.h"

#define PRINTF(...) printf(__VA_ARGS__)

int udp_client_setup(struct sockaddr * dest_addr, socklen_t * addr_len,
				 const char * dst, const char * lport,
				 const char * dport) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;

	/* Obtain address(es) matching host/dport */

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;	   /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;	   /* Any protocol */

	s = getaddrinfo(dst, dport, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	/* getaddrinfo() returns a list of address structures.
		  Try each address until we successfully connect(2).
		  If socket(2) (or connect(2)) fails, we (close the socket
		  and) try the next address. */

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
					 rp->ai_protocol);
		if (sfd == -1)
			continue;

		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
			int ret = -1, yes = 1, sendbuff = 2048;
			struct sockaddr unspec;
			memcpy(dest_addr, rp->ai_addr, sizeof(struct sockaddr));
			* addr_len = rp->ai_addrlen;

			memset(&unspec, 0, sizeof(struct sockaddr));
			unspec.sa_family = AF_UNSPEC;
			/* un-connect the socket */
			if (connect(sfd, &unspec, sizeof(struct sockaddr)) < 0) {
				PRINTF("unable to connect(AF_UNSPEC): %s\n", strerror(errno));
				close(sfd);
				continue;
			}

			if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes,
						   sizeof(int)) == -1) {
				perror("setsockopt()");
				exit(EXIT_FAILURE);
			}

			if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &sendbuff,
						   sizeof(sendbuff)) == -1) {
				perror("setsockopt()");
				exit(EXIT_FAILURE);
			}


			if (lport) {
				if (rp->ai_family == AF_INET) {
					struct sockaddr_in serv_addr;

					memset(&serv_addr, 0, sizeof(struct sockaddr_in));
					serv_addr.sin_family = AF_INET;
					serv_addr.sin_addr.s_addr = INADDR_ANY;
					serv_addr.sin_port = htons(atoi(lport));

					ret = bind(sfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
				} else if (rp->ai_family == AF_INET6) {
					struct sockaddr_in6 serv_addr;

					memset(&serv_addr, 0, sizeof(struct sockaddr_in6));
					serv_addr.sin6_family = AF_INET6;
					serv_addr.sin6_addr = in6addr_any;
					serv_addr.sin6_port = htons(atoi(lport));

					ret = bind(sfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
				}
				else {
					fprintf(stderr, "address family not supported\n");
					exit(EXIT_FAILURE);
				}

				if ( ret < 0 ) {
					PRINTF("unable to bind() the UDP socket: %s\n", strerror(errno));
					close(sfd);
					continue;
				}
			}

			/* bind the socket to a local port */
			break; /* Success */
		}

		close(sfd);
	}

	if (rp == NULL) { /* No address succeeded */
		fprintf(stderr, "Could not connect\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result);	   /* No longer needed */

	return sfd;
}

/* make the socket *socket* join a multicast group named *group* (IPv4 or IPv6)
 * the socket has to be bound to the address INADDR_ANY or in6addr_any and on a local port
 * exit on error, does not return anything */
int join_multicast_group(int af, const char * group, int sockfd) {
	int ret;

	switch(af) {
	case AF_INET: {
		struct ip_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		if(!inet_pton(AF_INET, group, & mreq.imr_multiaddr)) {
			perror("inet_pton()");
			return -1;
		}
		ret = setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
		break;
	}
	case AF_INET6: {
		struct ipv6_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		if (!inet_pton(AF_INET6, group, & mreq.ipv6mr_multiaddr)) {
			perror("inet_pton()");
			return -1;
		}
		ret = setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
		break;
	}
	default:
		fprintf(stderr, "address family not supported\n");
		return -1;
	}

	if (ret) {
		perror("MCAST_JOIN_GROUP");
		return -1;
	}
}

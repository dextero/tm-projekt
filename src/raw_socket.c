#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "raw_socket.h"

static int __create_raw_socket();
static void __set_ifr_name(struct ifreq* ifr, char* if_name);
static int __retrieve_if_index(int sockfd, struct ifreq* pifr);
static int __bind_raw_socket(int sockfd, struct ifreq* pifr);
static void __fill_sockaddr_ll(struct sockaddr_ll* psll, struct ifreq* pifr);
static int __set_socket_options(int sockfd, struct ifreq* pifr);

static int __create_raw_socket() {
	int retval = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	return retval;
}

static void __set_ifr_name(struct ifreq* ifr, char* if_name) {
	strncpy((char*) ifr->ifr_name, if_name, IFNAMSIZ);
}

static int __retrieve_if_index(int sockfd, struct ifreq* pifr) {
	int retval = ioctl(sockfd, SIOCGIFINDEX, pifr);
	return retval;
}

static int __bind_raw_socket(int sockfd, struct ifreq* pifr) {
	struct sockaddr_ll sll;
	__fill_sockaddr_ll(&sll, pifr);	
	int retval = bind(sockfd, (struct sockaddr*) &sll, sizeof(sll));
	return retval;
}

static void __fill_sockaddr_ll(struct sockaddr_ll* psll, struct ifreq* pifr) {
	psll->sll_family = AF_PACKET;
	psll->sll_ifindex = pifr->ifr_ifindex;
	psll->sll_protocol = htons(ETH_P_ALL);
}

static int __set_socket_options(int sockfd, struct ifreq* pifr) {
	struct packet_mreq mr;
	memset (&mr, 0, sizeof(mr));
	mr.mr_ifindex = pifr->ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	int retval = setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
	return retval;
}

int open_raw_socket(char* if_name) {
	int sockfd = __create_raw_socket();
	if(sockfd < 0)
		return sockfd;
	struct ifreq ifr;
	__set_ifr_name(&ifr, if_name);
	int retrievement_result = __retrieve_if_index(sockfd, &ifr);
	if(retrievement_result < 0)
		return retrievement_result;
	int binding_result = __bind_raw_socket(sockfd, &ifr);
	if(binding_result < 0)
		return binding_result;
	__set_socket_options(sockfd, &ifr);
	return sockfd;
}



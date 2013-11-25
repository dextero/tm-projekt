#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "raw_socket.h"

static int create_raw_socket();
static void set_ifr_name(struct ifreq* ifr, char* if_name);
static int retrieve_if_index(int sockfd, struct ifreq* pifr);
static int bind_raw_socket(int sockfd, struct ifreq* pifr);
static void fill_sockaddr_ll(struct sockaddr_ll* psll, struct ifreq* pifr);
static int set_socket_options(int sockfd, struct ifreq* pifr);

static int create_raw_socket() {
	int retval;
	retval = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	return retval;
}

static void set_ifr_name(struct ifreq* ifr, char* if_name) {
	strncpy((char*) ifr->ifr_name, if_name, IFNAMSIZ);
}

static int retrieve_if_index(int sockfd, struct ifreq* pifr) {
	int retval;
	retval = ioctl(sockfd, SIOCGIFINDEX, pifr);
	return retval;
}

static int bind_raw_socket(int sockfd, struct ifreq* pifr) {
	struct sockaddr_ll sll;
	int retval;
	fill_sockaddr_ll(&sll, pifr);	
	retval = bind(sockfd, (struct sockaddr*) &sll, sizeof(sll));
	return retval;
}

static void fill_sockaddr_ll(struct sockaddr_ll* psll, struct ifreq* pifr) {
	psll->sll_family = AF_PACKET;
	psll->sll_ifindex = pifr->ifr_ifindex;
	psll->sll_protocol = htons(ETH_P_ALL);
}

static int set_socket_options(int sockfd, struct ifreq* pifr) {
	struct packet_mreq mr;
	int retval;
	memset (&mr, 0, sizeof(mr));
	mr.mr_ifindex = pifr->ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	retval = setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
	return retval;
}

static void get_interface_mac(int sockfd, const char* if_name, mac_address* out_mac) {
    struct ifreq ifr;
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, if_name);
    ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    memcpy(out_mac, ifr.ifr_hwaddr.sa_data, sizeof(*out_mac));
}

int open_raw_socket(char* if_name, mac_address* out_mac) {
	int sockfd;
	struct ifreq ifr;
	int retrievement_result;
	int binding_result;
	sockfd = create_raw_socket();
	if(sockfd < 0)
		return sockfd;
	set_ifr_name(&ifr, if_name);
	retrievement_result = retrieve_if_index(sockfd, &ifr);
	if(retrievement_result < 0)
		return retrievement_result;
	binding_result = bind_raw_socket(sockfd, &ifr);
	if(binding_result < 0)
		return binding_result;
	set_socket_options(sockfd, &ifr);
    get_interface_mac(sockfd, if_name, out_mac);
	return sockfd;
}


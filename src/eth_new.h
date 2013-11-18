#ifndef MIKRO_PROJEKT_ETH_NEW_H
#define MIKRO_PROJEKT_ETH_NEW_H

#include <stddef.h>
#include <stdint.h>

#define ETH_MAX_PAYLOAD_LEN 1500
#define ETHERTYPE_IPV6 0x86DD

#pragma pack(1)
typedef struct mac_address {
	uint8_t bytes[6];
} mac_address;

typedef struct eth_socket {
	mac_address mac;
	int raw_socket_fd;
} eth_socket;

typedef struct eth_frame {
	mac_address dest_addr;
	mac_address src_addr;
	uint16_t ethertype;
	uint8_t tail[1508];
} eth_frame;
#pragma pack()

void bind_fd_to_mac(int sockfd, mac_address* mac, eth_socket* ethsock);
int eth_send(eth_socket* ethsock, mac_address* dest, uint16_t ethertype,
		uint8_t* buf, size_t len);
int eth_recv(eth_socket* ethsock, uint16_t* ethertype, uint8_t* buf,
		size_t* len);

#endif /* MIKRO_PROJEKT_ETH_NEW_H */
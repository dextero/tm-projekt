#ifndef MIKRO_PROJEKT_ETH_H
#define MIKRO_PROJEKT_ETH_H

#include <stddef.h>
#include <stdint.h>

#define ETH_MAX_DATA_LEN 1500

#pragma pack(1)
typedef struct mac_address {
	unsigned char bytes[6];
} mac_address;

typedef struct eth_socket {
	mac_address mac;
	int raw_socket_fd;
} eth_socket;

typedef struct eth_frame {
	mac_address dest_addr;
	mac_address src_addr;
	uint16_t ethertype;
	/* 4 bytes excluded from payload
	if the frame is tagged with a 802.1Q tag. */
	uint8_t payload[ETH_MAX_DATA_LEN + 4 + 4];
	uint32_t crc;
	uint8_t is_tagged;
} eth_frame;
#pragma pack()

void ethRecv(void *outBuffer, size_t bytes);
void ethSkip(size_t bytes);

void ethSend(const void *buffer, size_t bytes);

void bind_raw_socket_to_mac(int sockfd, mac_address* mac, eth_socket* ethsock);
void eth_send_data(eth_socket* ethsock, mac_address* dest, char* buf, int len);

#endif /* MIKRO_PROJEKT_ETH_H */

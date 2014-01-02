#include <string.h>
#include <unistd.h>

#include "eth_new.h"
#include "crc.h"
#include "utils.h"
#include "raw_socket.h"
#include "utils.h"

static int is_addressed_to_me(mac_address* my_mac, mac_address* dest_mac);

void eth_socket_init(eth_socket* ethsock) {
    mac_address mac;
    /* TODO: zmienic to "lo" */
    int sockfd = open_raw_socket("lo", &mac);
    bind_fd_to_mac(sockfd, &mac, ethsock);
}

void bind_fd_to_mac(int sockfd, mac_address* mac, eth_socket* ethsock) {
	ethsock->raw_socket_fd = sockfd;
	memcpy((void*) &(ethsock->mac), (void*) mac, sizeof(mac_address));
}

int eth_send(eth_socket* ethsock, mac_address* dest, uint16_t ethertype,
                uint8_t* buf, size_t len) {
	eth_frame frame;
	size_t total_len;
	uint32_t checksum;
	if(len > ETH_MAX_PAYLOAD_LEN) {
        logInfo("eth_send: too much data");
		return -1;
    }
	memcpy(&frame.dest_addr, (void*) dest, sizeof(mac_address));
	memcpy(&frame.src_addr, &ethsock->mac, sizeof(mac_address));
	frame.ethertype = htons(ethertype);
	memcpy((void*) frame.tail, (void*) buf, len);
	if(len < 46)
		len = 46;
	total_len = 2 * sizeof(mac_address) + sizeof(uint16_t) + len;
	/*if(ethertype <= ETH_MAX_PAYLOAD_LEN) {*/
		checksum = crc32buf((char*) &frame, total_len);
		memcpy((void*) (frame.tail + len), &checksum,
				sizeof(checksum));
		total_len += sizeof(checksum);
	/*}*/
	return write(ethsock->raw_socket_fd, &frame, total_len);
}

int eth_recv(eth_socket* ethsock, mac_address* out_source, uint16_t* ethertype,
        uint8_t* buf, size_t* len) {
	eth_frame frame;
	size_t read_octets;
	size_t tail_len;
	uint32_t checksum;
	read_octets = read(ethsock->raw_socket_fd, &frame, sizeof(frame));
    memcpy(out_source, &frame.dest_addr, sizeof(mac_address));
	if(read_octets < 64)
		return -1;
	if(!is_addressed_to_me(&ethsock->mac, &frame.dest_addr))
		return eth_recv(ethsock, out_source, ethertype, buf, len);
	*ethertype = ntohs(frame.ethertype);
	tail_len = read_octets - 2 * sizeof(mac_address) - sizeof(uint16_t);
	if(*ethertype > ETH_MAX_PAYLOAD_LEN) {
		memcpy(buf, frame.tail, tail_len);
		*len = tail_len;
		return 0;
	}
	tail_len -= 4;
	checksum = crc32buf((char*) &frame, tail_len);
	if(checksum != *((uint32_t*) (frame.tail + tail_len)))
		return eth_recv(ethsock, out_source, ethertype, buf, len);
	memcpy(buf, frame.tail, tail_len);
	*len = tail_len;
	return 0;
}

static int is_addressed_to_me(mac_address* my_mac, mac_address* dest_mac) {
	int i;
	int result;
	uint8_t* my_mac_bytes;
	uint8_t* dest_mac_bytes;
	my_mac_bytes = my_mac->bytes;
	dest_mac_bytes = dest_mac->bytes;
	result = 1;
	for(i = 0; i < 6; ++i)
		if(dest_mac_bytes[i] != (uint8_t) 255)
			result = 0;
	if(result)
		return result;
	for(i = 0; i < 6; ++i)
		if(my_mac_bytes[i] != dest_mac_bytes[i])
			return 0;
	return 1;
}










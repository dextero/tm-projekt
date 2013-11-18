#include "crc.h"
#include "eth.h"

#include <string.h>
#include <unistd.h>

#include "test_data.h"
#include "utils.h"

static const char DATA[] = TEST_IPv6_PACKET;
static const size_t dataSize = sizeof(DATA) - 1;
static size_t currPos = 0;

static uint32_t compute_crc(eth_frame* frame) {
	uint32_t checksum;
	char* buf;
	size_t len;
	uint16_t datalen;
	buf = (char*) frame;
	if(frame->is_tagged) {
		datalen = ntohs(*((char*) &(frame->ethertype) + 4));
		if(datalen < 42)
			datalen = 42;
	}
	else {
		datalen = ntohs(frame->ethertype);
		if(datalen < 46)
			datalen = 46;
	}
	len = 2 * sizeof(mac_address) + sizeof(uint16_t) + datalen;
	if(frame->is_tagged)
		len += 4;
	checksum = crc32buf(buf, len);
	return checksum;
}

static int
eth_send_data_df(eth_socket* ethsock, mac_address* dest, char* buf, uint16_t len) {
	eth_frame frame;
	uint32_t checksum;
	int sockfd;
	int to_send;
	memcpy(&frame.dest_addr, (void*) dest, sizeof(mac_address));
	memcpy(&frame.src_addr, (void*) &ethsock->mac, sizeof(mac_address));
	if(len < 46)	
		frame.ethertype = htons(46);
	else
		frame.ethertype = htons(len);
	memcpy((void*) frame.payload, (void*) buf, len);
	if(len < 46)
	memset((void *) (frame.payload + len), 0, 46 - len);
	checksum = compute_crc(&frame);
	sockfd = ethsock->raw_socket_fd;
	if(len < 46)
		len = 46;
	to_send = 2 * sizeof(mac_address) + sizeof(uint16_t) + len + 4;
	memcpy((void*) (frame.payload + len), &checksum, sizeof(checksum));
	return write(sockfd, &frame, to_send);
}

void ethRecv(void *outBuffer, size_t bytes) {
    while (bytes > 0) {
        size_t bytesToCopy = MIN(dataSize - currPos, bytes);

        memcpy(outBuffer, DATA + currPos, bytesToCopy);
        outBuffer = (char*)outBuffer + bytesToCopy;
        bytes -= bytesToCopy;
        currPos = (currPos + bytesToCopy) % dataSize;
    }
}

void ethSkip(size_t bytes) {
    currPos = (currPos + bytes) % dataSize;
}

void ethSend(const void *buffer, size_t bytes) {
    (void)buffer;
    logInfo("ethSend: %lu bytes\n", bytes);
}

void bind_raw_socket_to_mac(int sockfd, mac_address* mac, eth_socket* ethsock) {
	ethsock->raw_socket_fd = sockfd;
	memcpy((void*) &(ethsock->mac), (void*) mac, sizeof(mac_address));
}

void eth_send_data(eth_socket* ethsock, mac_address* dest, char* buf, int len) {
	while(len > ETH_MAX_DATA_LEN) {
		eth_send_data_df(ethsock, dest, buf, ETH_MAX_DATA_LEN);
		buf += ETH_MAX_DATA_LEN;
		len -= ETH_MAX_DATA_LEN;
	}
	eth_send_data_df(ethsock, dest, buf, len);
}



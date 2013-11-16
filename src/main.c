#include <stdlib.h>

#include "tcp_ip6.h"
#include "utils.h"

#include <unistd.h>

#include "eth.h"
#include "raw_socket.h"

unsigned char mac_array[6] = { '\xe8', '\x11', '\x32', '\x94', '\x11', '\x7b' };
unsigned char broadcast[6] = { 255, 255, 255, 255, 255, 255 };
unsigned char lolframe[6] = { 'a', 'b', 'c', 'd', 'e', 'f' };

int main(int argc, const char** argv) {
	int sockfd;
	/* mac_address mac; */
	eth_socket ethsock;
	sockfd = open_raw_socket(argv[1]);
	/* memcpy((void*) mac.bytes, (void*) mac_array, 6); */
	bind_raw_socket_to_mac(sockfd, mac_array, &ethsock);
	while(666) {
		eth_send_data(&ethsock, (mac_address*) broadcast, lolframe, sizeof(lolframe));
		sleep(1);
	}
	return 0;
}

/*
int main() {
    char *line = NULL;
    size_t lineLength = 0;
    size_t i;

    for (i = 0; i < 10; ++i) {
        tcpIp6RecvLine(&line, &lineLength);
        logInfo("read %lu characters", lineLength);
        logInfo(">%s<", line);
        free(line);
        line = NULL;
    }

    return 0;
}
*/

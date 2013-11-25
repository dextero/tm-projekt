#ifndef MIKRO_PROJEKT_SOCKET_H
#define MIKRO_PROJEKT_SOCKET_H

#include <stddef.h>

#include "tcp_ip6.h"

typedef struct tcpIp6Socket tcpIp6Socket;

tcpIp6Socket *socketTryAccept(uint16_t port);
void socketClose(tcpIp6Socket *socket);

int socketRecv(tcpIp6Socket *socket, char *buffer, size_t bufferSize);
int socketRecvLine(tcpIp6Socket *socket, char **outBuffer, size_t *outSize);

#endif /* MIKRO_PROJEKT_SOCKET_H */

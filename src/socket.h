#ifndef MIKRO_PROJEKT_SOCKET_H
#define MIKRO_PROJEKT_SOCKET_H

#include <stddef.h>

#include "tcp_ip6.h"

tcpIp6Socket *socketCreate(void);
void socketRelease(tcpIp6Socket *sock);

int socketAccept(tcpIp6Socket *sock,
                 uint16_t port);
void socketClose(tcpIp6Socket *sock);

int socketRecvLine(tcpIp6Socket *sock,
                   char **outLine,
                   size_t *outSize);
int socketRecv(tcpIp6Socket *sock,
               void *buffer,
               size_t bufferSize);

int socketSend(tcpIp6Socket *sock,
               void *data,
               size_t data_size);


#endif /* MIKRO_PROJEKT_SOCKET_H */

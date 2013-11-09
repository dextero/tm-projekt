#ifndef MIKRO_PROJEKT_TCP_IP6_H
#define MIKRO_PROJEKT_TCP_IP6_H

#include <stddef.h>
#include <stdint.h>

typedef uint16_t ip6Address[8];
typedef struct tcpIp6Socket tcpIp6Socket;

tcpIp6Socket *tcpIp6Accept(uint16_t port);
void tcpIp6Close(tcpIp6Socket *sock);

int tcpIp6RecvLine(tcpIp6Socket *sock,
                   char **outLine,
                   size_t *outSize);
int tcpIp6Recv(tcpIp6Socket *sock,
               void *buffer,
               size_t bufferSize);

#endif /* MIKRO_PROJEKT_TCP_IP6_H */

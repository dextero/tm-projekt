#ifndef MIKRO_PROJEKT_TCP_IP6_H
#define MIKRO_PROJEKT_TCP_IP6_H

#include <stddef.h>

int tcpIp6RecvLine(char **outLine, size_t *outSize);
int tcpIp6Recv(char *buffer, size_t bufferSize);

#endif /* MIKRO_PROJEKT_TCP_IP6_H */

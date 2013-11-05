#ifndef MIKRO_PROJEKT_TCP_H
#define MIKRO_PROJEKT_TCP_H

#include <stddef.h>

int tcpRecv(void *outBuffer, size_t size);
int tcpRecvLine(char **outString, size_t *outSize);

#endif /* MIKRO_PROJEKT_TCP_H */

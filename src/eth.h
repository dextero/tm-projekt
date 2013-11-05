#ifndef MIKRO_PROJEKT_ETH_H
#define MIKRO_PROJEKT_ETH_H

#include <stddef.h>

void ethRecv(void *outBuffer, size_t bytes);
void ethSkip(size_t bytes);

void ethSend(const void *buffer, size_t bytes);

#endif /* MIKRO_PROJEKT_ETH_H */

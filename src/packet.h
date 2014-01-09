#ifndef MIKRO_PROJEKT_TCP_IP6_H
#define MIKRO_PROJEKT_TCP_IP6_H

#include <stddef.h>
#include <stdint.h>

#include "ip6.h"
#include "tcp.h"

ip6PacketHeader *packetGetIp6Header(void *packet);
tcpPacketHeader *packetGetTcpHeader(void *packet);
uint16_t packetGetChecksum(void *packet);

void packetFillIp6Header(void *packet,
                         uint16_t nextHeaderType,
                         const ip6Address localAddress,
                         const ip6Address remoteAddress,
                         size_t dataLength);

void packetFillTcpHeader(void *packet,
                         tcpIp6Socket *sock,
                         uint32_t flags);

uint32_t packetGetTcpDataSize(void *packet);

#endif /* MIKRO_PROJEKT_TCP_IP6_H */

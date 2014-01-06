#ifndef MIKRO_PROJEKT_TCP_IP6_H
#define MIKRO_PROJEKT_TCP_IP6_H

#include <stddef.h>
#include <stdint.h>

#include "socket.h"
#include "tcp.h"

#define STREAM_ERROR (-1)
#define STREAM_WAITING_FOR_PACKET (-2)

int tcpSend(tcpIp6Socket *sock,
            uint32_t flags,
            void *data,
            size_t data_size);

int tcpProcessNextPacket(tcpIp6Socket *sock);

ssize_t tcpStreamReadNextPacket(tcpStream *stream,
                                void *buffer,
                                size_t bufferSize);
int tcpStreamReadNextLine(tcpStream *stream,
                          char **outLine,
                          size_t *outSize);

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

#endif /* MIKRO_PROJEKT_TCP_IP6_H */

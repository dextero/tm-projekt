#include "packet.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "utils.h"
#include "eth_new.h"
#include "generic_list.h"
#include "ip6.h"
#include "tcp.h"
#include "socket.h"
#include "ndp.h"
#include "arp.h"


ip6PacketHeader *packetGetIp6Header(void *packet) {
    return (ip6PacketHeader*)packet;
}

tcpPacketHeader *packetGetTcpHeader(void *packet) {
    return (tcpPacketHeader*)((char*)packet + sizeof(ip6PacketHeader));
}

static size_t calculateIp6PseudoHeaderChecksum(const ip6PacketHeader *header) {
    size_t checksum = 0;
    size_t dataLength = ntohs(header->dataLength);
    size_t i;

    for (i = 0; i < sizeof(header->source) / sizeof(uint16_t); ++i) {
        checksum += ntohs(header->source[i]);
        /*logInfo("%04x", ntohs(header->source[i]));*/
        checksum += ntohs(header->destination[i]);
        /*logInfo("%04x", ntohs(header->destination[i]));*/
    }

    checksum += dataLength;
    /*logInfo("%04x", dataLength);*/
    checksum += header->nextHeaderType;
    /*logInfo("%04x", header->nextHeaderType);*/

    return checksum;
}

uint16_t packetGetChecksum(void *packet) {
    ip6PacketHeader *ip6Header = packetGetIp6Header(packet);

    size_t checksum = 0;
    uint8_t *ptr = (uint8_t*)packetGetTcpHeader(packet);
    size_t i;
    size_t dataLength = ntohs(ip6Header->dataLength);

    checksum = calculateIp6PseudoHeaderChecksum(ip6Header);

    for (i = 0; i < dataLength; i += 2) {
        uint16_t val = ((ptr[i] << 8) & 0xFF00) + (ptr[i + 1] & 0xFF);
        checksum += val;
        /*logInfo("%04x", val);*/
    }

    if (dataLength % 2) {
        uint16_t val = (ptr[i - 1] << 8) & 0xFF00;
        checksum += val;
        /*logInfo("%04x", val);*/
    }

    checksum = htons(~(uint16_t)((checksum & 0xFFFF) + (checksum >> 16)));
    /*logInfo("checksum = %04x", checksum);*/
    return checksum;
}

void packetFillIp6Header(void *packet,
                         uint16_t nextHeaderType,
                         const ip6Address localAddress,
                         const ip6Address remoteAddress,
                         size_t dataLength) {
    ip6PacketHeader *ip6Header = packetGetIp6Header(packet);

    memcpy(ip6Header->source, localAddress, sizeof(ip6Address));
    memcpy(ip6Header->destination, remoteAddress, sizeof(ip6Address));

    ip6Header->hopLimit = 255;
    ip6Header->dataLength = dataLength;
    ip6Header->nextHeaderType = nextHeaderType;

    ip6SetVersion(ip6Header, 6);
    ip6SetTrafficClass(ip6Header, 0);   /* TODO */
    ip6SetFlowLabel(ip6Header, 0);      /* TODO */

    ip6ToNetworkByteOrder(ip6Header);
}

void packetFillTcpHeader(void *packet,
                         tcpIp6Socket *sock,
                         uint32_t flags) {
    ip6PacketHeader *ip6Header = packetGetIp6Header(packet);
    tcpPacketHeader *tcpHeader = packetGetTcpHeader(packet);
    uint32_t dataSize;

    tcpHeader->base.sourcePort = sock->localPort;
    tcpHeader->base.destinationPort = sock->remotePort;
    tcpHeader->base.urgentPointer = 0;      /* TODO */
    tcpHeader->base.windowWidth = ETH_MAX_PAYLOAD_LEN;    /* TODO */
    tcpHeader->base.checksum = 0;
    tcpHeader->base.sequenceNumber = sock->sequenceNumber;
    tcpHeader->base.ackNumber = (flags & TCP_FLAG_ACK)
            ? sock->stream.nextContiniousSeqNumber : 0;

    tcpSetDataOffset(tcpHeader, sizeof(tcpPacketHeaderBase));
    tcpSetFlags(tcpHeader, flags);

    if (flags & TCP_FLAG_SYN) {
        ++sock->sequenceNumber;
    }

    dataSize = ntohs(ip6Header->dataLength) - tcpGetDataOffset(tcpHeader);
    if (dataSize > 0) {
        /*logInfo("dataSize = %u", dataSize);*/
        sock->sequenceNumber += dataSize;
    }

    tcpToNetworkByteOrder(tcpHeader);
    tcpHeader->base.checksum = packetGetChecksum(packet);
}


#ifndef MIKRO_PROJEKT_TCP_H
#define MIKRO_PROJEKT_TCP_H

#include <stdint.h>
#include "utils.h"

#pragma pack(1)
typedef struct tcpPacketHeaderBase {
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint32_t sequenceNumber;
    uint32_t ackNumber;
    uint16_t flags;
    uint16_t windowWidth;
    uint16_t checksum;
    uint16_t urgentPointer;
} tcpPacketHeaderBase;

typedef enum tcpFlags {
    TCP_FLAG_URG = (1 << 5),
    TCP_FLAG_ACK = (1 << 4),
    TCP_FLAG_PSH = (1 << 3),
    TCP_FLAG_RST = (1 << 2),
    TCP_FLAG_SYN = (1 << 1),
    TCP_FLAG_FIN = (1 << 0)
} tcpFlags;

typedef uint32_t tcpPacketHeaderOptions[10];

typedef struct tcpPacketHeader {
    tcpPacketHeaderBase base;
    tcpPacketHeaderOptions options;
} tcpPacketHeader;
#pragma pack()

uint32_t tcpGetDataOffset(const tcpPacketHeader *header);
bool tcpGetFlag(const tcpPacketHeader *header, tcpFlags flag);

void tcpSetDataOffset(tcpPacketHeader *header,
                      uint32_t dataOffset);
void tcpSetFlags(tcpPacketHeader *header,
                 uint32_t flags);

#ifdef _DEBUG
void tcpDebugPrint(const tcpPacketHeader *header);
#else
#   define tcpDebugPrint (void)
#endif /* _DEBUG */

void tcpToHostByteOrder(tcpPacketHeader *header);
void tcpToNetworkByteOrder(tcpPacketHeader *header);

#endif /* MIKRO_PROJEKT_TCP_H */


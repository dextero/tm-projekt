#ifndef MIKRO_PROJEKT_TCP_H
#define MIKRO_PROJEKT_TCP_H

#include "utils.h"
#include <stddef.h>

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
    TCP_FLAG_NS  = (1 << 7),
    TCP_FLAG_CWR = (1 << 8),
    TCP_FLAG_ECN = (1 << 9),
    TCP_FLAG_URG = (1 << 10),
    TCP_FLAG_ACK = (1 << 11),
    TCP_FLAG_PSH = (1 << 12),
    TCP_FLAG_RST = (1 << 13),
    TCP_FLAG_SYN = (1 << 14),
    TCP_FLAG_FIN = (1 << 15)
} tcpFlags;

typedef uint32_t tcpPacketHeaderOptions[10];

typedef struct tcpPacketHeader {
    tcpPacketHeaderBase base;
    tcpPacketHeaderOptions options;
} tcpPacketHeader;
#pragma pack()

uint32_t tcpGetDataOffset(const tcpPacketHeaderBase *header);
bool tcpGetFlag(const tcpPacketHeaderBase *header, tcpFlags flag);

void tcpDebugPrint(const tcpPacketHeaderBase *header);

int tcpRecv(const void *buffer, size_t size);

#endif /* MIKRO_PROJEKT_TCP_H */

#ifndef MIKRO_PROJEKT_IP6_H
#define MIKRO_PROJEKT_IP6_H

#include "utils.h"
#include <stddef.h>

#pragma pack(1)
typedef uint16_t ip6Address[8];

typedef struct ip6PacketHeader {
    uint32_t versionTrafficClassFlowLabel;
    uint16_t dataLength;
    uint8_t nextHeader;
    uint8_t hopLimit;
    ip6Address source;
    ip6Address destination;
} ip6PacketHeader;
#pragma pack()

typedef struct ip6PacketBuffer {
    size_t size;
    size_t bytesWritten;
    uint8_t *data;
} ip6PacketBuffer;

uint32_t ip6GetVersion(const ip6PacketHeader *header);
uint32_t ip6GetTrafficClass(const ip6PacketHeader *header);
uint32_t ip6GetFlowLabel(const ip6PacketHeader *header);

void ip6DebugPrintAddress6(const char *label, const ip6Address addr);
void ip6DebugPrint(const ip6PacketHeader *header);

void ip6ToHostByteOrder(ip6PacketBuffer *packet);

void ip6PacketInit(ip6PacketBuffer *packet, const ip6PacketHeader *header);
void ip6PacketComplete(ip6PacketBuffer *packet);

int ip6Recv(const void *buffer, size_t size);

#endif /* MIKRO_PROJEKT_IP6_H */

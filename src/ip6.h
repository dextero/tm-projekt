#ifndef MIKRO_PROJEKT_IP6_H
#define MIKRO_PROJEKT_IP6_H

#include "utils.h"

#include <stddef.h>

#define ETHERTYPE_IPv6 0x86DD
#define HEADER_TYPE_TCP 6
#define HEADER_TYPE_ICMPv6 58

typedef uint16_t ip6Address[8];

#pragma pack(1)
typedef struct ip6PacketHeader {
    uint32_t versionTrafficClassFlowLabel;
    uint16_t dataLength;
    uint8_t nextHeaderType;
    uint8_t hopLimit;
    ip6Address source;
    ip6Address destination;
} ip6PacketHeader;
#pragma pack()


int ip6AddressForInterface(const char *interface,
                           ip6Address *outAddress);

uint32_t ip6GetVersion(const ip6PacketHeader *header);
uint32_t ip6GetTrafficClass(const ip6PacketHeader *header);
uint32_t ip6GetFlowLabel(const ip6PacketHeader *header);

void ip6SetVersion(ip6PacketHeader *header,
                   uint32_t version);

void ip6SetTrafficClass(ip6PacketHeader *header,
                        uint32_t trafficClass);

void ip6SetFlowLabel(ip6PacketHeader *header,
                     uint32_t flowLabel);

void ip6PrintAddress(const char *label,
                     const ip6Address addr,
                     bool isNetworkByteOrder);

#ifdef _DEBUG
void ip6DebugPrint(const ip6PacketHeader *header);
#else
#   define ip6DebugPrint (void)
#endif /* _DEBUG */

void ip6ToHostByteOrder(ip6PacketHeader *header);
void ip6ToNetworkByteOrder(ip6PacketHeader *header);

bool ip6AddressEqual(const ip6Address first,
                     const ip6Address second);

void ip6FillHeader(void *packet,
                   uint16_t nextHeaderType,
                   const ip6Address localAddress,
                   const ip6Address remoteAddress,
                   size_t dataLength);

#endif /* MIKRO_PROJEKT_IP6_H */

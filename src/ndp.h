#ifndef MIKRO_PROJEKT_NDP_H
#define MIKRO_PROJEKT_NDP_H

#include "socket.h"

#pragma pack(1)
typedef struct icmp6Option {
    uint8_t type;
    uint8_t length; /* 8-byte chunks */
    uint8_t data[6];
} icmp6Option;

typedef struct icmp6Packet {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t flags;
    ip6Address targetAddress;
    icmp6Option option;
} icmp6Packet;
#pragma pack()

typedef enum icmp6Flags {
    ICMP6_FLAG_ROUTER    = (1 << 31),
    ICMP6_FLAG_SOLICITED = (1 << 30),
    ICMP6_FLAG_OVERRIDE  = (1 << 29)
} icmp6Flags;

#define ICMP6_TYPE_NEIGHBOR_SOLICIT 135
#define ICMP6_TYPE_NEIGHBOR_ADVERTISE 136

#define ICMP6_OPTION_TARGET_MAC 2


int icmp6Interpret(void *packet,
                   tcpIp6Socket *sock);

void icmp6ToNetworkByteOrder(icmp6Packet *icmp);
#define icmp6ToHostByteOrder icmp6ToNetworkByteOrder

void printIcmp6PacketInfo(const char *header,
                          void *packet,
                          bool isNetworkByteOrder);

int icmp6SendSolicit(tcpIp6Socket *sock,
                     const ip6Address target);

icmp6Packet *packetGetIcmp6Data(void *packet);

#endif /* MIKRO_PROJEKT_NDP_H */

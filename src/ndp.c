#include "ndp.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ip6.h"
#include "eth_new.h"
#include "packet.h"
#include "arp.h"

const ip6Address IPv6_ALL_LINK_LOCAL = { 0xff, 0x02, 0, 0, 0, 0, 0, 1 };
mac_address MAC_BROADCAST = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

icmp6Packet *packetGetIcmp6Data(void *packet) {
    return (icmp6Packet*)((char*)packet + sizeof(ip6PacketHeader));
}

void icmp6ToNetworkByteOrder(icmp6Packet *icmp) {
    size_t i;

    icmp->flags = htonl(icmp->flags);
    for (i = 0; i < ARRAY_SIZE(icmp->targetAddress); ++i) {
        icmp->targetAddress[i] = htons(icmp->targetAddress[i]);
    }
}

void printIcmp6PacketInfo(const char *header,
                          void *packet,
                          bool isNetworkByteOrder) {
    ip6PacketHeader *ip6Header = packetGetIp6Header(packet);
    icmp6Packet *icmp = packetGetIcmp6Data(packet);
    size_t payloadSize = ip6Header->dataLength;
    size_t packetSize;
    uint32_t flags = icmp->flags;

    if (isNetworkByteOrder) {
        payloadSize = htons(payloadSize);
        flags = htonl(flags);
    }

    packetSize = sizeof(ip6PacketHeader) + payloadSize;

    logInfoNoNewline("%s: ICMP ", header);

    switch (icmp->type) {
    case ICMP6_TYPE_NEIGHBOR_SOLICIT:
        logInfoNoNewline("SOLICIT");
        break;
    case ICMP6_TYPE_NEIGHBOR_ADVERTISE:
        logInfoNoNewline("ADVERTISE");
        break;
    default:
        logInfoNoNewline("??? (%d)", (int)icmp->type);
        break;
    }

    logInfoNoNewline(" [%c%c%c], ",
                     (icmp->flags & ICMP6_FLAG_ROUTER) ? 'R' : ' ',
                     (icmp->flags & ICMP6_FLAG_SOLICITED) ? 'S' : ' ',
                     (icmp->flags & ICMP6_FLAG_OVERRIDE) ? 'O' : ' ');
    ip6PrintAddress("", ip6Header->source, isNetworkByteOrder);
    ip6PrintAddress(" -> ", ip6Header->destination, isNetworkByteOrder);
    ip6PrintAddress("; target: ", icmp->targetAddress, isNetworkByteOrder);
    logInfo(", %luB data", packetSize);
}

static int icmp6Send(tcpIp6Socket *sock,
                     mac_address *remote_mac,
                     int type,
                     int flags,
                     const ip6Address remoteIp,
                     const ip6Address targetIp) {
    char packetBuffer[sizeof(ip6PacketHeader) + sizeof(icmp6Packet)] = { 0 };
    icmp6Packet *packet = packetGetIcmp6Data(packetBuffer);

    packetFillIp6Header(packetBuffer, HEADER_TYPE_ICMPv6,
                        sock->localAddress, remoteIp, sizeof(icmp6Packet));

    packet->type = type;
    packet->code = 0;
    packet->flags = flags;
    packet->option.type = ICMP6_OPTION_TARGET_MAC;
    packet->option.length = 1;
    memcpy(packet->option.data, &sock->ethSocket.mac, sizeof(mac_address));
    memcpy(packet->targetAddress, targetIp, sizeof(ip6Address));

    icmp6ToNetworkByteOrder(packet);
    printIcmp6PacketInfo("SEND", packetBuffer, true);
    packet->checksum = packetGetChecksum(packetBuffer);

    if (eth_send(&sock->ethSocket, remote_mac, ETHERTYPE_IPv6,
                 (uint8_t*)packetBuffer, sizeof(packetBuffer)) < 0) {
        logInfo("eth_send failed");
        return -1;
    }

    return 0;
}

static int icmp6SendAdvertise(tcpIp6Socket *sock,
                              mac_address *remote_mac,
                              const ip6Address localIp,
                              const ip6Address *remoteIp) {
    return icmp6Send(sock, remote_mac, ICMP6_TYPE_NEIGHBOR_ADVERTISE,
                     remoteIp ? ICMP6_FLAG_SOLICITED : 0,
                     remoteIp ? *remoteIp : IPv6_ALL_LINK_LOCAL,
                     localIp);
}

int icmp6SendSolicit(tcpIp6Socket *sock,
                     const ip6Address target) {
    return icmp6Send(sock, &MAC_BROADCAST, ICMP6_TYPE_NEIGHBOR_SOLICIT, 0,
                     IPv6_ALL_LINK_LOCAL, target);
}


int icmp6Interpret(void *packet,
                   tcpIp6Socket *sock) {
    const ip6PacketHeader *ip6Header = packetGetIp6Header(packet);
    icmp6Packet *icmp = packetGetIcmp6Data(packet);
    mac_address *source = (mac_address*)icmp->option.data;

    switch (icmp->type) {
    case ICMP6_TYPE_NEIGHBOR_SOLICIT:
        if (icmp->code != 0) {
            logInfo("invalid code: %d", icmp->code);
            return -1;
        }

        /*ip6PrintAddress("got solicitation for ", ip6Header->source, false);*/
        /*logInfo("; MAC is to %x:%x:%x:%x:%x:%x",*/
                /*source->bytes[0], source->bytes[1], source->bytes[2],*/
                /*source->bytes[3], source->bytes[4], source->bytes[5]);*/

        arpAdd(ip6Header->source, *source);

        if (ip6AddressEqual(icmp->targetAddress, sock->localAddress)) {
            if (icmp6SendAdvertise(sock, source, sock->localAddress,
                                   &ip6Header->source)) {
                logInfo("icmp6SendAdvertise failed");
                return -1;
            }
        }
        break;
    case ICMP6_TYPE_NEIGHBOR_ADVERTISE:
        if (icmp->code != 0) {
            logInfo("invalid code: %d", icmp->code);
            return -1;
        }

        /*ip6PrintAddress("got advertisement for ",*/
                             /*icmp->targetAddress, false);*/
        /*logInfo("; MAC is to %x:%x:%x:%x:%x:%x",*/
                /*source->bytes[0], source->bytes[1], source->bytes[2],*/
                /*source->bytes[3], source->bytes[4], source->bytes[5]);*/

        arpAdd(icmp->targetAddress, *source);
        break;
    default:
        logInfo("unknown ICMPv6 packet type: %d", (int)icmp->type);
        return 0;
    }

    return 0;
}


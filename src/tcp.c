#include "tcp.h"

#include <string.h>

#include "test_data.h"
#include "utils.h"
#include "ip6.h"

uint32_t tcpGetDataOffset(const tcpPacketHeaderBase *header) {
    return (uint32_t)(((header->flags) & 0xf000) >> 12) * sizeof(uint32_t);
}

bool tcpGetFlag(const tcpPacketHeaderBase *header, tcpFlags flag) {
    return !!(header->flags & flag);
}

void tcpDebugPrint(const tcpPacketHeaderBase *header) {
#define FORMAT "%-12u (0x%x)"
    logInfo(
        "[TCP HEADER]\n"
        "     source port: " FORMAT "\n"
        "destination port: " FORMAT "\n"
        " sequence number: " FORMAT "\n"
        "      ack number: " FORMAT "\n"
        "     header size: " FORMAT "\n"
        "           flags:\n"
        "              ns  " FORMAT "\n"
        "              cwr " FORMAT "\n"
        "              ecn " FORMAT "\n"
        "              urg " FORMAT "\n"
        "              ack " FORMAT "\n"
        "              psh " FORMAT "\n"
        "              rst " FORMAT "\n"
        "              syn " FORMAT "\n"
        "              fin " FORMAT "\n",
        (unsigned int)header->sourcePort,      (unsigned int)header->sourcePort,
        (unsigned int)header->destinationPort, (unsigned int)header->destinationPort,
        (unsigned int)header->sequenceNumber,  (unsigned int)header->sequenceNumber,
        (unsigned int)header->ackNumber,       (unsigned int)header->ackNumber,
        tcpGetDataOffset(header),              tcpGetDataOffset(header),
        tcpGetFlag(header, TCP_FLAG_NS ),      tcpGetFlag(header, TCP_FLAG_NS ),
        tcpGetFlag(header, TCP_FLAG_CWR),      tcpGetFlag(header, TCP_FLAG_CWR),
        tcpGetFlag(header, TCP_FLAG_ECN),      tcpGetFlag(header, TCP_FLAG_ECN),
        tcpGetFlag(header, TCP_FLAG_URG),      tcpGetFlag(header, TCP_FLAG_URG),
        tcpGetFlag(header, TCP_FLAG_ACK),      tcpGetFlag(header, TCP_FLAG_ACK),
        tcpGetFlag(header, TCP_FLAG_PSH),      tcpGetFlag(header, TCP_FLAG_PSH),
        tcpGetFlag(header, TCP_FLAG_RST),      tcpGetFlag(header, TCP_FLAG_RST),
        tcpGetFlag(header, TCP_FLAG_SYN),      tcpGetFlag(header, TCP_FLAG_SYN),
        tcpGetFlag(header, TCP_FLAG_FIN),      tcpGetFlag(header, TCP_FLAG_FIN));
    logInfo(
        "    window width: " FORMAT "\n"
        "        checksum: " FORMAT "\n"
        "  urgent pointer: " FORMAT "\n",
        (unsigned int)header->windowWidth,     (unsigned int)header->windowWidth,
        (unsigned int)header->checksum,        (unsigned int)header->checksum,
        (unsigned int)header->urgentPointer,   (unsigned int)header->urgentPointer);
#undef FORMAT
}

int tcpRecv(const void *buffer, size_t size) {
    tcpPacketHeader header;
    const void *data;

    memcpy(&header.base, buffer, sizeof(tcpPacketHeaderBase));

    header.base.sourcePort      = ntohs(header.base.sourcePort);
    header.base.destinationPort = ntohs(header.base.destinationPort);
    header.base.sequenceNumber  = ntohl(header.base.sequenceNumber);
    header.base.ackNumber       = ntohl(header.base.ackNumber);
    header.base.flags           = ntohs(header.base.flags);
    header.base.windowWidth     = ntohs(header.base.windowWidth);
    header.base.checksum        = ntohs(header.base.checksum);
    header.base.urgentPointer   = ntohs(header.base.urgentPointer);

    data = (uint8_t*)buffer + tcpGetDataOffset(&header.base);

    tcpDebugPrint(&header.base);
    logInfo("[HTTP DATA]\n%s", data);

    return 0;
}

int main() {
    logInfo("packet size: %lu (%lx)",
            sizeof(TEST_TCP_PACKET) - 1, sizeof(TEST_TCP_PACKET) - 1);
#if 0
    return tcpRecv(TEST_TCP_PACKET, sizeof(TEST_TCP_PACKET) - 1);
#else
    return ip6Recv(TEST_IPv6_PACKET, sizeof(TEST_IPv6_PACKET) - 1);
#endif
}

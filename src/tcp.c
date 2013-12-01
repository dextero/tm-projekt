#include "tcp.h"
#include "utils.h"

#include <assert.h>

uint32_t tcpGetDataOffset(const tcpPacketHeader *header) {
    return (uint32_t)(((header->base.flags) & 0xF000) >> 12) * sizeof(uint32_t);
}

bool tcpGetFlag(const tcpPacketHeader *header, tcpFlags flag) {
    return !!(header->base.flags & flag);
}

void tcpSetDataOffset(tcpPacketHeader *header,
                      uint32_t dataOffset) {
    assert(dataOffset % sizeof(uint32_t) == 0);
    header->base.flags = (header->base.flags & 0x0FFF)
            | (((dataOffset / sizeof(uint32_t)) & 0xF) << 12);
}

void tcpSetFlags(tcpPacketHeader *header,
                 uint32_t flags) {
    header->base.flags = (header->base.flags & 0xF000)
            | (flags & 0x0FFF);
}

#ifdef _DEBUG
void tcpDebugPrint(const tcpPacketHeader *header) {
#ifndef LONG_DEBUG
    logInfo("port %u to %u,%s%s%s",
            (unsigned)header->base.sourcePort,
            (unsigned)header->base.destinationPort,
            (tcpGetFlag(header, TCP_FLAG_SYN) ? " SYN" : ""),
            (tcpGetFlag(header, TCP_FLAG_ACK) ? " ACK" : ""),
            (tcpGetFlag(header, TCP_FLAG_RST) ? " RST" : ""));
#else
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
        (unsigned int)header->base.sourcePort,      (unsigned int)header->base.sourcePort,
        (unsigned int)header->base.destinationPort, (unsigned int)header->base.destinationPort,
        (unsigned int)header->base.sequenceNumber,  (unsigned int)header->base.sequenceNumber,
        (unsigned int)header->base.ackNumber,       (unsigned int)header->base.ackNumber,
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
        (unsigned int)header->base.windowWidth,     (unsigned int)header->base.windowWidth,
        (unsigned int)header->base.checksum,        (unsigned int)header->base.checksum,
        (unsigned int)header->base.urgentPointer,   (unsigned int)header->base.urgentPointer);
#undef FORMAT
#endif /* LONG_DEBUG */
}
#endif /* _DEBUG */

void tcpToHostByteOrder(tcpPacketHeader *header) {
    header->base.sourcePort      = ntohs(header->base.sourcePort);
    header->base.destinationPort = ntohs(header->base.destinationPort);
    header->base.sequenceNumber  = ntohl(header->base.sequenceNumber);
    header->base.ackNumber       = ntohl(header->base.ackNumber);
    header->base.flags           = ntohs(header->base.flags);
    header->base.windowWidth     = ntohs(header->base.windowWidth);
    header->base.checksum        = ntohs(header->base.checksum);
    header->base.urgentPointer   = ntohs(header->base.urgentPointer);
}

void tcpToNetworkByteOrder(tcpPacketHeader *header) {
    tcpToHostByteOrder(header);
}


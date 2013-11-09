#include "tcp_ip6.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utils.h"
#include "eth.h"
#include "arp.h"
#include "generic_list.h"

/* ----------- *
 * IPv6 header *
 * ----------- */

#define HEADER_TYPE_TCP 6

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

#ifdef _DEBUG
static uint32_t ip6GetVersion(const ip6PacketHeader *header) {
    return (header->versionTrafficClassFlowLabel >> 28) & 0xF;
}

static uint32_t ip6GetTrafficClass(const ip6PacketHeader *header) {
    return (header->versionTrafficClassFlowLabel >> 20) & 0xFF;
}

static uint32_t ip6GetFlowLabel(const ip6PacketHeader *header) {
    return header->versionTrafficClassFlowLabel & 0xFFFFF;
}

static void ip6DebugPrintAddress6(const char *label, const ip6Address addr) {
    size_t i;
    enum {
        NOT_ENCOUNTERED_YET,
        STILL,
        DONE
    } zeros = NOT_ENCOUNTERED_YET;

    if (label != NULL)
        logInfoNoNewline(label);

    logInfoNoNewline("[");
    for (i = 0; i < sizeof(ip6Address) / sizeof(addr[0]); ++i) {
        if (addr[i] == 0) {
            switch (zeros) {
            case NOT_ENCOUNTERED_YET:
                logInfoNoNewline(":");
            case STILL:
                zeros = STILL;
                continue;
            default:
                break;
            }
        }

        zeros = (zeros == NOT_ENCOUNTERED_YET) ? NOT_ENCOUNTERED_YET : DONE;

        if (i > 0)
            logInfoNoNewline(":");
        logInfoNoNewline("%hx", addr[i]);
    }
    logInfo("]");
}

static void ip6DebugPrint(const ip6PacketHeader *header) {
#define FORMAT "%-6u (%x)"
    logInfo(
        "[IPv6 HEADER]\n"
        "      version: " FORMAT "\n"
        "traffic class: " FORMAT "\n"
        "   flow label: " FORMAT "\n"
        "  data length: " FORMAT "\n"
        "  next header: " FORMAT "\n"
        "    hop limit: " FORMAT,
        ip6GetVersion(header),            ip6GetVersion(header),
        ip6GetTrafficClass(header),       ip6GetTrafficClass(header),
        ip6GetFlowLabel(header),          ip6GetFlowLabel(header),
        (uint32_t)header->dataLength,     (uint32_t)header->dataLength,
        (uint32_t)header->nextHeaderType, (uint32_t)header->nextHeaderType,
        (uint32_t)header->hopLimit,       (uint32_t)header->hopLimit);
    ip6DebugPrintAddress6("       source: ", header->source);
    ip6DebugPrintAddress6("  destination: ", header->destination);
#undef FORMAT
}
#else
#   define ip6DebugPrintAddress6 (void)
#   define ip6DebugPrint (void)
#endif /* _DEBUG */

static void ip6ToHostByteOrder(ip6PacketHeader *header) {
    size_t i;

    header->dataLength = ntohs(header->dataLength);
    for (i = 0; i < ARRAY_SIZE(header->source); ++i) {
        header->source[i] = ntohs(header->source[i]);
    }
    for (i = 0; i < ARRAY_SIZE(header->destination); ++i) {
        header->destination[i] = ntohs(header->destination[i]);
    }

    ip6DebugPrint(header);
}

/* ---------- *
 * TCP header *
 * ---------- */

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
    TCP_FLAG_NS  = (1 << 8),
    TCP_FLAG_CWR = (1 << 7),
    TCP_FLAG_ECN = (1 << 6),
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

uint32_t tcpGetDataOffset(const tcpPacketHeader *header) {
    return (uint32_t)(((header->base.flags) & 0xf000) >> 12) * sizeof(uint32_t);
}

bool tcpGetFlag(const tcpPacketHeader *header, tcpFlags flag) {
    return !!(header->base.flags & flag);
}

#ifdef _DEBUG
static void tcpDebugPrint(const tcpPacketHeader *header) {
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
}
#else
#   define tcpDebugPrint (void)
#endif /* _DEBUG */

static void tcpToHostByteOrder(tcpPacketHeader *header) {
    header->base.sourcePort      = ntohs(header->base.sourcePort);
    header->base.destinationPort = ntohs(header->base.destinationPort);
    header->base.sequenceNumber  = ntohl(header->base.sequenceNumber);
    header->base.ackNumber       = ntohl(header->base.ackNumber);
    header->base.flags           = ntohs(header->base.flags);
    header->base.windowWidth     = ntohs(header->base.windowWidth);
    header->base.checksum        = ntohs(header->base.checksum);
    header->base.urgentPointer   = ntohs(header->base.urgentPointer);
}

/* --------------- *
 * recv* functions *
 * --------------- */

int ip6RecvNextPacket(void **outPacket) {
    ip6PacketHeader header;
    tcpPacketHeader *tcpHeader;

    *outPacket = NULL;

    while (true) {
        /* odbierz kolejny pakiet */
        ethRecv(&header, sizeof(header));
        ip6ToHostByteOrder(&header);

        if (header.nextHeaderType == HEADER_TYPE_TCP) {
            *outPacket = malloc(sizeof(header) + header.dataLength);
            memcpy(*outPacket, &header, sizeof(header));
            ethRecv((char*)*outPacket + sizeof(header), header.dataLength);

            tcpHeader = (tcpPacketHeader*)((char*)*outPacket + sizeof(header));
            tcpToHostByteOrder(tcpHeader);
            tcpDebugPrint(tcpHeader);

            return 0;
        } else {
            ethSkip(header.dataLength);
            logInfo("skipping non-TCP packet (type = %u)",
                    (unsigned)header.nextHeaderType);
        }
    }

    return 0;
}

/*
int tcpIp6Send(ip6Address dstIp,
               uint16_t dstPort,
               void *buffer,
               size_t bufferSize) {
    macAddress dstMac;
    tcpPacketHeader tcpHeader;
    ip6PacketHeader ip6Header;

    if (arpQuery(dstIp, &dstMac))

    tcpHeader.base.sourcePort = 80;
    tcpHeader.base.destinationPort = dstPort;
    tcpHeader.base.sequenceNumber = random();
    tcpHeader.base.ackNumber = 0;
    tcpHeader.base.flags = TCP_FLAG_SYN;
    tcpHeader.base.windowWidth;
    tcpHeader.base.checksum;
    tcpHeader.base.urgentPointer;
    TODO
}*/

typedef enum tcpSocketState {
    SOCK_STATE_CLOSED,
    SOCK_STATE_LISTEN,          /* SERVER only */
    SOCK_STATE_SYN_SENT,        /* client only */
    SOCK_STATE_SYN_RECEIVED,    /* SERVER only */
    SOCK_STATE_ESTABLISHED,
    SOCK_STATE_FIN_WAIT_1,
    SOCK_STATE_FIN_WAIT_2,
    SOCK_STATE_CLOSE_WAIT,
    SOCK_STATE_CLOSING,
    SOCK_STATE_LAST_ACK,
    SOCK_STATE_TIME_WAIT
} tcpSocketState;

static ip6PacketHeader *packetGetIp6Header(void *packet) {
    return (ip6PacketHeader*)packet;
}

static tcpPacketHeader *packetGetTcpHeader(void *packet) {
    return (tcpPacketHeader*)((char*)packet + sizeof(ip6PacketHeader));
}

bool ip6AddressEqual(const ip6Address first,
                     const ip6Address second) {
    return !memcmp(first, second, sizeof(ip6Address));
}

struct tcpIp6Socket {
    tcpSocketState state;
    ip6Address remoteAddress;
    uint16_t remotePort;
    uint16_t localPort;
    uint32_t sequenceNumber;
    uint32_t currPacketDataAlreadyRead;
    LIST(void*) packets;
};

LIST(tcpIp6Socket) allTcpSockets = NULL;

void tcpAddPacketToList(LIST(void*) *packets,
                        void *packet) {
    void ***curr;
    tcpPacketHeader *newTcpHeader = packetGetTcpHeader(packet);

    logInfo("tcpAddPacketToList");

    LIST_FOREACH_PTR(curr, packets) {
        tcpPacketHeader *tcpHeader = packetGetTcpHeader(*curr);
        logInfo("checking %p", curr);
        if (tcpHeader->base.sequenceNumber <
                newTcpHeader->base.sequenceNumber) {
            logInfo("inserting somewhere inside");
            *LIST_INSERT_NEW(curr, void*) = packet;
            return;
        }
    }

    logInfo("appending");
    *LIST_APPEND_NEW(packets, void*) = packet;
}

int tcpIp6ProcessPacket(bool accept,
                        uint16_t acceptPort,
                        tcpIp6Socket **outSocket) {
    void *packet;
    ip6PacketHeader *ip6Header;
    tcpPacketHeader *tcpHeader;
    tcpIp6Socket *socket;

    logInfo("tcpIp6ProcessPacket %d %u", accept, (unsigned)acceptPort);

    if (ip6RecvNextPacket(&packet)) {
        return -1;
    }

    ip6Header = packetGetIp6Header(packet);
    tcpHeader = packetGetTcpHeader(packet);

    logInfo("tcp packet: dst port = %u",
            (unsigned)tcpHeader->base.destinationPort);

    LIST_FOREACH(socket, allTcpSockets) {
        if (ip6AddressEqual(socket->remoteAddress, ip6Header->source)
                && socket->remotePort == tcpHeader->base.sourcePort) {
            tcpAddPacketToList(&socket->packets, packet);
            return 0;
        }
    }

    logInfo("no matching socket so far");

    if (accept
            && acceptPort == tcpHeader->base.destinationPort
            && tcpGetFlag(tcpHeader, TCP_FLAG_SYN)) {
        *outSocket = LIST_APPEND_NEW(&allTcpSockets, tcpIp6Socket);

        (*outSocket)->remotePort = tcpHeader->base.sourcePort;
        memcpy((*outSocket)->remoteAddress, ip6Header->source,
               sizeof(ip6Address));
        (*outSocket)->localPort = tcpHeader->base.destinationPort;
        (*outSocket)->state = SOCK_STATE_SYN_RECEIVED;
        (*outSocket)->sequenceNumber = tcpHeader->base.sequenceNumber;

        tcpAddPacketToList(&(*outSocket)->packets, packet);
    } else {
        logInfo("skipping packet");
        free(packet);
    }

    return 0;
}

tcpIp6Socket *tcpIp6Accept(uint16_t port) {
    tcpIp6Socket *sock = NULL;

    logInfo("tcpIp6Accept %u", (unsigned)port);
    do {
        if (tcpIp6ProcessPacket(true, port, &sock)) {
            return NULL;
        }
    } while (!sock);

    return sock;
}

int tcpIp6Recv(tcpIp6Socket *sock,
               void *buffer,
               size_t bufferSize) {
    while (bufferSize > 0) {
        ip6PacketHeader *ip6Header;
        tcpPacketHeader *tcpHeader;
        size_t dataOffset;
        size_t bytesRemaining;
        size_t bytesToCopy;

        while (!sock->packets) {
            logInfo("tcpIp6Recv waiting for packets");
            if (tcpIp6ProcessPacket(false, 0, NULL)) {
                logInfo("tcpIp6ProcessPacket() failed");
                return -1;
            }
        }

        ip6Header = packetGetIp6Header(*sock->packets);
        tcpHeader = packetGetTcpHeader(*sock->packets);

        dataOffset = tcpGetDataOffset(tcpHeader)
                     + sock->currPacketDataAlreadyRead;
        bytesRemaining = ip6Header->dataLength - dataOffset;
        bytesToCopy = MIN(bufferSize, bytesRemaining);

        memcpy(buffer, ((char*)tcpHeader) + dataOffset, bytesToCopy);

        sock->currPacketDataAlreadyRead += bytesToCopy;
        buffer = (char*)buffer + bytesToCopy;
        bufferSize -= bytesToCopy;

        logInfo("DEBUG______");
        ip6DebugPrint(ip6Header);

        logInfo("%zu bytes read, %zu remaining\n"
                "dataLength %zu, alreadyRead %zu",
                bytesToCopy, bufferSize,
                ip6Header->dataLength,
                sock->currPacketDataAlreadyRead);

        if (bytesRemaining == bytesToCopy) {
            free(*sock->packets);
            LIST_ERASE(&sock->packets);
            sock->currPacketDataAlreadyRead = 0;
        }
    }

    return 0;
}

void stringAppendPart(char **string,
                      const char *suffixStart,
                      const char *suffixEnd) {
    size_t oldLength = (*string ? strlen(*string) : 0);
    size_t newLength = oldLength + suffixEnd - suffixStart;
    char *newString = malloc(newLength + 1);

    if (*string) {
        memcpy(newString, *string, oldLength);
        free(*string);
    }

    memcpy(newString + oldLength, suffixStart, suffixEnd - suffixStart);
    newString[newLength] = '\0';

    *string = newString;
}

int tcpIp6RecvLine(tcpIp6Socket *sock,
                   char **outLine,
                   size_t *outSize) {
    *outLine = NULL;
    *outSize = 0;

    while (true) {
        ip6PacketHeader *ip6Header;
        tcpPacketHeader *tcpHeader;
        size_t currentChunkLength;
        char *lineStart;
        char *lineEnd;
        bool isEndOfPacket = false;

        while (!sock->packets) {
            logInfo("tcpIp6RecvLine waiting for packets");
            if (tcpIp6ProcessPacket(false, 0, NULL)) {
                logInfo("tcpIp6ProcessPacket() failed");
                return -1;
            }
        }

        ip6Header = packetGetIp6Header(*sock->packets);
        tcpHeader = packetGetTcpHeader(*sock->packets);

        lineStart = ((char*)tcpHeader) + tcpGetDataOffset(tcpHeader)
                     + sock->currPacketDataAlreadyRead;

        for (lineEnd = lineStart;
             !isEndOfPacket && *lineEnd != '\n';
             ++lineEnd) {
            if (lineEnd >= ((char*)tcpHeader) + ip6Header->dataLength) {
                isEndOfPacket = true;
            }
        }

        currentChunkLength = (lineEnd - lineStart);
        sock->currPacketDataAlreadyRead += currentChunkLength;
        *outSize += currentChunkLength;

        if (isEndOfPacket) {
            logInfo("end of packet!");

            stringAppendPart(outLine, lineStart, lineEnd);
            free(*sock->packets);
            LIST_ERASE(&sock->packets);
            sock->currPacketDataAlreadyRead = 0;
        } else {
            assert(*lineEnd == '\n');
            logInfo("end of line!");

            stringAppendPart(outLine, lineStart, lineEnd + 1);
            sock->currPacketDataAlreadyRead += 1;
            *outSize += 1; /* newline */
            break;
        }
    }

    return 0;
}


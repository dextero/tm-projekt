#include "tcp_ip6.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utils.h"
#include "eth_new.h"
#include "arp.h"
#include "generic_list.h"

/* ----------- *
 * IPv6 header *
 * ----------- */

#define ETHERTYPE_IPv6 0x86DD
#define HEADER_TYPE_TCP 6

#define LONG_DEBUG

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

static void ip6SetVersion(ip6PacketHeader *header,
                          uint32_t version) {
    header->versionTrafficClassFlowLabel =
        (header->versionTrafficClassFlowLabel & 0x0FFFFFFF)
        | ((version & 0xF) << 28);
}

static void ip6SetTrafficClass(ip6PacketHeader *header,
                               uint32_t trafficClass) {
    header->versionTrafficClassFlowLabel =
        (header->versionTrafficClassFlowLabel & 0xF00FFFFF)
        | ((trafficClass & 0xFF) << 20);
}

static void ip6SetFlowLabel(ip6PacketHeader *header,
                            uint32_t flowLabel) {
    header->versionTrafficClassFlowLabel =
        (header->versionTrafficClassFlowLabel & 0xFFF00000)
        | (flowLabel & 0xFFFFF);
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
    logInfoNoNewline("]");
}

static void ip6DebugPrint(const ip6PacketHeader *header) {
#ifndef LONG_DEBUG
    ip6DebugPrintAddress6("from ", header->source);
    ip6DebugPrintAddress6(" to ", header->destination);
    logInfo("");
#else
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
    logInfo("");
    ip6DebugPrintAddress6("  destination: ", header->destination);
    logInfo("");
#undef FORMAT
#endif /* LONG_DEBUG */
}
#else
#   define ip6DebugPrintAddress6 (void)
#   define ip6DebugPrint (void)
#endif /* _DEBUG */

static void ip6ToHostByteOrder(ip6PacketHeader *header) {
    size_t i;

    header->versionTrafficClassFlowLabel =
            ntohl(header->versionTrafficClassFlowLabel);
    header->dataLength = ntohs(header->dataLength);
    for (i = 0; i < ARRAY_SIZE(header->source); ++i) {
        header->source[i] = ntohs(header->source[i]);
    }
    for (i = 0; i < ARRAY_SIZE(header->destination); ++i) {
        header->destination[i] = ntohs(header->destination[i]);
    }

    /*ip6DebugPrint(header);*/
}

static void ip6ToNetworkByteOrder(ip6PacketHeader *header) {
    ip6ToHostByteOrder(header);
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
static void tcpDebugPrint(const tcpPacketHeader *header) {
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

static void tcpToNetworkByteOrder(tcpPacketHeader *header) {
    tcpToHostByteOrder(header);
}


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
    eth_socket ethSocket;
    tcpSocketState state;
    ip6Address localAddress;
    ip6Address remoteAddress;
    uint16_t remotePort;
    uint16_t localPort;
    uint32_t sequenceNumber;
    uint32_t currPacketDataAlreadyRead;
    uint32_t lastReceivedSeqNumber;
    uint32_t lastReceivedAckNumber;
    LIST(void*) receivedPackets;
    LIST(void*) unacknowledgedPackets; /* sent but not ACKed */
};

LIST(tcpIp6Socket) allTcpSockets = NULL;

static int ip6RecvNextPacket(tcpIp6Socket *sock, void **outPacket) {
    tcpPacketHeader *tcpHeader;
    ip6PacketHeader *header;
    *outPacket = malloc(ETH_MAX_PAYLOAD_LEN);
    header = (ip6PacketHeader*)*outPacket;

    while (true) {
        uint16_t ethertype;
        size_t bytesRead;

        /* odbierz kolejny pakiet */
        if (eth_recv(&sock->ethSocket, &ethertype, (uint8_t*)*outPacket, &bytesRead)) {
            logInfo("eth_recv failed");
            continue;
        }

        ip6ToHostByteOrder(header);

        if (ethertype == ETHERTYPE_IPv6
                && header->nextHeaderType == HEADER_TYPE_TCP) {
            tcpHeader = (tcpPacketHeader*)((char*)*outPacket + sizeof(*header));
            tcpToHostByteOrder(tcpHeader);
            /*tcpDebugPrint(tcpHeader);*/

            return 0;
        } else {
#ifdef LONG_DEBUG
            logInfo("skipping non-TCP packet (ethertype = %u, type = %u)",
                    (unsigned)ethertype, (unsigned)header->nextHeaderType);
#endif /* LONG_DEBUG */
        }
    }

    logInfo("wtf?");
    return -1;
}


static void tcpAddReceivedPacketToList(LIST(void*) *packets,
                                       void *packet) {
    void ***curr;
    tcpPacketHeader *newTcpHeader = packetGetTcpHeader(packet);

    logInfo("tcpAddReceivedPacketToList");

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

static void acknowledgePackets(tcpIp6Socket *socket,
                              uint32_t ackNumber) {
    logInfo("acknowledged: %u", ackNumber);

    LIST_CLEAR(&socket->unacknowledgedPackets) {
        if (packetGetTcpHeader(*socket->unacknowledgedPackets)
                ->base.sequenceNumber > ackNumber) {
            break;
        }
    }
}

static int tcpIp6ProcessPacket(tcpIp6Socket *socket,
                               uint16_t acceptPort) {
    void *packet;
    ip6PacketHeader *ip6Header;
    tcpPacketHeader *tcpHeader;
    tcpIp6Socket *sockIter = NULL;

    assert(socket);
    logInfo("tcpIp6ProcessPacket %p %u", socket, (unsigned)acceptPort);

    if (ip6RecvNextPacket(socket, &packet)) {
        return -1;
    }

    ip6Header = packetGetIp6Header(packet);
    tcpHeader = packetGetTcpHeader(packet);

    logInfo("tcp packet: dst port = %u",
            (unsigned)tcpHeader->base.destinationPort);

    LIST_FOREACH(sockIter, allTcpSockets) {
        if (ip6AddressEqual(sockIter->remoteAddress, ip6Header->source)
                && sockIter->remotePort == tcpHeader->base.sourcePort) {
            tcpAddReceivedPacketToList(&sockIter->receivedPackets, packet);

            if (tcpGetFlag(tcpHeader, TCP_FLAG_ACK)) {
                acknowledgePackets(socket, tcpHeader->base.ackNumber);
            }
            return 0;
        }
    }

    logInfo("no matching socket so far");

    if (acceptPort == tcpHeader->base.destinationPort
            && tcpGetFlag(tcpHeader, TCP_FLAG_SYN)) {
        static const ip6Address loAddr = { 0, 0, 0, 0, 0, 0, 0, 1 };

        socket->remotePort = tcpHeader->base.sourcePort;
        /* TODO: correctly fill local address */
        memcpy(socket->localAddress, loAddr, sizeof(ip6Address));
        memcpy(socket->remoteAddress, ip6Header->source,
               sizeof(ip6Address));
        socket->localPort = tcpHeader->base.destinationPort;
        socket->state = SOCK_STATE_SYN_RECEIVED;
        socket->lastReceivedAckNumber = tcpHeader->base.ackNumber;
        socket->sequenceNumber = tcpHeader->base.sequenceNumber;
        socket->lastReceivedSeqNumber = socket->sequenceNumber;

        tcpAddReceivedPacketToList(&socket->receivedPackets, packet);
    } else {
        logInfo("skipping packet");
        free(packet);
    }

    return 0;
}

int scheduleSendPacket(tcpIp6Socket *sock,
                       void *packet) {
    void **elem = LIST_APPEND_NEW(&sock->unacknowledgedPackets, void*);
    if (!elem) {
        return -1;
    }

    *elem = packet;
    return 0;
}

int resendPackets(tcpIp6Socket *sock) {
    void **packet = NULL;
    mac_address destinationMac;

    if (arpQuery(sock->remoteAddress, &destinationMac)) {
        logInfo("arpQuery() failed");
        return -1;
    }

    LIST_FOREACH(packet, sock->unacknowledgedPackets) {
        if (eth_send(&sock->ethSocket, &destinationMac, ETHERTYPE_IPv6,
                     (uint8_t*)*packet, ETH_MAX_PAYLOAD_LEN) < 0) {
            logInfo("eth_send failed");
            return -1;
        }
    }

    return 0;
}

int tcpIp6Send(tcpIp6Socket *sock,
               uint32_t flags,
               void *data,
               size_t data_size) {
    static const size_t MAX_REAL_DATA_PER_FRAME =
            ETH_MAX_PAYLOAD_LEN - sizeof(ip6PacketHeader)
                                - sizeof(tcpPacketHeaderBase);
    size_t dataTransmitted = 0;
    mac_address remoteMac;

    if (arpQuery(sock->remoteAddress, &remoteMac)) {
        logInfo("arpQuery failed");
        return -1;
    }

    do {
        void *packet = calloc(1, ETH_MAX_PAYLOAD_LEN);
        ip6PacketHeader *ip6Header = packetGetIp6Header(packet);
        tcpPacketHeader *tcpHeader = packetGetTcpHeader(packet);
        void *dataPointer = (char*)tcpHeader + sizeof(tcpPacketHeaderBase);
        size_t dataChunkLength = MIN(data_size, MAX_REAL_DATA_PER_FRAME);

        memcpy(&ip6Header->source, &sock->localAddress,
               sizeof(ip6Address));
        memcpy(&ip6Header->destination, &sock->remoteAddress,
               sizeof(ip6Address));
        ip6Header->hopLimit = 255;
        ip6Header->dataLength = sizeof(tcpPacketHeaderBase) + dataChunkLength;
        ip6Header->nextHeaderType = HEADER_TYPE_TCP;
        ip6SetVersion(ip6Header, 6);
        ip6SetTrafficClass(ip6Header, 0);   /* TODO */
        ip6SetFlowLabel(ip6Header, 0);      /* TODO */

        tcpHeader->base.sourcePort = sock->localPort;
        tcpHeader->base.destinationPort = sock->remotePort;
        tcpHeader->base.urgentPointer = 0;  /* TODO */
        tcpHeader->base.windowWidth = 0;    /* TODO */
        tcpHeader->base.checksum = 0;       /* TODO */
        tcpHeader->base.ackNumber = 0;      /* TODO */
        tcpHeader->base.sequenceNumber = sock->sequenceNumber++;
        tcpHeader->base.ackNumber = sock->lastReceivedSeqNumber;
        tcpSetDataOffset(tcpHeader, sizeof(tcpPacketHeaderBase)
                                    + dataTransmitted);
        tcpSetFlags(tcpHeader, flags);

        logInfo("-----\nSENDING/BEFORE:\n-----");
        ip6DebugPrint(ip6Header);
        tcpDebugPrint(tcpHeader);
        logInfo("-----\n/ SENDING/BEFORE:\n-----");

        ip6ToNetworkByteOrder(ip6Header);
        tcpToNetworkByteOrder(tcpHeader);

        memcpy(dataPointer, data, dataChunkLength);

        if (scheduleSendPacket(sock, packet)) {
            logInfo("scheduleSendPacket failed");
            return -1;
        }

        data = (char*)data + dataChunkLength;
        dataTransmitted += dataChunkLength;
        data_size -= dataChunkLength;
    } while (data_size > 0);

    if (resendPackets(sock)) {
        logInfo("resendPackets failed");
        return -1;
    }

    return 0;
}

tcpIp6Socket *tcpIp6Accept(uint16_t port) {
    tcpIp6Socket *sock = LIST_NEW_ELEMENT(tcpIp6Socket);
    logInfo("sock = %p", sock);
    eth_socket_init(&sock->ethSocket);
    sock->state = SOCK_STATE_LISTEN;

    logInfo("tcpIp6Accept %u", (unsigned)port);
    do {
        if (tcpIp6ProcessPacket(sock, port)) {
            return NULL;
        }
    } while (sock->state == SOCK_STATE_LISTEN);

    if (tcpIp6Send(sock, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0)) {
        logInfo("tcpIp6Send failed");
        return NULL;
    }

    LIST_APPEND(&allTcpSockets, sock);
    return sock;
}

void tcpIp6Close(tcpIp6Socket *sock) {
    tcpIp6Socket **curr;

    LIST_FOREACH_PTR(curr, &allTcpSockets) {
        if (*curr == sock) {
            LIST_CLEAR(&sock->receivedPackets) {
                free(*sock->receivedPackets);
            }
            LIST_ERASE(curr);
            return;
        }
    }
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

        while (!sock->receivedPackets
                /* TODO: ughhh, ugly */
                || packetGetTcpHeader(*sock->receivedPackets)
                    ->base.sequenceNumber !=
                    sock->lastReceivedSeqNumber + 1) {
            logInfo("tcpIp6Recv waiting for packets");
            if (tcpIp6ProcessPacket(sock, 0)) {
                logInfo("tcpIp6ProcessPacket() failed");
                return -1;
            }
        }

        ip6Header = packetGetIp6Header(*sock->receivedPackets);
        tcpHeader = packetGetTcpHeader(*sock->receivedPackets);

        dataOffset = tcpGetDataOffset(tcpHeader)
                     + sock->currPacketDataAlreadyRead;
        bytesRemaining = ip6Header->dataLength - dataOffset;
        bytesToCopy = MIN(bufferSize, bytesRemaining);

        memcpy(buffer, ((char*)tcpHeader) + dataOffset, bytesToCopy);

        sock->currPacketDataAlreadyRead += bytesToCopy;
        buffer = (char*)buffer + bytesToCopy;
        bufferSize -= bytesToCopy;

        logInfo("DEBUG______");
        /*ip6DebugPrint(ip6Header);*/

        logInfo("%zu bytes read, %zu remaining\n"
                "dataLength %zu, alreadyRead %zu",
                bytesToCopy, bufferSize,
                ip6Header->dataLength,
                sock->currPacketDataAlreadyRead);

        if (bytesRemaining == bytesToCopy) {
            free(*sock->receivedPackets);
            LIST_ERASE(&sock->receivedPackets);
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

        while (!sock->receivedPackets) {
            logInfo("tcpIp6RecvLine waiting for packets");
            if (tcpIp6ProcessPacket(sock, 0)) {
                logInfo("tcpIp6ProcessPacket() failed");
                return -1;
            }
        }

        ip6Header = packetGetIp6Header(*sock->receivedPackets);
        tcpHeader = packetGetTcpHeader(*sock->receivedPackets);

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
            free(*sock->receivedPackets);
            LIST_ERASE(&sock->receivedPackets);
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


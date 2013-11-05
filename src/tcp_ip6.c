#include "tcp_ip6.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utils.h"
#include "eth.h"

/* ----------- *
 * IPv6 header *
 * ----------- */

#define HEADER_TYPE_TCP 6

#pragma pack(1)
typedef uint16_t ip6Address[8];

typedef struct ip6PacketHeader {
    uint32_t versionTrafficClassFlowLabel;
    uint16_t dataLength;
    uint8_t nextHeaderType;
    uint8_t hopLimit;
    ip6Address source;
    ip6Address destination;
} ip6PacketHeader;
#pragma pack()

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

typedef struct tcpServerSocket {
    tcpSocketState state;
    uint32_t sequenceNumber;
} tcpServerSocket;

uint32_t tcpGetDataOffset(const tcpPacketHeader *header) {
    return (uint32_t)(((header->base.flags) & 0xf000) >> 12) * sizeof(uint32_t);
}

bool tcpGetFlag(const tcpPacketHeader *header, tcpFlags flag) {
    return !!(header->base.flags & flag);
}

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

static void *currentPacket = NULL;
static size_t currentPacketBytesRead = 0;

int ip6RecvNextPacket(void) {
    ip6PacketHeader header;
    tcpPacketHeader *tcpHeader;

    while (true) {
        /* odbierz kolejny pakiet */
        ethRecv(&header, sizeof(header));
        ip6ToHostByteOrder(&header);

        if (header.nextHeaderType == HEADER_TYPE_TCP) {
            currentPacket = malloc(sizeof(header) + header.dataLength);
            currentPacketBytesRead = 0;
            memcpy(currentPacket, &header, sizeof(header));
            ethRecv((char*)currentPacket + sizeof(header), header.dataLength);

            tcpHeader = (tcpPacketHeader*)((char*)currentPacket
                                                  + sizeof(header));
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

int tcpIp6Recv(char *buffer, size_t bufferSize) {
    while (bufferSize > 0) {
        ip6PacketHeader *ip6Header;
        tcpPacketHeader *tcpHeader;
        size_t dataOffset;
        size_t bytesRemaining;
        size_t bytesToCopy;

        if (!currentPacket) {
            if (ip6RecvNextPacket()) {
                logInfo("ip6RecvNextPacket() failed");
                return -1;
            }
        }

        ip6Header = (ip6PacketHeader*)currentPacket;
        tcpHeader = (tcpPacketHeader*)((char*)currentPacket
                                       + sizeof(ip6PacketHeader));

        dataOffset = tcpGetDataOffset(tcpHeader) + currentPacketBytesRead;
        bytesRemaining = ip6Header->dataLength - dataOffset;
        bytesToCopy = MIN(bufferSize, bytesRemaining);

        memcpy(buffer, ((char*)tcpHeader) + dataOffset, bytesToCopy);

        currentPacketBytesRead += bytesToCopy;
        buffer += bytesToCopy;
        bufferSize -= bytesToCopy;

        if (bytesRemaining == bytesToCopy) {
            free(currentPacket);
            currentPacket = NULL;
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

int tcpIp6RecvLine(char **outLine, size_t *outSize) {
    *outLine = NULL;
    *outSize = 0;

    while (true) {
        ip6PacketHeader *ip6Header;
        tcpPacketHeader *tcpHeader;
        size_t currentChunkLength;
        char *lineStart;
        char *lineEnd;
        bool isEndOfPacket = false;

        if (!currentPacket) {
            if (ip6RecvNextPacket()) {
                logInfo("ip6RecvNextPacket() failed");
                return -1;
            }
        }

        ip6Header = (ip6PacketHeader*)currentPacket;
        tcpHeader = (tcpPacketHeader*)((char*)currentPacket
                                       + sizeof(ip6PacketHeader));
        lineStart = ((char*)tcpHeader) + tcpGetDataOffset(tcpHeader)
                    + currentPacketBytesRead;

        for (lineEnd = lineStart;
             !isEndOfPacket && *lineEnd != '\n';
             ++lineEnd) {
            if (lineEnd >= ((char*)tcpHeader) + ip6Header->dataLength) {
                isEndOfPacket = true;
            }
        }

        currentChunkLength = (lineEnd - lineStart);
        currentPacketBytesRead += currentChunkLength;
        *outSize += currentChunkLength;

        if (isEndOfPacket) {
            logInfo("end of packet!");

            stringAppendPart(outLine, lineStart, lineEnd);
            free(currentPacket);
            currentPacket = NULL;
        } else {
            assert(*lineEnd == '\n');
            logInfo("end of line!");

            stringAppendPart(outLine, lineStart, lineEnd + 1);
            currentPacketBytesRead += 1;
            *outSize += 1; /* newline */
            break;
        }
    }

    return 0;
}

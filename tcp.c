#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define TEST_HTTP_DATA \
    "GET /index.html HTTP/1.1\r\n" \
    "Host: www.example.com\r\n"

#define TEST_TCP_PACKET \
    "\xe3\x4c\x00\x50\xcd\x0b\xcf\x24\xba\x8f\xba\xff\x80\x10\x00\x32" \
    "\xc0\xab\x00\x00\x01\x01\x08\x0a\x0f\xdf\x4d\x5b\x00\x11\x2d\x3c" \
    TEST_HTTP_DATA

#define TEST_IPv6_PACKET \
    "\x60\x00\x00\x00\x00\x51\x11\x01\xfe\x80\x00\x00\x00\x00\x00\x00" \
    "\x39\x89\x48\x68\xa2\xf7\xc4\x78\xff\x02\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x0c" TEST_TCP_PACKET

#define TEST_FRAME \
    "\x33\x33\x00\x00\x00\x0c\x4c\x80\x93\x00\xe0\x97\x86\xdd" TEST_IPv6_PACKET;

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int tcpRecv(const void *buffer, size_t size);
int tcpSend(const void *buffer, size_t size);
int ipRecv(const void *buffer, size_t size);
int ipSend(const void *buffer, size_t size);

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef uint8_t bool;
static const uint8_t true = 1;
static const uint8_t false = 0;

uint16_t ntohs(uint16_t bytes) {
    return __builtin_bswap16(bytes);
}

uint32_t ntohl(uint32_t bytes) {
    return __builtin_bswap32(bytes);
}

void logInfoNoNewline(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
}

void logInfo(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);

    printf("\n");
}

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

ip6PacketBuffer nextPacket = { 0, 0, NULL };

uint32_t ipGetVersion(const ip6PacketHeader *header) {
    return (header->versionTrafficClassFlowLabel >> 28) & 0xF;
}

uint32_t ipGetTrafficClass(const ip6PacketHeader *header) {
    return (header->versionTrafficClassFlowLabel >> 20) & 0xFF;
}

uint32_t ipGetFlowLabel(const ip6PacketHeader *header) {
    return header->versionTrafficClassFlowLabel & 0xFFFFF;
}

void ipDebugPrintAddress6(const char *label, const ip6Address addr) {
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

void ipDebugPrint(const ip6PacketHeader *header) {
#define FORMAT "%-6u (%x)"
    logInfo(
        "[IPv6 HEADER]\n"
        "      version: " FORMAT "\n"
        "traffic class: " FORMAT "\n"
        "   flow label: " FORMAT "\n"
        "  data length: " FORMAT "\n"
        "  next header: " FORMAT "\n"
        "    hop limit: " FORMAT,
        ipGetVersion(header),       ipGetVersion(header),
        ipGetTrafficClass(header),  ipGetTrafficClass(header),
        ipGetFlowLabel(header),     ipGetFlowLabel(header),
        (uint32_t)header->dataLength, (uint32_t)header->dataLength,
        (uint32_t)header->nextHeader, (uint32_t)header->nextHeader,
        (uint32_t)header->hopLimit,   (uint32_t)header->hopLimit);
    ipDebugPrintAddress6("       source: ", header->source);
    ipDebugPrintAddress6("  destination: ", header->destination);
#undef FORMAT
}

void ipToHostByteOrder(ip6PacketBuffer *packet) {
    ip6PacketHeader *header = (ip6PacketHeader*)packet->data;
    size_t i;

    header->dataLength = ntohs(header->dataLength);
    for (i = 0; i < ARRAY_SIZE(header->source); ++i)
        header->source[i] = ntohs(header->source[i]);
    for (i = 0; i < ARRAY_SIZE(header->destination); ++i)
        header->destination[i] = ntohs(header->destination[i]);

    ipDebugPrint(header);
}

void ipPacketInit(ip6PacketBuffer *packet, const ip6PacketHeader *header) {
    nextPacket.size = sizeof(ip6PacketHeader) + ntohs(header->dataLength);
    nextPacket.bytesWritten = 0;

    logInfo("allocating %lu (%lx) bytes", nextPacket.size, nextPacket.size);
    nextPacket.data = (uint8_t*)malloc(nextPacket.size);
}

void ipPacketComplete(ip6PacketBuffer *packet) {
    ipToHostByteOrder(packet);

    if (tcpRecv(packet->data + sizeof(ip6PacketHeader),
                packet->size - sizeof(ip6PacketHeader))) {
        logInfo("tcpRecv failed");
    }

    free(packet->data);
    packet->size = 0;
    packet->bytesWritten = 0;
    packet->data = NULL;
}

int ipRecv(const void *buffer, size_t size) {
    size_t bytesToCopy;

    while (size > 0) {
        if (nextPacket.size == 0) {
            logInfo("new IPv6 packet");

            if (size < offsetof(ip6PacketHeader, dataLength) + sizeof(uint16_t))
                return -1;

            ipPacketInit(&nextPacket, (const ip6PacketHeader*)buffer);
        }

        bytesToCopy = MIN(nextPacket.size - nextPacket.bytesWritten, size);
        memcpy(nextPacket.data + nextPacket.bytesWritten, buffer, bytesToCopy);
        nextPacket.bytesWritten += bytesToCopy;

        if (nextPacket.bytesWritten == nextPacket.size) {
            ipPacketComplete(&nextPacket);
        }

        size -= bytesToCopy;
    }

    return 0;
}

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
    TCP_FLAG_FIN = (1 << 15),
} tcpFlags;

typedef uint32_t tcpPacketHeaderOptions[10];

typedef struct tcpPacketHeader {
    tcpPacketHeaderBase base;
    tcpPacketHeaderOptions options;
} tcpPacketHeader;
#pragma pack()

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
        "              fin " FORMAT "\n"
        "    window width: " FORMAT "\n"
        "        checksum: " FORMAT "\n"
        "  urgent pointer: " FORMAT "\n",
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
        tcpGetFlag(header, TCP_FLAG_FIN),      tcpGetFlag(header, TCP_FLAG_FIN),
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
    //return tcpRecv(TEST_TCP_PACKET, sizeof(TEST_TCP_PACKET) - 1);
    return ipRecv(TEST_IPv6_PACKET, sizeof(TEST_IPv6_PACKET) - 1);
}

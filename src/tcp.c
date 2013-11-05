#include "tcp.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "test_data.h"
#include "utils.h"
#include "ip6.h"

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

typedef struct tcpBuffer {
    void *packet;
    tcpPacketHeader *header;
    void *dataPtr;
    size_t dataBytesRemaining;
} tcpBuffer;

static void tcpBufferStoreNextPacket(tcpBuffer *buffer) {
    size_t packetSize;
    size_t dataOffset;

    if (buffer->packet != NULL) {
        logInfo("WARNING: tcpBufferStoreNextPacket on non-empty buffer!");
        free(buffer->packet);
    }

    ip6Recv(&buffer->packet, &packetSize);
    buffer->header = (tcpPacketHeader*)buffer->packet;

    tcpDebugPrint(buffer->header);

    tcpToHostByteOrder(buffer->header);
    dataOffset = tcpGetDataOffset(buffer->header);
    buffer->dataBytesRemaining = packetSize - dataOffset;
    buffer->dataPtr = (char*)buffer->packet + dataOffset;

    logInfo("stored: %s", (char*)buffer->dataPtr);
}

static size_t tcpBufferRead(tcpBuffer *buffer, void *outData, size_t size) {
    size_t bytesToRead;

    /*logInfo("tcpBufferRead %lu", size);*/

    if (buffer->dataBytesRemaining == 0) {
        logInfo("WARNING: tcpBufferRead on empty buffer");
        return 0;
    }

    bytesToRead = MIN(buffer->dataBytesRemaining, size);
    memcpy(buffer->dataPtr, outData, bytesToRead);

    buffer->dataPtr = (char*)buffer->dataPtr + bytesToRead;
    buffer->dataBytesRemaining -= bytesToRead;
    if (buffer->dataBytesRemaining == 0) {
        free(buffer->packet);
        buffer->packet = NULL;
        buffer->header = NULL;
        buffer->dataPtr = NULL;
    }

    logInfo("read: %s", (char*)outData);

    return bytesToRead;
}

#define NOT_FOUND ((size_t)-1)

static size_t tcpBufferFind(tcpBuffer *buffer, char delimiter) {
    const char *pos = (const char*)buffer->dataPtr;
    const char *end = (const char*)buffer->packet
                      + tcpGetDataOffset(buffer->header);
    for (; pos < end && *pos != delimiter; ++pos);

    if (pos == end) {
        return NOT_FOUND;
    }

    return (size_t)(pos - (const char*)buffer->dataPtr);
}

static char *tcpAppendString(char **string, const char *toAppend) {
    /*logInfo("tcpAppendString <%s> <%s>", *string, toAppend);*/

    if (*string == NULL) {
        return *string = strdup(toAppend);
    } else {
        size_t oldLength = strlen(*string);
        size_t newLength = oldLength + strlen(toAppend);
        char *newString = malloc(newLength + 1);
        strncpy(newString, *string, oldLength);
        strncpy(newString + oldLength, toAppend, newLength - oldLength + 1);
        newString[newLength] = '\0';
        free(*string);
        *string = newString;
        return newString;
    }
}

static size_t tcpBufferGetline(tcpBuffer *buffer,
                               char **inoutData,
                               size_t *inoutSize,
                               char delimiter) {
    char *result = NULL;

    if (*inoutData == NULL) {
        size_t length = 0;
        size_t eolAt;

        while (true) {
            size_t bytesToRead;

            eolAt = tcpBufferFind(buffer, delimiter);
            bytesToRead = (eolAt == NOT_FOUND) ? buffer->dataBytesRemaining
                                               : eolAt;

            result = (char*)malloc(bytesToRead + 1);
            tcpBufferRead(buffer, result, bytesToRead + 1);
            result[bytesToRead] = '\0';
            length += bytesToRead;

            tcpAppendString(inoutData, result);

            if (eolAt == NOT_FOUND) {
                tcpBufferStoreNextPacket(buffer);
                break;
            }
        }

        *inoutSize = length;
        return length;
    } else {
        assert(!"not yet implemented");
    }

    return 0;
}

static tcpBuffer tcpTempBuffer = { NULL, NULL, NULL, 0 };

int tcpRecv(void *outBuffer, size_t size) {
    if (tcpTempBuffer.dataBytesRemaining) {
        size_t bytesRead = tcpBufferRead(&tcpTempBuffer, outBuffer, size);

        outBuffer = (char*)outBuffer + bytesRead;
        size -= bytesRead;
    }

    while (size > 0) {
        size_t bytesRead;

        tcpBufferStoreNextPacket(&tcpTempBuffer);
        bytesRead = tcpBufferRead(&tcpTempBuffer, outBuffer, size);
        outBuffer = (char*)outBuffer + bytesRead;
        size -= bytesRead;
    }

    return 0;
}

int tcpRecvLine(char **outString, size_t *outSize) {
    if (*outString == NULL) {
        if (tcpTempBuffer.dataBytesRemaining == 0) {
            tcpBufferStoreNextPacket(&tcpTempBuffer);
        }

        return (tcpBufferGetline(&tcpTempBuffer, outString, outSize, '\n') == 0)
                ? -1 : 0;
    } else {
        assert(!"not yet implemented");
    }

    return -1;
}

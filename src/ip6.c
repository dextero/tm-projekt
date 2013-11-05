#include "ip6.h"

#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "tcp.h"
#include "eth.h"

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

int ip6Recv(void **outData, size_t *outSize) {
    ip6PacketHeader header;

    while (true) {
        /* odbierz kolejny pakiet */
        ethRecv(&header, sizeof(header));
        ip6ToHostByteOrder(&header);

        if (header.nextHeaderType == HEADER_TYPE_TCP) {
            *outData = malloc(header.dataLength);
            *outSize = header.dataLength;
            ethRecv(*outData, header.dataLength);

            return 0;
        } else {
            ethSkip(header.dataLength);
            logInfo("skipping non-TCP packet (type = %u)",
                    (unsigned)header.nextHeaderType);
        }
    }

    return 0;
}


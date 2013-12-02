#include "ip6.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

uint32_t ip6GetVersion(const ip6PacketHeader *header) {
    return (header->versionTrafficClassFlowLabel >> 28) & 0xF;
}

uint32_t ip6GetTrafficClass(const ip6PacketHeader *header) {
    return (header->versionTrafficClassFlowLabel >> 20) & 0xFF;
}

uint32_t ip6GetFlowLabel(const ip6PacketHeader *header) {
    return header->versionTrafficClassFlowLabel & 0xFFFFF;
}

void ip6SetVersion(ip6PacketHeader *header,
                          uint32_t version) {
    header->versionTrafficClassFlowLabel =
        (header->versionTrafficClassFlowLabel & 0x0FFFFFFF)
        | ((version & 0xF) << 28);
}

void ip6SetTrafficClass(ip6PacketHeader *header,
                               uint32_t trafficClass) {
    header->versionTrafficClassFlowLabel =
        (header->versionTrafficClassFlowLabel & 0xF00FFFFF)
        | ((trafficClass & 0xFF) << 20);
}

void ip6SetFlowLabel(ip6PacketHeader *header,
                            uint32_t flowLabel) {
    header->versionTrafficClassFlowLabel =
        (header->versionTrafficClassFlowLabel & 0xFFF00000)
        | (flowLabel & 0xFFFFF);
}

#ifdef _DEBUG
void ip6DebugPrintAddress(const char *label, const ip6Address addr) {
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

void ip6DebugPrint(const ip6PacketHeader *header) {
#ifndef LONG_DEBUG
    ip6DebugPrintAddress("from ", header->source);
    ip6DebugPrintAddress(" to ", header->destination);
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
    ip6DebugPrintAddress("       source: ", header->source);
    logInfo("");
    ip6DebugPrintAddress("  destination: ", header->destination);
    logInfo("");
#undef FORMAT
#endif /* LONG_DEBUG */
}
#endif /*_DEBUG */

void ip6ToHostByteOrder(ip6PacketHeader *header) {
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

void ip6ToNetworkByteOrder(ip6PacketHeader *header) {
    ip6ToHostByteOrder(header);
}

bool ip6AddressEqual(const ip6Address first,
                     const ip6Address second) {
    return !memcmp(first, second, sizeof(ip6Address));
}


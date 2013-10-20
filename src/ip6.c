#include "ip6.h"

#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "tcp.h"

uint32_t ip6GetVersion(const ip6PacketHeader *header) {
    return (header->versionTrafficClassFlowLabel >> 28) & 0xF;
}

uint32_t ip6GetTrafficClass(const ip6PacketHeader *header) {
    return (header->versionTrafficClassFlowLabel >> 20) & 0xFF;
}

uint32_t ip6GetFlowLabel(const ip6PacketHeader *header) {
    return header->versionTrafficClassFlowLabel & 0xFFFFF;
}

void ip6DebugPrintAddress6(const char *label, const ip6Address addr) {
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

void ip6DebugPrint(const ip6PacketHeader *header) {
#define FORMAT "%-6u (%x)"
    logInfo(
        "[IPv6 HEADER]\n"
        "      version: " FORMAT "\n"
        "traffic class: " FORMAT "\n"
        "   flow label: " FORMAT "\n"
        "  data length: " FORMAT "\n"
        "  next header: " FORMAT "\n"
        "    hop limit: " FORMAT,
        ip6GetVersion(header),       ip6GetVersion(header),
        ip6GetTrafficClass(header),  ip6GetTrafficClass(header),
        ip6GetFlowLabel(header),     ip6GetFlowLabel(header),
        (uint32_t)header->dataLength, (uint32_t)header->dataLength,
        (uint32_t)header->nextHeader, (uint32_t)header->nextHeader,
        (uint32_t)header->hopLimit,   (uint32_t)header->hopLimit);
    ip6DebugPrintAddress6("       source: ", header->source);
    ip6DebugPrintAddress6("  destination: ", header->destination);
#undef FORMAT
}

void ip6ToHostByteOrder(ip6PacketBuffer *packet) {
    ip6PacketHeader *header = (ip6PacketHeader*)packet->data;
    size_t i;

    header->dataLength = ntohs(header->dataLength);
    for (i = 0; i < ARRAY_SIZE(header->source); ++i)
        header->source[i] = ntohs(header->source[i]);
    for (i = 0; i < ARRAY_SIZE(header->destination); ++i)
        header->destination[i] = ntohs(header->destination[i]);

    ip6DebugPrint(header);
}

void ip6PacketInit(ip6PacketBuffer *packet, const ip6PacketHeader *header) {
    packet->size = sizeof(ip6PacketHeader) + ntohs(header->dataLength);
    packet->bytesWritten = 0;

    logInfo("allocating %lu (%lx) bytes", packet->size, packet->size);
    packet->data = (uint8_t*)malloc(packet->size);
}

void ip6PacketComplete(ip6PacketBuffer *packet) {
    ip6ToHostByteOrder(packet);

    if (tcpRecv(packet->data + sizeof(ip6PacketHeader),
                packet->size - sizeof(ip6PacketHeader))) {
        logInfo("tcpRecv failed");
    }

    free(packet->data);
    packet->size = 0;
    packet->bytesWritten = 0;
    packet->data = NULL;
}

static ip6PacketBuffer nextPacket = { 0, 0, NULL };

int ip6Recv(const void *buffer, size_t size) {
    size_t bytesToCopy;

    while (size > 0) {
        if (nextPacket.size == 0) {
            logInfo("new IPv6 packet");

            if (size < offsetof(ip6PacketHeader, dataLength) + sizeof(uint16_t))
                return -1;

            ip6PacketInit(&nextPacket, (const ip6PacketHeader*)buffer);
        }

        bytesToCopy = MIN(nextPacket.size - nextPacket.bytesWritten, size);
        memcpy(nextPacket.data + nextPacket.bytesWritten, buffer, bytesToCopy);
        nextPacket.bytesWritten += bytesToCopy;

        if (nextPacket.bytesWritten == nextPacket.size) {
            ip6PacketComplete(&nextPacket);
        }

        size -= bytesToCopy;
    }

    return 0;
}


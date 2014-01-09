#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "generic_list.h"
#include "socket.h"
#include "tcp.h"
#include "ip6.h"
#include "packet.h"
#include "ndp.h"
#include "arp.h"
#include "eth.h"


extern LIST(tcpIp6Socket) allTcpSockets;

static int resendPackets(tcpIp6Socket *sock);

uint32_t tcpGetDataOffset(const tcpPacketHeader *header) {
    return (uint32_t)(((header->base.flags) & 0xF000) >> 12) * sizeof(uint32_t);
}

bool tcpGetFlag(const tcpPacketHeader *header, tcpFlags flag) {
    return !!(header->base.flags & flag);
}

static uint32_t getNextPacketSeqNumber(void *packet) {
    ip6PacketHeader *ip6Header = packetGetIp6Header(packet);
    tcpPacketHeader *tcpHeader = packetGetTcpHeader(packet);
    uint32_t dataSize = ip6Header->dataLength - tcpGetDataOffset(tcpHeader);

    if (tcpGetFlag(tcpHeader, TCP_FLAG_SYN) && dataSize == 0) {
        return tcpHeader->base.sequenceNumber + 1;
    } else {
        return tcpHeader->base.sequenceNumber + dataSize;
    }
}

static void printPacketInfo(const char *header,
                            void *packet,
                            bool isHostByteOrder) {
    tcpPacketHeader *tcpHeader = packetGetTcpHeader(packet);
    ip6PacketHeader *ip6Header = packetGetIp6Header(packet);

    uint16_t flags = tcpHeader->base.flags;
    uint32_t seqNumber = tcpHeader->base.sequenceNumber;
    uint32_t ackNumber = tcpHeader->base.ackNumber;
    uint16_t payloadSize = ip6Header->dataLength;
    size_t packetSize;
    size_t actualDataSize;

    if (!isHostByteOrder) {
        flags = ntohs(flags);
        seqNumber = ntohl(seqNumber);
        ackNumber = ntohl(ackNumber);
        payloadSize = ntohs(payloadSize);
    }

    packetSize = sizeof(ip6PacketHeader) + payloadSize;
    actualDataSize = payloadSize - tcpGetDataOffset(tcpHeader);

    logInfo("%s:  TCP [%c%c%c%c%c%c], seq % 10u, ack % 10u, %luB(%luB) data",
            header,
            (flags & TCP_FLAG_URG) ? 'U' : ' ',
            (flags & TCP_FLAG_ACK) ? 'A' : ' ',
            (flags & TCP_FLAG_PSH) ? 'P' : ' ',
            (flags & TCP_FLAG_RST) ? 'R' : ' ',
            (flags & TCP_FLAG_SYN) ? 'S' : ' ',
            (flags & TCP_FLAG_FIN) ? 'F' : ' ',
            seqNumber, ackNumber,
            actualDataSize, packetSize);
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

static int streamGetNextPacket(tcpStream *stream)
{
    tcpPacketHeader *tcpHeader;
    ip6PacketHeader *ip6Header;

    /*logInfo("streamGetNextPacket: %u", stream->currPacketSeqNumber);*/

    while (stream->packets) {
        uint32_t seqNum;
        uint32_t unreadDataSize;

        tcpHeader = packetGetTcpHeader(*stream->packets);
        ip6Header = packetGetIp6Header(*stream->packets);

        seqNum = tcpHeader->base.sequenceNumber;
        unreadDataSize = ip6Header->dataLength - tcpGetDataOffset(tcpHeader)
                         - stream->currPacketDataAlreadyRead;

        if ((seqNum == stream->currPacketSeqNumber && unreadDataSize > 0)
                || seqNum > stream->currPacketSeqNumber) {
            break;
        } else {
            logInfo("skip: %u (%s)", seqNum,
                    unreadDataSize == 0 ? "no more data"
                                        : "sequence number too small");

            stream->currPacketSeqNumber =
                    getNextPacketSeqNumber(*stream->packets);
            stream->currPacketDataAlreadyRead = 0;

            logInfo("currPacketSeqNumber = %u", stream->currPacketSeqNumber);

            free(*stream->packets);
            LIST_ERASE(&stream->packets);
        }
    }

    if (!stream->packets
            || tcpHeader->base.sequenceNumber > stream->currPacketSeqNumber) {
        logInfo("waiting for packet %u", stream->currPacketSeqNumber);
        return STREAM_WAITING_FOR_PACKET;
    }

#ifdef _DEBUG
    logInfo("got: %u", tcpHeader->base.sequenceNumber);
#endif /* _DEBUG */
    return 0;
}

ssize_t tcpStreamReadNextPacket(tcpStream *stream,
                                void *buffer,
                                size_t bufferSize)
{
    ip6PacketHeader *ip6Header;
    tcpPacketHeader *tcpHeader;
    size_t dataOffset;
    size_t bytesRemaining;
    size_t bytesToCopy;

    /*logInfo("tcpStreamReadNextPacket");*/

    if (streamGetNextPacket(stream)) {
        return STREAM_WAITING_FOR_PACKET;
    }

    ip6Header = packetGetIp6Header(*stream->packets);
    tcpHeader = packetGetTcpHeader(*stream->packets);

    dataOffset = tcpGetDataOffset(tcpHeader)
                 + stream->currPacketDataAlreadyRead;
    bytesRemaining = ip6Header->dataLength - dataOffset;
    bytesToCopy = MIN(bufferSize, bytesRemaining);

    memcpy(buffer, ((char*)tcpHeader) + dataOffset, bytesToCopy);

    stream->currPacketDataAlreadyRead += bytesToCopy;
    buffer = (char*)buffer + bytesToCopy;
    bufferSize -= bytesToCopy;

    /*logInfo("%zu bytes read, %zu remaining\n"*/
            /*"dataLength %zu, alreadyRead %zu",*/
            /*bytesToCopy, bufferSize,*/
            /*ip6Header->dataLength - sizeof(tcpPacketHeaderBase),*/
            /*stream->currPacketDataAlreadyRead);*/

    return bytesToCopy;
}

int tcpStreamReadNextLine(tcpStream *stream,
                          char **outLine,
                          size_t *outSize) {
    ip6PacketHeader *ip6Header;
    tcpPacketHeader *tcpHeader;
    size_t currentChunkLength;
    char *lineStart;
    char *lineEnd;
    bool isEndOfPacket = false;

    /*logInfo("tcpStreamReadNextLine");*/

    if (streamGetNextPacket(stream)) {
        return STREAM_WAITING_FOR_PACKET;
    }

    ip6Header = packetGetIp6Header(*stream->packets);
    tcpHeader = packetGetTcpHeader(*stream->packets);

    lineStart = ((char*)tcpHeader) + tcpGetDataOffset(tcpHeader)
                 + stream->currPacketDataAlreadyRead;

    for (lineEnd = lineStart;
         !isEndOfPacket && *lineEnd != '\n';
         ++lineEnd) {
        if (lineEnd >= ((char*)tcpHeader) + ip6Header->dataLength) {
            isEndOfPacket = true;
        }
    }

    currentChunkLength = (lineEnd - lineStart);
    stream->currPacketDataAlreadyRead += currentChunkLength;
    *outSize += currentChunkLength;

    /*logInfo("currentChunkLength %zu, dataLength %zu, alreadyRead %zu",*/
            /*currentChunkLength,*/
            /*ip6Header->dataLength - sizeof(tcpPacketHeaderBase),*/
            /*stream->currPacketDataAlreadyRead);*/

    /*printPacketInfo("READING: ", *stream->packets, true);*/
    /*logInfo("end of packet? %s", isEndOfPacket ? "yes" : "no");*/

    if (isEndOfPacket) {
        char buffer[65536] = { 0 };
        snprintf(buffer, sizeof(buffer), "%s", lineStart);

        /*logInfo("LINESTART -> LINEEND");*/
        /*logInfo("%s", buffer);*/
        /*logInfo("/LINESTART -> LINEEND");*/

        stringAppendPart(outLine, lineStart, lineEnd);

        /*logInfo("END OF PACKET");*/
        /*logInfo("%s", *outLine);*/
        /*logInfo("/END OF PACKET");*/

        return STREAM_WAITING_FOR_PACKET;
    } else {
        assert(*lineEnd == '\n');

        stringAppendPart(outLine, lineStart, lineEnd + 1);
        stream->currPacketDataAlreadyRead += 1;

        /*logInfo("END OF LINE");*/
        /*logInfo("%s", *outLine);*/
        /*logInfo("/END OF LINE");*/
    }

    return lineEnd - lineStart;
}


static int recvNextPacket(tcpIp6Socket *sock, void **outPacket) {
    tcpPacketHeader *tcpHeader;
    ip6PacketHeader *header;
    *outPacket = malloc(ETH_MAX_PAYLOAD_LEN);
    header = (ip6PacketHeader*)*outPacket;

    while (true) {
        uint16_t ethertype;
        size_t bytesRead;
        mac_address source;

        /* odbierz kolejny pakiet */
        if (eth_recv(&sock->ethSocket, &ethertype, &source,
                     (uint8_t*)*outPacket, &bytesRead)) {
            logInfo("eth_recv failed");
            continue;
        }

        ip6ToHostByteOrder(header);

        if (ethertype == ETHERTYPE_IPv6) {
            switch (header->nextHeaderType) {
            case HEADER_TYPE_TCP:
                tcpHeader = (tcpPacketHeader*)((char*)*outPacket + sizeof(*header));
                tcpToHostByteOrder(tcpHeader);

                printPacketInfo("RECV", *outPacket, true);
                return 0;
            case HEADER_TYPE_ICMPv6:
                icmp6ToHostByteOrder(packetGetIcmp6Data(*outPacket));
                printIcmp6PacketInfo("RECV", *outPacket, false);

                if (icmp6Interpret(*outPacket, &source, sock)) {
                    logInfo("icmp6Interpret failed");
                }
                break;
            default:
    #ifdef LONG_DEBUG
                /*logInfo("skipping non-TCP packet (ethertype = %u, type = %u)",*/
                        /*(unsigned)ethertype, (unsigned)header->nextHeaderType);*/
    #endif /* LONG_DEBUG */
                break;
            }
        }
    }

    logInfo("wtf?");
    return -1;
}

static void addReceivedPacket(tcpIp6Socket *sock,
                              void *packet) {
    void ***curr;
    tcpPacketHeader *newTcpHeader = packetGetTcpHeader(packet);
    LIST(void*) *packets = &sock->stream.packets;

    uint32_t seqNumberToAcknowledge = sock->stream.nextContiniousSeqNumber;
    bool packetInserted = false;

    LIST_FOREACH_PTR(curr, packets) {
        tcpPacketHeader *tcpHeader = packetGetTcpHeader(**curr);
        uint32_t packetSeqNum = tcpHeader->base.sequenceNumber;
        uint32_t nextSeqNum = getNextPacketSeqNumber(**curr);

        /*logInfo("last %u, curr %u", seqNumberToAcknowledge, packetSeqNum);*/
        /*logInfo("next = %u", nextSeqNum);*/
        if (packetSeqNum == seqNumberToAcknowledge) {
            seqNumberToAcknowledge = nextSeqNum;
        } else if (packetInserted) {
            break;
        }

        if (packetSeqNum < newTcpHeader->base.sequenceNumber) {
            *LIST_INSERT_NEW(curr, void*) = packet;
            packetInserted = true;
        }
    }

    if (!packetInserted) {
        tcpPacketHeader *tcpHeader = packetGetTcpHeader(packet);
        uint32_t packetSeqNum = tcpHeader->base.sequenceNumber;
        uint32_t nextSeqNum = getNextPacketSeqNumber(packet);

        /*logInfo("2: last %u, curr %u", seqNumberToAcknowledge, packetSeqNum);*/
        /*logInfo("next = %u", nextSeqNum);*/
        if (packetSeqNum == seqNumberToAcknowledge) {
            seqNumberToAcknowledge = nextSeqNum;
        }

        *LIST_APPEND_NEW(packets, void*) = packet;
    }

    /*logInfo("packet inserted; seq was %u, is %u",*/
            /*sock->stream.nextContiniousSeqNumber, seqNumberToAcknowledge);*/
    if (seqNumberToAcknowledge > sock->stream.nextContiniousSeqNumber) {
        sock->stream.nextContiniousSeqNumber = seqNumberToAcknowledge;

        if (tcpSend(sock, TCP_FLAG_ACK, NULL, 0)) {
            logInfo("tcpSend failed");
        }
    }
}

static void acknowledgePackets(tcpIp6Socket *sock,
                               uint32_t ackNumber) {
    logInfo("*** resending");
    if (resendPackets(sock)) {
        logInfo("resendPackets failed");
    }

    LIST_CLEAR(&sock->unacknowledgedPackets) {
        if (packetGetTcpHeader(*sock->unacknowledgedPackets)
                ->base.sequenceNumber >= ackNumber) {
            break;
        }
    }
}

static void fillClientSocket(tcpIp6Socket *sock,
                             ip6PacketHeader *ip6Header,
                             tcpPacketHeader *tcpHeader) {
    sock->remotePort = tcpHeader->base.sourcePort;
    /* TODO: correctly fill local address */
    memcpy(sock->remoteAddress, ip6Header->source,
           sizeof(ip6Address));
    sock->localPort = tcpHeader->base.destinationPort;
    sock->state = SOCK_STATE_SYN_RECEIVED;
    sock->lastReceivedAckNumber = tcpHeader->base.ackNumber;
    sock->sequenceNumber = 0;
    sock->lastAcknowledgedSeqNumber = 0;

    sock->stream.currPacketDataAlreadyRead = 0;
    sock->stream.nextContiniousSeqNumber = tcpHeader->base.sequenceNumber + 1;
    sock->stream.currPacketSeqNumber = tcpHeader->base.sequenceNumber + 1;
    LIST_CLEAR(&sock->stream.packets) {
        free(*sock->stream.packets);
    }
}

static int processPacket(tcpIp6Socket *sock,
                         void *packet) {
    tcpPacketHeader *tcpHeader = packetGetTcpHeader(packet);
    bool savePacket = true;

    if (tcpGetFlag(tcpHeader, TCP_FLAG_RST)) {
        socketReset(sock);
        return 0;
    }

    switch (sock->state) {
    case SOCK_STATE_SYN_RECEIVED:
        if (tcpGetFlag(tcpHeader, TCP_FLAG_ACK)) {
            sock->state = SOCK_STATE_ESTABLISHED;
        }
        /* no break; */
    case SOCK_STATE_ESTABLISHED:
        if (tcpGetFlag(tcpHeader, TCP_FLAG_FIN)) {
            sock->state = SOCK_STATE_LAST_ACK;

            if (tcpSend(sock, TCP_FLAG_ACK | TCP_FLAG_FIN, NULL, 0)) {
                logInfo("tcpSend failed");
                return -1;
            }
        }
        if (tcpGetFlag(tcpHeader, TCP_FLAG_ACK)) {
            acknowledgePackets(sock, tcpHeader->base.ackNumber);
        }
        break;
    case SOCK_STATE_LAST_ACK:
        logInfo("connection terminated by remote host");
        if (tcpGetFlag(tcpHeader, TCP_FLAG_ACK)) {
            sock->state = SOCK_STATE_CLOSED;
        }
        break;
    case SOCK_STATE_FIN_WAIT_1:
        if (tcpGetFlag(tcpHeader, TCP_FLAG_FIN)) {
            sock->state = SOCK_STATE_TIME_WAIT;
            ++sock->sequenceNumber;
            ++sock->stream.nextContiniousSeqNumber;
            savePacket = false;

            if (tcpSend(sock, TCP_FLAG_ACK, NULL, 0)) {
                logInfo("tcpSend failed");
                return -1;
            }
        }
        break;
    default:
        logInfo("packet received while in state %d", sock->state);
        break;
    }

    printSocket(sock);

    if (savePacket) {
        addReceivedPacket(sock, packet);
    } else {
        logInfo("not saving");
    }
    return 0;
}

int tcpProcessNextPacket(tcpIp6Socket *sock) {
    void *packet;
    ip6PacketHeader *ip6Header;
    tcpPacketHeader *tcpHeader;
    tcpIp6Socket *sockIter = NULL;

    assert(sock);

    if (recvNextPacket(sock, &packet)) {
        return -1;
    }

    ip6Header = packetGetIp6Header(packet);
    tcpHeader = packetGetTcpHeader(packet);

    LIST_FOREACH(sockIter, allTcpSockets) {
        if (sockIter->localPort != tcpHeader->base.destinationPort) {
            continue;
        }

        if (ip6AddressEqual(sockIter->remoteAddress, ip6Header->source)
                && sockIter->remotePort == tcpHeader->base.sourcePort) {
            return processPacket(sockIter, packet);
        }

        if (sock->state == SOCK_STATE_LISTEN
                && tcpGetFlag(tcpHeader, TCP_FLAG_SYN)) {
            fillClientSocket(sock, ip6Header, tcpHeader);
            addReceivedPacket(sock, packet);
            return 0;
        }
    }

    logInfo("skipping packet (src port = %u, dst port = %u)",
            tcpHeader->base.sourcePort, tcpHeader->base.destinationPort);
    free(packet);
    return 0;
}

static int scheduleSendPacket(tcpIp6Socket *sock,
                              void *packet) {
    void **elem = LIST_APPEND_NEW(&sock->unacknowledgedPackets, void*);
    if (!elem) {
        logInfo("LIST_APPEND_NEW failed");
        return -1;
    }

    *elem = packet;
    return 0;
}

static int resendPackets(tcpIp6Socket *sock) {
    void **packet = NULL;
    mac_address destinationMac;

    if (arpQuery(sock, sock->remoteAddress, &destinationMac)) {
        logInfo("arpQuery failed");
        return -1;
    }

    LIST_FOREACH(packet, sock->unacknowledgedPackets) {
        size_t bytesToSend = sizeof(ip6PacketHeader)
                + ntohs(packetGetIp6Header(*packet)->dataLength);

        printPacketInfo("SEND", *packet, false);

        if (eth_send(&sock->ethSocket, &destinationMac, ETHERTYPE_IPv6,
                     (uint8_t*)*packet, bytesToSend) < 0) {
            logInfo("eth_send failed");
            return -1;
        }
    }

    return 0;
}

int tcpSend(tcpIp6Socket *sock,
            uint32_t flags,
            void *data,
            size_t data_size) {
    const size_t MAX_REAL_DATA_PER_FRAME =
            ETH_MAX_PAYLOAD_LEN - 20 /* ?! */
                                - sizeof(ip6PacketHeader)
                                - sizeof(tcpPacketHeaderBase);
    size_t dataTransmitted = 0;
    mac_address remoteMac;

    if (arpQuery(sock, sock->remoteAddress, &remoteMac)) {
        logInfo("arpQuery failed");
        return -1;
    }

    do {
        void *packet = calloc(1, ETH_MAX_PAYLOAD_LEN);
        void *dataPointer = (char*)packetGetTcpHeader(packet)
                            + sizeof(tcpPacketHeaderBase);
        size_t dataChunkLength = MIN(data_size, MAX_REAL_DATA_PER_FRAME);

        logInfo("tcpSend: sending %zu bytes (%zu already sent)",
                dataChunkLength, dataTransmitted);

        memcpy(dataPointer, data, dataChunkLength);
        packetFillIp6Header(packet, HEADER_TYPE_TCP,
                            sock->localAddress, sock->remoteAddress,
                            sizeof(tcpPacketHeaderBase) + dataChunkLength);
        packetFillTcpHeader(packet, sock, flags);

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


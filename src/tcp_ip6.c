#include "tcp_ip6.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utils.h"
#include "eth_new.h"
#include "arp.h"
#include "generic_list.h"
#include "ip6.h"
#include "tcp.h"

typedef struct tcpStream {
    LIST(void*) packets;
    uint32_t currPacketSeqNumber;
    uint32_t currPacketDataAlreadyRead;
    uint32_t nextContiniousSeqNumber;
} tcpStream;

#define STREAM_ERROR (-1)
#define STREAM_WAITING_FOR_PACKET (-2)

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

struct tcpIp6Socket {
    eth_socket ethSocket;
    tcpSocketState state;
    ip6Address localAddress;
    ip6Address remoteAddress;
    uint16_t remotePort;
    uint16_t localPort;
    uint32_t sequenceNumber;
    uint32_t currPacketDataAlreadyRead;
    uint32_t lastAcknowledgedSeqNumber;
    uint32_t lastReceivedAckNumber;
    uint32_t nextUnreadSeqNumber;
    tcpStream stream;
    LIST(void*) unacknowledgedPackets; /* sent but not ACKed */
};

LIST(tcpIp6Socket) allTcpSockets = NULL;


static int sendWithFlags(tcpIp6Socket *sock,
                         uint32_t flags,
                         void *data,
                         size_t data_size);


static ip6PacketHeader *packetGetIp6Header(void *packet) {
    return (ip6PacketHeader*)packet;
}

static tcpPacketHeader *packetGetTcpHeader(void *packet) {
    return (tcpPacketHeader*)((char*)packet + sizeof(ip6PacketHeader));
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

#ifdef _DEBUG
static void printSocket(tcpIp6Socket *sock) {
    switch (sock->state) {
    case SOCK_STATE_CLOSED:       logInfo("state = CLOSED"); break;
    case SOCK_STATE_LISTEN:       logInfo("state = LISTEN"); break;
    case SOCK_STATE_SYN_SENT:     logInfo("state = SYN_SENT"); break;
    case SOCK_STATE_SYN_RECEIVED: logInfo("state = SYN_RECEIVED"); break;
    case SOCK_STATE_ESTABLISHED:  logInfo("state = ESTABLISHED"); break;
    case SOCK_STATE_FIN_WAIT_1:   logInfo("state = FIN_WAIT_1"); break;
    case SOCK_STATE_FIN_WAIT_2:   logInfo("state = FIN_WAIT_2"); break;
    case SOCK_STATE_CLOSE_WAIT:   logInfo("state = CLOSE_WAIT"); break;
    case SOCK_STATE_CLOSING:      logInfo("state = CLOSING"); break;
    case SOCK_STATE_LAST_ACK:     logInfo("state = LAST_ACK"); break;
    case SOCK_STATE_TIME_WAIT:    logInfo("state = TIME_WAIT"); break;
    }

    ip6DebugPrintAddress("local: ", sock->localAddress);
    logInfo(":%u", sock->localPort);

    ip6DebugPrintAddress("remote: ", sock->remoteAddress);
    logInfo(":%u", sock->remotePort);

    logInfo("seq: %u", sock->sequenceNumber);
    logInfo("last remote seq: %u", sock->stream.nextContiniousSeqNumber);
    logInfo("last remote ack: %u", sock->lastReceivedAckNumber);
    logInfo("last ack'd remote seq: %u", sock->lastAcknowledgedSeqNumber);

    logInfo("curr packet data read: %u", sock->currPacketDataAlreadyRead);
    logInfo("packets received: %lu", LIST_SIZE(sock->stream.packets));
    logInfo("packets unacknowledged: %lu", LIST_SIZE(sock->unacknowledgedPackets));
}
#else
#define printSocket(x) (void)0
#endif /* _DEBUG */

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

    logInfo("%s: [%c%c%c%c%c%c], seq % 10u, ack % 10u, %luB(%luB) data",
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

    logInfo("streamGetNextPacket: %u", stream->currPacketSeqNumber);

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

static ssize_t streamReadNextPacket(tcpStream *stream,
                                    void *buffer,
                                    size_t bufferSize)
{
    ip6PacketHeader *ip6Header;
    tcpPacketHeader *tcpHeader;
    size_t dataOffset;
    size_t bytesRemaining;
    size_t bytesToCopy;

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

    /*logInfo("%zu bytes read, %zu remaining\n"
            "dataLength %zu, alreadyRead %zu",
            bytesToCopy, bufferSize,
            ip6Header->dataLength,
            stream->currPacketDataAlreadyRead);*/

    if (bytesRemaining == bytesToCopy) {
        stream->currPacketSeqNumber = getNextPacketSeqNumber(*stream->packets);
        stream->currPacketDataAlreadyRead = 0;
        free(*stream->packets);
        LIST_ERASE(&stream->packets);
    }

    return bytesToCopy;
}

static int streamReadNextLine(tcpStream *stream,
                              char **outLine,
                              size_t *outSize) {
    ip6PacketHeader *ip6Header;
    tcpPacketHeader *tcpHeader;
    size_t currentChunkLength;
    char *lineStart;
    char *lineEnd;
    bool isEndOfPacket = false;

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

    logInfo("dataLength %zu, alreadyRead %zu",
            ip6Header->dataLength,
            stream->currPacketDataAlreadyRead);

    if (isEndOfPacket) {
        stringAppendPart(outLine, lineStart, lineEnd);
        stream->currPacketSeqNumber = getNextPacketSeqNumber(*stream->packets);
        free(*stream->packets);
        LIST_ERASE(&stream->packets);
        stream->currPacketDataAlreadyRead = 0;
        return STREAM_WAITING_FOR_PACKET;
    } else {
        assert(*lineEnd == '\n');

        stringAppendPart(outLine, lineStart, lineEnd + 1);
        stream->currPacketDataAlreadyRead += 1;
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

        /* odbierz kolejny pakiet */
        if (eth_recv(&sock->ethSocket, &ethertype,
                     (uint8_t*)*outPacket, &bytesRead)) {
            logInfo("eth_recv failed");
            continue;
        }

        ip6ToHostByteOrder(header);

        if (ethertype == ETHERTYPE_IPv6
                && header->nextHeaderType == HEADER_TYPE_TCP) {
            tcpHeader = (tcpPacketHeader*)((char*)*outPacket + sizeof(*header));
            tcpToHostByteOrder(tcpHeader);

            printPacketInfo("RECV", *outPacket, true);
            return 0;
        } else {
#ifdef LONG_DEBUG
            /*logInfo("skipping non-TCP packet (ethertype = %u, type = %u)",*/
                    /*(unsigned)ethertype, (unsigned)header->nextHeaderType);*/
#endif /* LONG_DEBUG */
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

        logInfo("last %u, curr %u", seqNumberToAcknowledge, packetSeqNum);
        logInfo("next = %u", nextSeqNum);
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

        logInfo("2: last %u, curr %u", seqNumberToAcknowledge, packetSeqNum);
        logInfo("next = %u", nextSeqNum);
        if (packetSeqNum == seqNumberToAcknowledge) {
            seqNumberToAcknowledge = nextSeqNum;
        }

        *LIST_APPEND_NEW(packets, void*) = packet;
    }

    logInfo("packet inserted; seq was %u, is %u",
            sock->stream.nextContiniousSeqNumber, seqNumberToAcknowledge);
    if (seqNumberToAcknowledge > sock->stream.nextContiniousSeqNumber) {
        sock->stream.nextContiniousSeqNumber = seqNumberToAcknowledge;

        if (sendWithFlags(sock, TCP_FLAG_ACK, NULL, 0)) {
            logInfo("sendWithFlags failed");
        }
    }
}

static void acknowledgePackets(tcpIp6Socket *sock,
                               uint32_t ackNumber) {
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
    static const ip6Address localAddr = { 0, 0, 0, 0, 0, 0, 0, 2 };

    sock->remotePort = tcpHeader->base.sourcePort;
    /* TODO: correctly fill local address */
    memcpy(sock->localAddress, localAddr, sizeof(ip6Address));
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

    switch (sock->state) {
    case SOCK_STATE_SYN_RECEIVED:
        if (tcpGetFlag(tcpHeader, TCP_FLAG_ACK)) {
            sock->state = SOCK_STATE_ESTABLISHED;
        }
        /* no break; */
    case SOCK_STATE_ESTABLISHED:
        if (tcpGetFlag(tcpHeader, TCP_FLAG_FIN)) {
            sock->state = SOCK_STATE_LAST_ACK;

            if (sendWithFlags(sock, TCP_FLAG_ACK | TCP_FLAG_FIN, NULL, 0)) {
                logInfo("sendWithFlags failed");
                return -1;
            }
        }
        if (tcpGetFlag(tcpHeader, TCP_FLAG_ACK)) {
            acknowledgePackets(sock, tcpHeader->base.ackNumber);
        }
        break;
    case SOCK_STATE_LAST_ACK:
        logInfo("connection terminated by remote host");
        savePacket = false;
        break;
    case SOCK_STATE_FIN_WAIT_1:
        if (tcpGetFlag(tcpHeader, TCP_FLAG_FIN)) {
            sock->state = SOCK_STATE_TIME_WAIT;
            ++sock->sequenceNumber;
            ++sock->stream.nextContiniousSeqNumber;
            savePacket = false;

            if (sendWithFlags(sock, TCP_FLAG_ACK, NULL, 0)) {
                logInfo("sendWithFlags failed");
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

static int processNextPacket(tcpIp6Socket *sock) {
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

    if (arpQuery(sock->remoteAddress, &destinationMac)) {
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

static void fillIp6Header(void *packet,
                          tcpIp6Socket *sock,
                          size_t dataLength) {
    ip6PacketHeader *ip6Header = packetGetIp6Header(packet);

    memcpy(&ip6Header->source, &sock->localAddress, sizeof(ip6Address));
    memcpy(&ip6Header->destination, &sock->remoteAddress, sizeof(ip6Address));

    ip6Header->hopLimit = 255;
    ip6Header->dataLength = sizeof(tcpPacketHeaderBase) + dataLength;
    ip6Header->nextHeaderType = HEADER_TYPE_TCP;

    ip6SetVersion(ip6Header, 6);
    ip6SetTrafficClass(ip6Header, 0);   /* TODO */
    ip6SetFlowLabel(ip6Header, 0);      /* TODO */

    ip6ToNetworkByteOrder(ip6Header);
}

static void fillTcpChecksum(void *packet) {
    ip6PacketHeader *ip6Header = packetGetIp6Header(packet);
    tcpPacketHeader *tcpHeader = packetGetTcpHeader(packet);

    size_t checksum = 0;
    uint8_t *ptr = (uint8_t*)tcpHeader;
    size_t i;
    size_t dataLength = ntohs(ip6Header->dataLength);

    tcpHeader->base.checksum = 0;

    for (i = 0; i < sizeof(ip6Header->source) / sizeof(uint16_t); ++i) {
        checksum += ntohs(ip6Header->source[i]);
        /*logInfo("%04x", ntohs(ip6Header->source[i]));*/
        checksum += ntohs(ip6Header->destination[i]);
        /*logInfo("%04x", ntohs(ip6Header->destination[i]));*/
    }

    checksum += dataLength;
    /*logInfo("%04x", dataLength);*/
    checksum += ip6Header->nextHeaderType;
    /*logInfo("%04x", ip6Header->nextHeaderType);*/

    for (i = 0; i < dataLength; i += 2) {
        uint16_t val = ((ptr[i] << 8) & 0xFF00) + (ptr[i + 1] & 0xFF);
        checksum += val;
        /*logInfo("%04x", val);*/
    }

    if (dataLength % 2) {
        uint16_t val = (ptr[i - 1] << 8) & 0xFF00;
        checksum += val;
        /*logInfo("%04x", val);*/
    }

    checksum = ~(uint16_t)((checksum & 0xFFFF) + (checksum >> 16));
    /*logInfo("checksum = %04x", checksum);*/
    tcpHeader->base.checksum = htons(checksum);
}

static void fillTcpHeader(void *packet,
                          tcpIp6Socket *sock,
                          uint32_t flags) {
    ip6PacketHeader *ip6Header = packetGetIp6Header(packet);
    tcpPacketHeader *tcpHeader = packetGetTcpHeader(packet);
    uint32_t dataSize;

    tcpHeader->base.sourcePort = sock->localPort;
    tcpHeader->base.destinationPort = sock->remotePort;
    tcpHeader->base.urgentPointer = 0;      /* TODO */
    tcpHeader->base.windowWidth = 43690;    /* TODO */
    tcpHeader->base.checksum = 0;           /* TODO */
    tcpHeader->base.sequenceNumber = sock->sequenceNumber;
    tcpHeader->base.ackNumber = (flags & TCP_FLAG_ACK)
            ? sock->stream.nextContiniousSeqNumber : 0;

    tcpSetDataOffset(tcpHeader, sizeof(tcpPacketHeaderBase));
    tcpSetFlags(tcpHeader, flags);

    if (flags & TCP_FLAG_SYN) {
        ++sock->sequenceNumber;
    }

    dataSize = ntohs(ip6Header->dataLength) - tcpGetDataOffset(tcpHeader);
    if (dataSize > 0) {
        logInfo("dataSize = %u", dataSize);
        sock->sequenceNumber += dataSize;
    }

    tcpToNetworkByteOrder(tcpHeader);
    fillTcpChecksum(packet);
}

static int sendWithFlags(tcpIp6Socket *sock,
                         uint32_t flags,
                         void *data,
                         size_t data_size) {
    const size_t MAX_REAL_DATA_PER_FRAME =
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
        void *dataPointer = (char*)packetGetTcpHeader(packet)
                            + sizeof(tcpPacketHeaderBase);
        size_t dataChunkLength = MIN(data_size, MAX_REAL_DATA_PER_FRAME);

        memcpy(dataPointer, data, dataChunkLength);
        fillIp6Header(packet, sock, dataChunkLength);
        fillTcpHeader(packet, sock, flags);

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

int tcpIp6Send(tcpIp6Socket *sock,
               void *data,
               size_t data_size) {
    return sendWithFlags(sock, TCP_FLAG_ACK | TCP_FLAG_PSH, data, data_size);
}

tcpIp6Socket *tcpIp6SocketCreate(void) {
    return LIST_APPEND_NEW(&allTcpSockets, tcpIp6Socket);
}

void tcpIp6SocketRelease(tcpIp6Socket *sock) {
    tcpIp6Socket **sockPtr;

    LIST_FOREACH_PTR(sockPtr, &allTcpSockets) {
        if (*sockPtr == sock) {
            LIST_ERASE(sockPtr);
            logInfo("socket erased");
            return;
        }
    }
}

int tcpIp6Accept(tcpIp6Socket *sock,
                 uint16_t port) {
    eth_socket_init(&sock->ethSocket);
    sock->state = SOCK_STATE_LISTEN;
    sock->localPort = port;

    do {
        if (processNextPacket(sock)) {
            logInfo("processPacket failed");
            return -1;
        }
    } while (sock->state == SOCK_STATE_LISTEN);

    if (sendWithFlags(sock, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0)) {
        logInfo("sendWithFlags failed");
        return -1;
    }

    do {
        if (processNextPacket(sock)) {
            logInfo("processPacket failed");
            return -1;
        }
    } while (sock->state != SOCK_STATE_ESTABLISHED);

    return 0;
}

static int closeConnection(tcpIp6Socket *sock) {
    logInfo("closing connection");

    if (sendWithFlags(sock, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0)) {
        logInfo("sendWithFlags failed");
        return -1;
    }

    /*logInfo("FIN sent, waiting for reply");*/
    sock->state = SOCK_STATE_FIN_WAIT_1;

    do {
        if (processNextPacket(sock)) {
            logInfo("processPacket failed");
            return -1;
        }
    } while (sock->state == SOCK_STATE_FIN_WAIT_1);

    logInfo("connection closed");

    memset(sock, 0, sizeof(*sock));
    sock->state = SOCK_STATE_CLOSED;
    return 0;
}

void tcpIp6Close(tcpIp6Socket *sock) {
    tcpIp6Socket **curr;

    closeConnection(sock);

    LIST_FOREACH_PTR(curr, &allTcpSockets) {
        if (*curr == sock) {
            LIST_CLEAR(&sock->stream.packets) {
                free(*sock->stream.packets);
            }
            logInfo("remaining packets freed");
            return;
        }
    }
}

int tcpIp6Recv(tcpIp6Socket *sock,
               void *buffer,
               size_t bufferSize) {
    if (sock->state != SOCK_STATE_ESTABLISHED) {
        logInfo("invalid socket state: %d", sock->state);
        return -1;
    }

    while (bufferSize > 0) {
        ssize_t bytesRead = streamReadNextPacket(&sock->stream,
                                                 buffer, bufferSize);

        switch (bytesRead) {
        case STREAM_ERROR:
            return -1;
        case STREAM_WAITING_FOR_PACKET:
            if (processNextPacket(sock)) {
                logInfo("processPacket failed");
                return -1;
            }
            break;
        default:
            bufferSize -= bytesRead;
            buffer = (char*)buffer + bytesRead;
            break;
        }
    }

    return 0;
}

int tcpIp6RecvLine(tcpIp6Socket *sock,
                   char **outLine,
                   size_t *outSize) {
    *outLine = NULL;
    *outSize = 0;

    if (sock->state != SOCK_STATE_ESTABLISHED) {
        logInfo("invalid socket state: %d", sock->state);
        return -1;
    }

    while (true) {
        ssize_t bytesRead = streamReadNextLine(&sock->stream,
                                               outLine, outSize);

        switch (bytesRead) {
        case STREAM_ERROR:
            return -1;
        case STREAM_WAITING_FOR_PACKET:
            if (processNextPacket(sock)) {
                logInfo("processPacket failed");
                return -1;
            }
            break;
        default:
            return 0;
        }
    }

    return -1;
}


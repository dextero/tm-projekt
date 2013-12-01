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
    uint32_t lastReceivedSeqNumber;
    uint32_t lastAcknowledgedSeqNumber;
    uint32_t lastReceivedAckNumber;
    LIST(void*) receivedPackets;
    LIST(void*) unacknowledgedPackets; /* sent but not ACKed */
};

LIST(tcpIp6Socket) allTcpSockets = NULL;


static ip6PacketHeader *packetGetIp6Header(void *packet) {
    return (ip6PacketHeader*)packet;
}

static tcpPacketHeader *packetGetTcpHeader(void *packet) {
    return (tcpPacketHeader*)((char*)packet + sizeof(ip6PacketHeader));
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

    if (!isHostByteOrder) {
        flags = ntohs(flags);
        seqNumber = ntohl(seqNumber);
        ackNumber = ntohl(ackNumber);
        payloadSize = ntohs(payloadSize);
    }

    packetSize = sizeof(ip6PacketHeader) + payloadSize;

    logInfo("%s: [%s%s%s%s%s%s%s%s%s], seq #%u, ack #%u, %lu bytes",
            header,
            (flags & TCP_FLAG_NS)  ? "NS "  : "",
            (flags & TCP_FLAG_CWR) ? "CWR " : "",
            (flags & TCP_FLAG_ECN) ? "ECN " : "",
            (flags & TCP_FLAG_URG) ? "URG " : "",
            (flags & TCP_FLAG_ACK) ? "ACK " : "",
            (flags & TCP_FLAG_PSH) ? "PSH " : "",
            (flags & TCP_FLAG_RST) ? "RST " : "",
            (flags & TCP_FLAG_SYN) ? "SYN " : "",
            (flags & TCP_FLAG_FIN) ? "FIN " : "",
            seqNumber, ackNumber, packetSize);
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


static void tcpAddReceivedPacketToList(LIST(void*) *packets,
                                       void *packet) {
    void ***curr;
    tcpPacketHeader *newTcpHeader = packetGetTcpHeader(packet);

    LIST_FOREACH_PTR(curr, packets) {
        tcpPacketHeader *tcpHeader = packetGetTcpHeader(*curr);
        if (tcpHeader->base.sequenceNumber <
                newTcpHeader->base.sequenceNumber) {
            *LIST_INSERT_NEW(curr, void*) = packet;
            return;
        }
    }

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

static void addClientSocket(tcpIp6Socket *socket,
                            ip6PacketHeader *ip6Header,
                            tcpPacketHeader *tcpHeader) {
    static const ip6Address localAddr = { 0, 0, 0, 0, 0, 0, 0, 2 };

    socket->remotePort = tcpHeader->base.sourcePort;
    /* TODO: correctly fill local address */
    memcpy(socket->localAddress, localAddr, sizeof(ip6Address));
    memcpy(socket->remoteAddress, ip6Header->source,
           sizeof(ip6Address));
    socket->localPort = tcpHeader->base.destinationPort;
    socket->state = SOCK_STATE_SYN_RECEIVED;
    socket->lastReceivedAckNumber = tcpHeader->base.ackNumber;
    socket->sequenceNumber = 0;
    socket->lastReceivedSeqNumber = tcpHeader->base.sequenceNumber;
    socket->lastAcknowledgedSeqNumber = 0;
}

static int processPacket(tcpIp6Socket *socket,
                         uint16_t acceptPort) {
    void *packet;
    ip6PacketHeader *ip6Header;
    tcpPacketHeader *tcpHeader;
    tcpIp6Socket *sockIter = NULL;

    assert(socket);

    if (recvNextPacket(socket, &packet)) {
        return -1;
    }

    ip6Header = packetGetIp6Header(packet);
    tcpHeader = packetGetTcpHeader(packet);

    LIST_FOREACH(sockIter, allTcpSockets) {
        if (ip6AddressEqual(sockIter->remoteAddress, ip6Header->source)) {
            if (socket->state == SOCK_STATE_FIN_WAIT_1
                    && tcpGetFlag(tcpHeader, TCP_FLAG_FIN)) {
                socket->state = SOCK_STATE_TIME_WAIT;
                return 0;
            }

            if (sockIter->remotePort == tcpHeader->base.sourcePort) {
                tcpAddReceivedPacketToList(&sockIter->receivedPackets, packet);

                if (tcpGetFlag(tcpHeader, TCP_FLAG_ACK)) {
                    socket->state = SOCK_STATE_ESTABLISHED;
                    acknowledgePackets(socket, tcpHeader->base.ackNumber);
                }

                return 0;
            }
        }
    }

    if (acceptPort == tcpHeader->base.destinationPort
            && tcpGetFlag(tcpHeader, TCP_FLAG_SYN)) {
        addClientSocket(socket, ip6Header, tcpHeader);
        tcpAddReceivedPacketToList(&socket->receivedPackets, packet);
    } else {
        logInfo("skipping packet (src port = %u, dst port = %u)",
                tcpHeader->base.sourcePort, tcpHeader->base.destinationPort);
        free(packet);
    }

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
        logInfo("arpQuery() failed");
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

    /* TODO: fragmentation */
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
    tcpPacketHeader *tcpHeader = packetGetTcpHeader(packet);

    tcpHeader->base.sourcePort = sock->localPort;
    tcpHeader->base.destinationPort = sock->remotePort;
    tcpHeader->base.urgentPointer = 0;      /* TODO */
    tcpHeader->base.windowWidth = 43690;    /* TODO */
    tcpHeader->base.checksum = 0;           /* TODO */
    tcpHeader->base.sequenceNumber = sock->sequenceNumber++;
    tcpHeader->base.ackNumber = sock->lastReceivedSeqNumber + 1;

    tcpSetDataOffset(tcpHeader, sizeof(tcpPacketHeaderBase));
    tcpSetFlags(tcpHeader, flags);

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

        if (flags & TCP_FLAG_ACK) {
            sock->lastAcknowledgedSeqNumber = sock->lastReceivedSeqNumber;
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

tcpIp6Socket *tcpIp6Accept(uint16_t port) {
    tcpIp6Socket *sock = LIST_NEW_ELEMENT(tcpIp6Socket);
    eth_socket_init(&sock->ethSocket);
    sock->state = SOCK_STATE_LISTEN;

    do {
        if (processPacket(sock, port)) {
            logInfo("processPacket failed");
            return NULL;
        }
    } while (sock->state == SOCK_STATE_LISTEN);

    if (sendWithFlags(sock, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0)) {
        logInfo("sendWithFlags failed");
        return NULL;
    }

    LIST_APPEND(&allTcpSockets, sock);
    return sock;
}

static int closeConnection(tcpIp6Socket *sock) {
    logInfo("closing connection");
    if (sendWithFlags(sock, TCP_FLAG_FIN, NULL, 0)) {
        logInfo("sendWithFlags failed");
        return -1;
    }

    logInfo("FIN sent, waiting for reply");
    sock->state = SOCK_STATE_FIN_WAIT_1;

    do {
        if (processPacket(sock, 0)) {
            logInfo("processPacket failed");
            return -1;
        }
    } while (sock->state == SOCK_STATE_FIN_WAIT_1);

    logInfo("connection closed");
    sock->state = SOCK_STATE_CLOSED;
    return 0;
}

void tcpIp6Close(tcpIp6Socket *sock) {
    tcpIp6Socket **curr;

    closeConnection(sock);

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
            if (processPacket(sock, 0)) {
                logInfo("processPacket() failed");
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

        /*logInfo("%zu bytes read, %zu remaining\n"
                "dataLength %zu, alreadyRead %zu",
                bytesToCopy, bufferSize,
                ip6Header->dataLength,
                sock->currPacketDataAlreadyRead);*/

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
        bool hasData = !!sock->receivedPackets;

        /* TODO: write it prettier */
        if (sock->receivedPackets) {
            ip6Header = packetGetIp6Header(*sock->receivedPackets);
            tcpHeader = packetGetTcpHeader(*sock->receivedPackets);

            hasData = (tcpGetDataOffset(tcpHeader) < ip6Header->dataLength);
        }

        while (!hasData) {
            if (processPacket(sock, 0)) {
                logInfo("processPacket() failed");
                return -1;
            }

            if (sock->receivedPackets) {
                ip6Header = packetGetIp6Header(*sock->receivedPackets);
                tcpHeader = packetGetTcpHeader(*sock->receivedPackets);

                hasData = (tcpGetDataOffset(tcpHeader) < ip6Header->dataLength);
                logInfo("has data? %d, data offset %x, length %x",
                        hasData, tcpGetDataOffset(tcpHeader), ip6Header->dataLength);

                if (!hasData) {
                    logInfo("removing %p", sock->receivedPackets);
                    LIST_ERASE(&sock->receivedPackets);
                }
            }
        }

        if (tcpGetDataOffset(tcpHeader) == ip6Header->dataLength) {
            continue;
        }

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
            stringAppendPart(outLine, lineStart, lineEnd);
            free(*sock->receivedPackets);
            LIST_ERASE(&sock->receivedPackets);
            sock->currPacketDataAlreadyRead = 0;
        } else {
            assert(*lineEnd == '\n');

            stringAppendPart(outLine, lineStart, lineEnd + 1);
            sock->currPacketDataAlreadyRead += 1;
            *outSize += 1; /* newline */
            break;
        }
    }

    return 0;
}


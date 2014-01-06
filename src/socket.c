#include "socket.h"

#include <string.h>

#include "tcp.h"
#include "generic_list.h"

LIST(tcpIp6Socket) allTcpSockets = NULL;

void printSocket(tcpIp6Socket *sock) {
#ifdef _DEBUG
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

    ip6PrintAddress("local: ", sock->localAddress, false);
    logInfo(":%u", sock->localPort);

    ip6PrintAddress("remote: ", sock->remoteAddress, false);
    logInfo(":%u", sock->remotePort);

    logInfo("seq: %u", sock->sequenceNumber);
    logInfo("last remote seq: %u", sock->stream.nextContiniousSeqNumber);
    logInfo("last remote ack: %u", sock->lastReceivedAckNumber);
    logInfo("last ack'd remote seq: %u", sock->lastAcknowledgedSeqNumber);

    logInfo("curr packet data read: %u", sock->currPacketDataAlreadyRead);
    logInfo("packets received: %lu", LIST_SIZE(sock->stream.packets));
    logInfo("packets unacknowledged: %lu", LIST_SIZE(sock->unacknowledgedPackets));
#else
    (void)sock;
#endif /* _DEBUG */
}


int socketSend(tcpIp6Socket *sock,
               void *data,
               size_t data_size) {
    return tcpSend(sock, TCP_FLAG_ACK | TCP_FLAG_PSH, data, data_size);
}

tcpIp6Socket *socketCreate(void) {
    tcpIp6Socket *sock = LIST_APPEND_NEW(&allTcpSockets, tcpIp6Socket);
    memcpy(sock->remoteAddress, IPv6_ALL_LINK_LOCAL, sizeof(ip6Address));
    return sock;
}

void socketRelease(tcpIp6Socket *sock) {
    tcpIp6Socket **sockPtr;

    LIST_FOREACH_PTR(sockPtr, &allTcpSockets) {
        if (*sockPtr == sock) {
            LIST_ERASE(sockPtr);
            logInfo("socket erased");
            return;
        }
    }
}

int socketAccept(tcpIp6Socket *sock,
                 const char *interface,
                 uint16_t port) {
    eth_socket_init(&sock->ethSocket, interface);
    sock->state = SOCK_STATE_LISTEN;
    sock->localPort = port;

    if (ip6AddressForInterface(interface, &sock->localAddress)) {
        logInfo("ip6AddressForInterface failed");
        return -1;
    }

    do {
        if (tcpProcessNextPacket(sock)) {
            logInfo("processPacket failed");
            return -1;
        }
    } while (sock->state == SOCK_STATE_LISTEN);

    if (tcpSend(sock, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0)) {
        logInfo("tcpSend failed");
        return -1;
    }

    do {
        if (tcpProcessNextPacket(sock)) {
            logInfo("processPacket failed");
            return -1;
        }
    } while (sock->state != SOCK_STATE_ESTABLISHED);

    return 0;
}

static int closeConnection(tcpIp6Socket *sock) {
    logInfo("closing connection");

    if (tcpSend(sock, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0)) {
        logInfo("tcpSend failed");
        return -1;
    }

    /*logInfo("FIN sent, waiting for reply");*/
    sock->state = SOCK_STATE_FIN_WAIT_1;

    do {
        if (tcpProcessNextPacket(sock)) {
            logInfo("processPacket failed");
            return -1;
        }
    } while (sock->state == SOCK_STATE_FIN_WAIT_1);

    logInfo("connection closed");

    memset(sock, 0, sizeof(*sock));
    sock->state = SOCK_STATE_CLOSED;
    return 0;
}

void socketReset(tcpIp6Socket *sock) {
    tcpIp6Socket **curr;

    LIST_FOREACH_PTR(curr, &allTcpSockets) {
        if (*curr == sock) {
            LIST_CLEAR(&sock->stream.packets) {
                free(*sock->stream.packets);
            }
            logInfo("remaining packets freed");
            return;
        }
    }

    sock->state = SOCK_STATE_CLOSED;
}

void socketClose(tcpIp6Socket *sock) {
    closeConnection(sock);
    socketReset(sock);
}


int socketRecv(tcpIp6Socket *sock,
               void *buffer,
               size_t bufferSize) {
    while (bufferSize > 0) {
        ssize_t bytesRead;

        if (sock->state != SOCK_STATE_ESTABLISHED) {
            logInfo("invalid socket state: %d", sock->state);
            return -1;
        }

        bytesRead = tcpStreamReadNextPacket(&sock->stream, buffer, bufferSize);

        switch (bytesRead) {
        case STREAM_ERROR:
            return -1;
        case STREAM_WAITING_FOR_PACKET:
            if (tcpProcessNextPacket(sock)) {
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

int socketRecvLine(tcpIp6Socket *sock,
                   char **outLine,
                   size_t *outSize) {
    *outLine = NULL;
    *outSize = 0;

    while (true) {
        ssize_t bytesRead;

        if (sock->state != SOCK_STATE_ESTABLISHED) {
            logInfo("invalid socket state: %d", sock->state);
            return -1;
        }

        bytesRead = tcpStreamReadNextLine(&sock->stream, outLine, outSize);

        switch (bytesRead) {
        case STREAM_ERROR:
            return -1;
        case STREAM_WAITING_FOR_PACKET:
            if (tcpProcessNextPacket(sock)) {
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


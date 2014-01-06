#ifndef MIKRO_PROJEKT_SOCKET_H
#define MIKRO_PROJEKT_SOCKET_H

#include <stdint.h>

#include "eth.h"
#include "generic_list.h"
#include "ip6.h"

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

typedef struct tcpStream {
    LIST(void*) packets;
    uint32_t currPacketSeqNumber;
    uint32_t currPacketDataAlreadyRead;
    uint32_t nextContiniousSeqNumber;
} tcpStream;

typedef struct tcpIp6Socket {
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
} tcpIp6Socket;


tcpIp6Socket *socketCreate(void);
void socketRelease(tcpIp6Socket *sock);

int socketAccept(tcpIp6Socket *sock,
                 const char *interface,
                 uint16_t port);
void socketClose(tcpIp6Socket *sock);
void socketReset(tcpIp6Socket *sock);

int socketRecvLine(tcpIp6Socket *sock,
                   char **outLine,
                   size_t *outSize);
int socketRecv(tcpIp6Socket *sock,
               void *buffer,
               size_t bufferSize);

int socketSend(tcpIp6Socket *sock,
               void *data,
               size_t data_size);

eth_socket *socketGetEthSocket(tcpIp6Socket *sock);

void printSocket(tcpIp6Socket *sock);

#endif /* MIKRO_PROJEKT_SOCKET_H */

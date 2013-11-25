#include <stdlib.h>

#include "tcp_ip6.h"
#include "utils.h"

int main() {
    char *line = NULL;
    size_t lineLength = 0;
    size_t i;

    char buffer[32] = "";

    tcpIp6Socket *socket = tcpIp6Accept(4545);

    if (!socket) {
        logInfo("tcpIp6Accept failed");
        return -1;
    }

    tcpIp6Recv(socket, buffer, sizeof(buffer) - 1);
    logInfo("recv: read %lu chars\n%s", sizeof(buffer) - 1, buffer);

    for (i = 0; i < 10; ++i) {
        tcpIp6RecvLine(socket, &line, &lineLength);
        logInfo("read %lu characters", lineLength);
        logInfo(">%s<", line);
        free(line);
        line = NULL;
    }

    tcpIp6Close(socket);
    return 0;
}

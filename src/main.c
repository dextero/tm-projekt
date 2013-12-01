#include <stdlib.h>
#include <stdio.h>

#include "tcp_ip6.h"
#include "utils.h"

#define DUMMY_RESPONSE \
    "HTTP/1.1 200 OK\n" \
    "Content-Type: text/html; charset=UTF-8\n" \
    "\n" \
    "<html><head/><body>Hello world!</body></html>\n" \
    "\n"


int main() {
    char *line = NULL;
    size_t lineLength = 0;

    tcpIp6Socket *socket;
    bool httpHeaderEnd;

    logInfo("waiting for a connection...");
    socket = tcpIp6Accept(4545);

    if (!socket) {
        logInfo("tcpIp6Accept failed");
        return -1;
    }

    logInfo("connection accepted!");
    logInfo("received data:");

    do {
        tcpIp6RecvLine(socket, &line, &lineLength);
        printf("> %s", line);

        httpHeaderEnd = !line
                || line[0] == '\n'
                || (line[0] == '\r' && line[1] == '\n');

        free(line);
        line = NULL;
    } while (!httpHeaderEnd);

    logInfo("seding HTTP 200...");
    tcpIp6Send(socket, DUMMY_RESPONSE, sizeof(DUMMY_RESPONSE) - 1);
    logInfo("response sent!");

    tcpIp6Close(socket);
    return 0;
}

#include <stdlib.h>
#include <stdio.h>

#include "tcp_ip6.h"
#include "utils.h"

#define DUMMY_RESPONSE_HTML \
    "<html>" \
      "<head/>" \
      "<body>" \
        "Hello world!" \
        "<form>" \
          "<textarea name=\"foo\"></textarea>" \
          "<input type=\"submit\" />" \
        "</form>" \
        "<script>" \
          "var text = '';" \
          "for (var i = 0; i < 10000; ++i) text += 'AAAAA';" \
          "document.getElementsByName('foo')[0].value = text;" \
        "</script>" \
      "</body>" \
    "</html>\n"

#define DUMMY_RESPONSE_HEADERS \
    "HTTP/1.1 200 OK\n" \
    "Content-Type: text/html; charset=UTF-8\n" \
    "Content-Length: %u\n" \
    "\n"

#define DUMMY_RESPONSE DUMMY_RESPONSE_HEADERS "%s"


int main() {
    char responseBuffer[sizeof(DUMMY_RESPONSE_HEADERS) + 16
                        + sizeof(DUMMY_RESPONSE_HTML)];
    char *line = NULL;
    size_t lineLength = 0;

    tcpIp6Socket *socket = tcpIp6SocketCreate();
    bool httpHeaderEnd;

    int i;

    ssize_t responseSize = snprintf(responseBuffer, sizeof(responseBuffer),
                                    DUMMY_RESPONSE,
                                    (unsigned)sizeof(DUMMY_RESPONSE_HTML) - 1,
                                    DUMMY_RESPONSE_HTML);

    for (i = 0; i < 3; ++i) {
        logInfo("*** waiting for a connection... ***");
        if (tcpIp6Accept(socket, 4545)) {
            logInfo("tcpIp6Accept failed");
            return -1;
        }

        logInfo("*** connection accepted! ***");
        logInfo("*** received data: ***");

        do {
            tcpIp6RecvLine(socket, &line, &lineLength);
            printf("> %s", line);

            httpHeaderEnd = !line
                    || line[0] == '\n'
                    || (line[0] == '\r' && line[1] == '\n');

            free(line);
            line = NULL;
        } while (!httpHeaderEnd);

        logInfo("*** seding HTTP 200... ***");
        tcpIp6Send(socket, responseBuffer, responseSize);
        logInfo("*** response sent! ***");

        tcpIp6Close(socket);
    }

    tcpIp6SocketRelease(socket);
    return 0;
}

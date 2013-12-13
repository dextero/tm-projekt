#include <stdlib.h>
#include <stdio.h>

#include "http.h"
#include "tcp_ip6.h"
#include "utils.h"

#define DUMMY_RESPONSE_HTML \
    "<html><head/><body>Hello world!</body></html>\n"

#define DUMMY_RESPONSE_HEADERS \
    "HTTP/1.1 200 OK\n" \
    "Content-Type: text/html; charset=UTF-8\n" \
    "Content-Length: 46\n" \
    "\n"

#define DUMMY_RESPONSE DUMMY_RESPONSE_HEADERS DUMMY_RESPONSE_HTML


int main() {
    char *line = NULL;
    size_t lineLength = 0;

    tcpIp6Socket *socket = tcpIp6SocketCreate();
    bool httpHeaderEnd;

    int i;
    for (i = 0; i < 3; ++i) {
        logInfo("waiting for a connection...");
        if (tcpIp6Accept(socket, 4545)) {
            logInfo("tcpIp6Accept failed");
            return -1;
        }

        logInfo("connection accepted!");
        logInfo("received data:");
        
        /*
        do {
            tcpIp6RecvLine(socket, &line, &lineLength);
            printf("> %s", line);

            httpHeaderEnd = !line
                    || line[0] == '\n'
                    || (line[0] == '\r' && line[1] == '\n');

            free(line);
            line = NULL;
        } while (!httpHeaderEnd);
        */
        http_request request;
        memset(&request, 0, sizeof(http_request));
        http_recv_request(socket, &request);
        http_print_request(&request);
        http_destroy_request_content(&request);

        logInfo("seding HTTP 200...");
        // tcpIp6Send(socket, DUMMY_RESPONSE, sizeof(DUMMY_RESPONSE) - 1);

        http_response resp;
        http_init_response(&resp);
        resp.code = 200;
        alloc_and_copy_string(&resp.content_type,"text/html; charset=UTF-8");
        alloc_and_copy_string(&resp.content, DUMMY_RESPONSE_HTML);
        http_send_response(socket, &resp);
        http_print_response(&resp);
        http_destroy_response_content(&resp);

        logInfo("response sent!");

        tcpIp6Close(socket);
    }

    tcpIp6SocketRelease(socket);
    return 0;
}

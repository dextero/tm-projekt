#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "http.h"
#include "tcp_ip6.h"
#include "utils.h"

#define RESPONSE_LEADING_HTML \
    "<html>\n" \
    " <head/>\n" \
    " <body>\n" \
    "  <h1>Leave your message:</h1>\n" \
    "  <FORM action=\"/\" enctype=\"multipart/form-data\" method=\"post\">\n" \
    "    Message: <INPUT type=\"text\" name=\"message\">\n" \
    "    <button>Send</button>\n" \
    "  </FORM>\n" \
    "  <br><h2>Messages:</h2>\n"

#define RESPONSE_TRAILING_HTML \
    " </body>\n" \
    "</html>"

#define DUMMY_RESPONSE_HTML RESPONSE_LEADING_HTML RESPONSE_TRAILING_HTML

#define CONTENT_DISPOSITION "Content-Disposition: form-data; name=\"message\""

static char* messages;

static void process_request(tcpIp6Socket* socket, http_request* request);
static void send_index(tcpIp6Socket* socket);
static void append_new_message(char* request_content);
static void send_see_other(tcpIp6Socket* socket);
static char* locate_message_in_response_content(char* request_content);

void process_request(tcpIp6Socket* socket, http_request* request) {
  if(request == NULL) {
    return;
  }
  if(request->request_type == HTTP_GET &&
      !strcmp(request->URI, "/")) {
    send_index(socket);
    return;
  }
  if(request->request_type == HTTP_POST &&
      !strcmp(request->URI, "/")) {
    append_new_message(request->content);
    send_see_other(socket);
  } 
}

static void send_index(tcpIp6Socket* socket) {
  http_response resp;
  http_init_response(&resp);
  resp.code = HTTP_CODE_OK;
  resp.content_type = strdup("text/html; charset=UTF-8");
  
  resp.content = malloc(strlen(DUMMY_RESPONSE_HTML) + strlen(messages) + 1);
  resp.content[0] = '\0';
  strcat(resp.content, RESPONSE_LEADING_HTML);
  strcat(resp.content, messages);
  strcat(resp.content, RESPONSE_TRAILING_HTML);
  
  http_send_response(socket, &resp);
  http_print_response(&resp);
  http_destroy_response_content(&resp);
}

static void append_new_message(char* request_content) {
  char* message;
  size_t new_messages_length;
  if(request_content == NULL)
    return;
  message = locate_message_in_response_content(request_content);
  if(message == NULL)
    return;
  new_messages_length = strlen(messages) + strlen(message) + 7;
  messages = realloc(messages, new_messages_length);
  strcat(messages, "<br>\n");
  strcat(messages, message);
  strcat(messages, "\n");
}

static char* locate_message_in_response_content(char* request_content) {
  char* iterator;
  char* message;
  iterator = strstr(request_content, CONTENT_DISPOSITION);
  if(iterator == NULL)
    return NULL;
  iterator += strlen(CONTENT_DISPOSITION);
  message = strtok(iterator, "\n\r");
  return message;
}

static void send_see_other(tcpIp6Socket* socket) {
  http_response response;
  http_init_response(&response);
  response.code = HTTP_CODE_SEE_OTHER;
  response.location = strdup("/"); 
  http_send_response(socket, &response);
  http_print_response(&response);
  http_destroy_response_content(&response);
}

int main() {
    char *line = NULL;
    size_t lineLength = 0;
    
    messages = malloc(1);
    messages[0] = '\0';

    tcpIp6Socket *socket = tcpIp6SocketCreate();
    bool httpHeaderEnd;

    int i;
        while (true) {
        logInfo("*** waiting for a connection... ***");
        if (tcpIp6Accept(socket, 4545)) {
            logInfo("tcpIp6Accept failed");
            return -1;
        }

        logInfo("connection accepted!");
        logInfo("received data:");
        
        /*

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
        */
        http_request* request = malloc(sizeof(http_request));
        memset(request, 0, sizeof(http_request));
        http_recv_request(socket, request);
        http_print_request(request);
        process_request(socket, request);
        http_destroy_request_content(request);
        free(request);

        logInfo("seding HTTP 200...");
        // tcpIp6Send(socket, DUMMY_RESPONSE, sizeof(DUMMY_RESPONSE) - 1);



        logInfo("response sent!");

        tcpIp6Close(socket);
    }

    tcpIp6SocketRelease(socket);
    return 0;
}

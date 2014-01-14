#include <string.h>
#include <stdlib.h>

#include "http.h"
#include "socket.h"

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
static void send_404(tcpIp6Socket* socket);

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
    return;
  }
  send_404(socket); 
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
  if(message == NULL || strlen(message) == 0)
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
  if(iterator[0] == '\r' && iterator[1] == '\n') {
    iterator += 4;
  } else if(iterator[0] == '\n') {
    iterator += 2;
  } else {
    return "";
  }
  if(iterator[0] == '\r' || iterator[0] == '\n') {
    return "";
  }
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

static void send_404(tcpIp6Socket* socket) {
  http_response response;
  http_init_response(&response);
  response.code = HTTP_CODE_NOT_FOUND;
  http_send_response(socket, &response);
  http_print_response(&response);
  http_destroy_response_content(&response); 
}

int main(int argc, char **argv) {
    tcpIp6Socket *socket = socketCreate();
    const char *interface = "lo";

    if (argc > 1) {
        interface = argv[1];
    }

    logInfo("*** using interface: %s ***", interface);
    
    messages = malloc(1);
    messages[0] = '\0';

    while (true) {
        http_request* request = NULL;

        logInfo("*** waiting for a connection... ***");
        if (socketAccept(socket, interface, 4545)) {
            logInfo("socketAccept failed");
            return -1;
        }

        logInfo("connection accepted!");
        logInfo("received data:");
        
        request = malloc(sizeof(http_request));
        memset(request, 0, sizeof(http_request));
        if (!http_recv_request(socket, request)) {
            http_print_request(request);
            process_request(socket, request);
            http_destroy_request_content(request);
            free(request);
        }

        logInfo("response sent!");

        socketClose(socket);
    }

    socketRelease(socket);
    return 0;
}

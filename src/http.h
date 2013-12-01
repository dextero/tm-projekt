#ifndef MIKRO_PROJEKT_HTTP_H
#define MIKRO_PROJEKT_HTTP_H

#include "tcp_ip6.h"

#define HTTP_INCORRECT_REQUEST 0
#define HTTP_GET 66
#define HTTP_POST 67

#pragma pack(1)
typedef struct http_request {
  char request_type;
  char* URI;
  char* protocol;
  char* accept;
  /* the following are used only for POST requests */
  char* content_type;
  size_t content_length;
  char* content;
} http_request;

typedef struct http_response {
  char* protocol;
  uint16_t code;
  char* code_description;
  char* date;
  char* server;
  char* content_type;
  char* content;
} http_response;
#pragma pack()

void http_destroy_request(http_request* request);
void http_destroy_response(http_response* response);
http_request* http_recv_request(tcpIp6Socket* socket);
void http_send_response(tcpIp6Socket* socket, http_response* response);

#endif /* MIKRO_PROJEKT_HTTP_H */

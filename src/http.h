#ifndef MIKRO_PROJEKT_HTTP_H
#define MIKRO_PROJEKT_HTTP_H

#include "packet.h"

#define HTTP_INCORRECT_REQUEST 0
#define HTTP_GET 66
#define HTTP_POST 67
#define HTTP_CODE_OK 200
#define HTTP_CODE_NO_CONTENT 204
#define HTTP_CODE_SEE_OTHER 303
#define HTTP_CODE_BAD_REQUEST 400
#define HTTP_CODE_FORBIDDEN 403
#define HTTP_CODE_NOT_FOUND 404

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
  char* date;
  char* server;
  char* location;
  char* content_type;
  char* content;
} http_response;
#pragma pack()

void http_destroy_request_content(http_request* request);
void http_destroy_response_content(http_response* response);
int http_recv_request(tcpIp6Socket* socket, http_request* request);
void http_init_response(http_response* response);
int http_send_response(tcpIp6Socket* socket, http_response* response);
void http_print_request(http_request* request);
void http_print_response(http_response* response);

#endif /* MIKRO_PROJEKT_HTTP_H */

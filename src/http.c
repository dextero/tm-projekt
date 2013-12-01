#include <string.h>
#include <stdlib.h>

#include "http.h"
#include "tcp_ip6.h"
#include "utils.h"

static int recv_first_line(tcpIp6Socket* socket, http_request* request);
static bool line_empty(char* line);
static char get_request_type(char* token);
static bool protocol_name_invalid(char* token);

static int recv_first_line(tcpIp6Socket* socket, http_request* request) {
#define FREE_AND_RETURN(line, i) { free(line); return (i); }
  char* line;
  size_t line_length;
  char* token;
  char request_type;
  line = NULL;
  line_length = -0;
  tcpIp6RecvLine(socket, &line, &line_length);
  if(line == NULL)
    return -1;
  if(line_empty(line)) {
    FREE_AND_RETURN(line, -1);
  }
  token = strtok(line, " ");
  request_type = get_request_type(token);
  if(request == HTTP_INCORRECT_REQUEST) {
    FREE_AND_RETURN(line, -1);
  }
  request->request_type = request_type;
  token = strtok(NULL, " ");
  if(token == NULL) {
    FREE_AND_RETURN(line, -1);
  }
  request->URI = malloc(strlen(token) + 1);
  strcpy(request->URI, token);
  token = strtok(NULL, " \r\n");
  if(token == NULL || protocol_name_invalid(token)) {
    FREE_AND_RETURN(line, -1);
  }
  request->protocol = malloc(strlen(token) + 1);
  strcpy(request->protocol, token);
  if(strtok(NULL, " \r\n") != NULL) {
    FREE_AND_RETURN(line, -1);
  } else {
    FREE_AND_RETURN(line, 0);
  }
}

static bool line_empty(char* line) {
  return !line || line[0] == '\n' || (line[0] == '\r' && line[1] == '\n');
}

static char get_request_type(char* token) {
  if(token == NULL)
    return HTTP_INCORRECT_REQUEST;
  else if(!strcmp(token, "GET"))
    return HTTP_GET;
  else if(!strcmp(token, "POST"))
    return HTTP_POST;
  else
    return HTTP_INCORRECT_REQUEST;
}

static bool protocol_name_invalid(char* token) {
  return strcmp(token, "HTTP/1.0") && strcmp(token, "HTTP/1.1");
}

void http_destroy_request(http_request* request) {
  if(request == NULL)
    return;
  if(request->URI != NULL)
    free(request->URI);
  if(request->protocol != NULL)
    free(request->protocol);
  if(request->accept != NULL)
    free(request->accept);
  if(request->content_type != NULL)
    free(request->content_type);
  if(request->content != NULL)
    free(request->content);
}

void http_destroy_response(http_response* response) {
  if(response == NULL)
    return;
  if(response->protocol != NULL)
    free(response->protocol);
  if(response->code_description != NULL)
    free(response->code_description);
  if(response->date != NULL)
    free(response->date);
  if(response->server != NULL)
    free(response->server);
  if(response->content_type != NULL)
    free(response->content_type);
  if(response->content != NULL)
    free(response->content);
}

http_request* http_recv_request(tcpIp6Socket* socket) {
  http_request request;
  if(recv_first_line(socket, &request)) {
    http_destroy_request(&request);
    return NULL;
  }
  /* TODO */
  return NULL;
}

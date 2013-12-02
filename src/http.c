#include <string.h>
#include <stdlib.h>

#include "http.h"
#include "tcp_ip6.h"
#include "utils.h"

#define FREE_AND_RETURN(line, i) { free(line); return (i); }

static int recv_first_line(tcpIp6Socket* socket, http_request* request);
static bool line_empty(char* line);
static char get_request_type(char* token);
static bool protocol_name_invalid(char* token);
static int recv_next_lines(tcpIp6Socket* socket, http_request* request);
static int fill_proper_request_field(char* line, http_request* request);
static int fill_specified_request_field(char* key, char* value, http_request* request);
static void alloc_and_copy_string(char** dest_pointer, char* source);
static int recv_msg_body(tcpIp6Socket* socket, http_request* request);

static int recv_first_line(tcpIp6Socket* socket, http_request* request) {
  char* line;
  size_t line_length;
  char* token;
  char request_type;
  line = NULL;
  line_length = 0;
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

static bool line_crlf(char* line) {
  return line != NULL && strlen(line) == 2 && line[0] == '\r' && line[1] == '\n';
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

static int recv_next_lines(tcpIp6Socket* socket, http_request* request) {
  char* line;
  size_t line_length; 
  tcpIp6RecvLine(socket, &line, &line_length);
  if(line_crlf(line)) {
    if(request->request_type == HTTP_POST && request->content == NULL) {
      FREE_AND_RETURN(line, recv_msg_body(socket, request));
    } else {
      FREE_AND_RETURN(line, 0);
    }
  } else if(line_empty(line)) {
    if(line != NULL)
      free(line);
    return 0;
  } else {
    if(fill_proper_request_field(line, request)) {
      FREE_AND_RETURN(line, -1);
    } else {
      FREE_AND_RETURN(line, recv_next_lines(socket, request));
    }
  }
}

static int recv_msg_body(tcpIp6Socket* socket, http_request* request) {
  char* line;
  char* line_content;
  size_t line_length;
  tcpIp6RecvLine(socket, &line, &line_length);
  if(line == NULL) {
    return -1;
  }
  line_content = strtok(line, "\n\r");
  if(line_content == NULL) {
    FREE_AND_RETURN(line, -1);
  }
  alloc_and_copy_string(&request->content, line_content);
  free(line);
  tcpIp6RecvLine(socket, &line, &line_length);
  if(line_crlf(line)) {
    FREE_AND_RETURN(line, 0);
  } else {
    FREE_AND_RETURN(line, -1);
  }
}

static int fill_proper_request_field(char* line, http_request* request) {
  char* key;
  char* value;
  if(line == NULL || request == NULL)
    return -1;
  key = strtok(line, ":");
  value = strtok(NULL, "\n\r");
  if(key == NULL || value == NULL)
    return -1;
  if(value[0] != ' ')
    return -1;
  ++value;
  return fill_specified_request_field(key, value, request);
}

static int
fill_specified_request_field(char* key, char* value, http_request* request) {
  if(!strcmp(key, "Accept")) {
    alloc_and_copy_string(&request->accept, value);
  } else if(!strcmp(key, "Content-Type")) {
    alloc_and_copy_string(&request->content_type, value);
  } else if(!strcmp(key, "Content-Length")) {
    request->content_length = (size_t) atoi(value);
  }
  return 0;
}

static void alloc_and_copy_string(char** dest_pointer, char* source) {
  *dest_pointer = malloc(strlen(source) + 1);
  memcpy(*dest_pointer, source, strlen(source + 1));
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
  free(request);
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
  free(response);
}

http_request* http_recv_request(tcpIp6Socket* socket) {
  http_request* request = malloc(sizeof(http_request));
  if(recv_first_line(socket, request)) {
    http_destroy_request(request);
    return NULL;
  }
  if(recv_next_lines(socket, request)) {
    http_destroy_request(request);
    return NULL;
  }
  return request;
}

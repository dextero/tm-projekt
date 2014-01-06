#include "http.h"

#include <string.h>
#include <time.h>
#include <stdio.h>

#include "socket.h"

#define FREE_AND_RETURN(line, i) { free(line); return (i); }

static int recv_first_line(tcpIp6Socket* socket, http_request* request);
static bool line_empty(char* line);
static char get_request_type(char* token);
static bool protocol_name_invalid(char* token);
static int recv_next_lines(tcpIp6Socket* socket, http_request* request);
static int fill_proper_request_field(char* line, http_request* request);
static int fill_specified_request_field(char* key, char* value, http_request* request);
static int recv_msg_body(tcpIp6Socket* socket, http_request* request);
static int is_response_incorrect(http_response* response);
static char* accumulate_response(char* accumulator, http_response* response);
static char* accumulate_first_line(char* accumulator, http_response* response);
static char* get_code_description(uint16_t code);
static char* accumulate_key_val(char* accumulator, char* key, char* value);
static char* accumulate_content(char* accumulator, char* content);
static char* get_request_code(int request_code);

static int recv_first_line(tcpIp6Socket* socket, http_request* request) {
  char* line;
  size_t line_length;
  char* token;
  char request_type;
  line = NULL;
  line_length = 0;
  socketRecvLine(socket, &line, &line_length);
  if(line == NULL)
    return -1;
  if(line_empty(line)) {
    FREE_AND_RETURN(line, -1);
  }
  token = strtok(line, " ");
  request_type = get_request_type(token);
  if(request_type == HTTP_INCORRECT_REQUEST) {
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
  line = NULL;
  socketRecvLine(socket, &line, &line_length);
  if(line == NULL)
    return -1;
  if(line_crlf(line)) {
    if(request->request_type == HTTP_POST && request->content == NULL) {
      FREE_AND_RETURN(line, recv_msg_body(socket, request));
    } else {
      FREE_AND_RETURN(line, 0);
    }
  } else if(line_empty(line)) {
    FREE_AND_RETURN(line, -1);
  } else {
    if(fill_proper_request_field(line, request)) {
      FREE_AND_RETURN(line, -1);
    } else {
      FREE_AND_RETURN(line, recv_next_lines(socket, request));
    }
  }
}

static int recv_msg_body(tcpIp6Socket* socket, http_request* request) {
  size_t to_receive = request->content_length;
  request->content = malloc(to_receive + 1);
  if (socketRecv(socket, request->content, to_receive))
    return -1;
  request->content[to_receive] = '\0';
  return 0;
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
    request->accept = strdup(value);
  } else if(!strcmp(key, "Content-Type")) {
    request->content_type = strdup(value);
  } else if(!strcmp(key, "Content-Length")) {
    request->content_length = (size_t) atoi(value);
  }
  return 0;
}

void http_destroy_request_content(http_request* request) {
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

void http_destroy_response_content(http_response* response) {
  if(response == NULL)
    return;
  if(response->protocol != NULL)
    free(response->protocol);
  if(response->date != NULL)
    free(response->date);
  if(response->server != NULL)
    free(response->server);
  if(response->location != NULL)
    free(response->location);
  if(response->content_type != NULL)
    free(response->content_type);
  if(response->content != NULL)
    free(response->content);
}

int http_recv_request(tcpIp6Socket* socket, http_request* request) {
  if(request == NULL)
    return -1;
  if(recv_first_line(socket, request)) {
    http_destroy_request_content(request);
    return -1;
  }
  if(recv_next_lines(socket, request)) {
    free(request);
    return -1;
  }
  return 0;
}

void http_init_response(http_response* response) {
  time_t current_time;
  memset((void*) response, (uint8_t) 0, sizeof(http_response));
  response->protocol = strdup("HTTP/1.1");
  response->server = strdup("Pawlicki-Radomski uber application serv ftw.");
  time(&current_time);
  response->date = strdup((char*) ctime(&current_time));
  response->date[strlen(response->date) - 1] = '\0';
}

int http_send_response(tcpIp6Socket* socket, http_response* response) {
  char* accumulator;
  int result;
  if(is_response_incorrect(response))
    return -1;
  accumulator = malloc(1);
  accumulator[0] = '\0';
  accumulator = accumulate_response(accumulator, response);
  result = socketSend(socket, accumulator, strlen(accumulator));
  free(accumulator);
  return result;
}

static int is_response_incorrect(http_response* response) {
  return
      response == NULL ||
      response->protocol == NULL ||
      (response->code != HTTP_CODE_OK &&
          response->code != HTTP_CODE_NO_CONTENT &&
          response->code != HTTP_CODE_SEE_OTHER &&
          response->code != HTTP_CODE_BAD_REQUEST &&
          response->code != HTTP_CODE_FORBIDDEN &&
          response->code != HTTP_CODE_NOT_FOUND);
}

static char* accumulate_response(char* accumulator, http_response* response) {
  accumulator = accumulate_first_line(accumulator, response);
  if(response->date != NULL)
    accumulator = accumulate_key_val(accumulator, "Date",  response->date);
  if(response->server != NULL)
    accumulator = accumulate_key_val(accumulator, "Server",  response->server);
  if(response->location != NULL)
    accumulator = accumulate_key_val(
        accumulator, "Location", response->location);
  if(response->content_type != NULL)
    accumulator = accumulate_key_val(
        accumulator, "Content-Type",  response->content_type);
  if(response->code != HTTP_CODE_NO_CONTENT &&
      response->content != NULL)
    accumulator = accumulate_content(accumulator, response->content);
  return accumulator;
}

static char* accumulate_first_line(char* accumulator, http_response* response) {
  char code_number[8];
  char* code_description;
  size_t length;
  sprintf(code_number, "%d", response->code);
  code_description = get_code_description(response->code);
  length = strlen(response->protocol) + strlen(code_number)
      + strlen(code_description) + 3;
  accumulator = realloc((void*) accumulator, strlen(accumulator) + length + 1);
  strcat(accumulator, response->protocol);
  strcat(accumulator, " ");
  strcat(accumulator, code_number);
  strcat(accumulator, " ");
  strcat(accumulator, code_description);
  strcat(accumulator, "\n");
  return accumulator;
}

static char* get_code_description(uint16_t code) {
  switch(code) {
    default:
    case HTTP_CODE_OK:
      return "OK";
    case HTTP_CODE_NO_CONTENT:
      return "No content";
    case HTTP_CODE_SEE_OTHER:
      return "See Other";
    case HTTP_CODE_BAD_REQUEST:
      return "Bad request";
    case HTTP_CODE_FORBIDDEN:
      return "Forbidden";
    case HTTP_CODE_NOT_FOUND:
      return "Not Found";
  }
}

static char* accumulate_key_val(char* accumulator,
    char* key, char* value) {
  int length;
  length = strlen(key) + strlen(value) + 3;
  accumulator = realloc((void*) accumulator, strlen(accumulator) + length + 1);
  strcat(accumulator, key);
  strcat(accumulator, ": ");
  strcat(accumulator, value);
  strcat(accumulator, "\n");
  return accumulator;
}

static char* accumulate_content(char* accumulator,
    char* content) {
  int content_length;
  int buf_length;
  char length_string[8];
  content_length = strlen(content);
  sprintf(length_string, "%d", content_length);
  accumulator = accumulate_key_val(accumulator, "Content-Length", length_string);
  buf_length = strlen(accumulator) + strlen(content) + 3;
  accumulator = realloc((void*) accumulator, buf_length);
  strcat(accumulator, "\r\n");
  strcat(accumulator, content);
  return accumulator;
}

void http_print_request(http_request* request) {
  if(request == NULL)
    return;
  printf(">>>>>>>>> REQUEST <<<<<<<<<\n");
  if(request->URI != NULL && request->protocol != NULL)
    printf("%s %s %s\n",
        get_request_code(request->request_type),
        request->URI,
        request->protocol);
  if(request->accept != NULL)
    printf("Accept: %s\n", request->accept);
  if(request->content_type != NULL) {
    printf("Content-Type: %s\n", request->content_type);
    printf("Content-Length: %d\n", (int) (request->content_length));
  }
  if(request->content != NULL)
    printf(">>>>>>>>> [content] <<<<<<<<<\n%s\n", request->content);
  printf(">>>>>>>>> END OF REQUEST <<<<<<<<<\n");
  fflush(stdout);
}

static char* get_request_code(int request_code) {
  switch(request_code) {
  case HTTP_GET:
    return "GET";
  case HTTP_POST:
    return "POST";
  default:
    return "";
  }
}

void http_print_response(http_response* response) {
  char* response_string;
  if(response == NULL)
    return;
  response_string = malloc(1);
  response_string[0] = '\0';
  response_string = accumulate_response(response_string, response);
  printf(">>>>>>>>> RESPONSE <<<<<<<<<\n");
  printf("%s\n", response_string);
  printf(">>>>>>>>> END OF RESPONSE <<<<<<<<<\n");
  free(response_string);
}

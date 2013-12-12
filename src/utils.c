#include "utils.h"

#ifdef logInfo
#undef logInfo
#endif

#include <stdio.h>
#include <stdarg.h>

uint16_t ntohs(uint16_t bytes) {
    return __builtin_bswap16(bytes);
}

uint32_t ntohl(uint32_t bytes) {
    return __builtin_bswap32(bytes);
}

void logInfoNoNewline(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
}

void logInfo(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);

    printf("\n");
}

void alloc_and_copy_string(char** dest_ptr, char* source) {
    *dest_ptr = malloc(strlen(source) + 1);
    strcpy(*dest_ptr, source);
}

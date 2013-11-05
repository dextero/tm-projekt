#include "eth.h"

#include <string.h>

#include "test_data.h"
#include "utils.h"

static const char DATA[] = TEST_IPv6_PACKET;
static const size_t dataSize = sizeof(DATA) - 1;
static size_t currPos = 0;

void ethRecv(void *outBuffer, size_t bytes) {
    while (bytes > 0) {
        size_t bytesToCopy = MIN(dataSize - currPos, bytes);

        memcpy(outBuffer, DATA + currPos, bytesToCopy);
        outBuffer = (char*)outBuffer + bytesToCopy;
        bytes -= bytesToCopy;
        currPos = (currPos + bytesToCopy) % dataSize;
    }
}

void ethSkip(size_t bytes) {
    currPos = (currPos + bytes) % dataSize;
}

void ethSend(const void *buffer, size_t bytes) {
    (void)buffer;
    logInfo("ethSend: %lu bytes\n", bytes);
}

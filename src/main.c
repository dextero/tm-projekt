#include <stdlib.h>

#include "tcp_ip6.h"
#include "utils.h"

int main() {
    char *line = NULL;
    size_t lineLength = 0;
    size_t i;

    for (i = 0; i < 10; ++i) {
        tcpIp6RecvLine(&line, &lineLength);
        logInfo("read %lu characters", lineLength);
        logInfo(">%s<", line);
        free(line);
        line = NULL;
    }

    return 0;
}

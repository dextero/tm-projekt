#include "arp.h"

#include <string.h>

int arpQuery(const ip6Address ip, mac_address *outMac) {
    (void)ip;
    memset(outMac, 0xffffffff, sizeof(*outMac));
    return 0;
}

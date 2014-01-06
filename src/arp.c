#include <string.h>
#include <stdlib.h>

#include "eth_new.h"
#include "generic_list.h"
#include "ip6.h"
#include "ndp.h"
#include "socket.h"
#include "tcp.h"


typedef struct ipMacPair {
    ip6Address ip;
    mac_address mac;
} ipMacPair;

LIST(ipMacPair) arpTable = NULL;


ipMacPair *arpFind(const ip6Address ip, mac_address *mac) {
    ipMacPair *pair;

    /*ip6PrintAddress("searching ARP table for ", ip, false);*/
    /*logInfo("");*/

    /*logInfo("%lu entries total", LIST_SIZE(arpTable));*/

    LIST_FOREACH(pair, arpTable) {
        /*ip6PrintAddress("checking ", pair->ip, false);*/
        /*logInfo("");*/

        if ((!ip || !memcmp(ip, pair->ip, sizeof(ip6Address)))
                && (!mac || !memcmp(mac, &pair->mac, sizeof(mac_address)))) {
            /*logInfo("that's it!");*/
            return pair;
        }
    }

    /*logInfo("nothing found :(");*/
    return NULL;
}

void arpAdd(const ip6Address ip, const mac_address mac) {
    ipMacPair *ipMac = arpFind(ip, NULL);

    if (!ipMac) {
        /*logInfo("new ARP table entry!");*/
        ipMac = LIST_NEW_ELEMENT(ipMacPair);
        LIST_APPEND(&arpTable, ipMac);
    } else {
        /*ip6PrintAddress("ARP table: updating ", ipMac->ip, false);*/
        /*logInfo(" with MAC %x:%x:%x:%x:%x:%x",*/
                /*ipMac->mac.bytes[0], ipMac->mac.bytes[1], ipMac->mac.bytes[2],*/
                /*ipMac->mac.bytes[3], ipMac->mac.bytes[4], ipMac->mac.bytes[5]);*/
    }

    memcpy(ipMac->ip, ip, sizeof(ip6Address));
    memcpy(&ipMac->mac, &mac, sizeof(mac_address));

    /*ip6PrintAddress("ARP table: adding ", ipMac->ip, false);*/
    /*logInfo(" with MAC %x:%x:%x:%x:%x:%x",*/
            /*ipMac->mac.bytes[0], ipMac->mac.bytes[1], ipMac->mac.bytes[2],*/
            /*ipMac->mac.bytes[3], ipMac->mac.bytes[4], ipMac->mac.bytes[5]);*/
}

int arpQuery(tcpIp6Socket *sock, const ip6Address ip, mac_address *outMac) {
    while (true) {
        ipMacPair *ipMac = arpFind(ip, NULL);

        if (ipMac) {
            memcpy(outMac, &ipMac->mac, sizeof(mac_address));
            ip6PrintAddress("ARP query ", ip, false);
            logInfo(" resolved to %x:%x:%x:%x:%x:%x",
                    outMac->bytes[0], outMac->bytes[1], outMac->bytes[2],
                    outMac->bytes[3], outMac->bytes[4], outMac->bytes[5]);
            return 0;
        }

        ip6PrintAddress("still waiting for advertisement for ", ip, false);
        logInfo("");

        if (icmp6SendSolicit(sock, ip)) {
            logInfo("icmp6SendSolicit() failed");
            return -1;
        }

        if (tcpProcessNextPacket(sock)) {
            logInfo("tcpProcessNextPacket() failed");
            return -1;
        }
    }

    return -1;
}

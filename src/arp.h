#ifndef MIKRO_PROJEKT_ARP_H
#define MIKRO_PROJEKT_ARP_H

#include "eth_new.h"
#include "tcp_ip6.h"

int arpQuery(const ip6Address ip, mac_address *outMac);

#endif /* MIKRO_PROJEKT_ARP_H */

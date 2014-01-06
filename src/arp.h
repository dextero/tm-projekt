#ifndef MIKRO_PROJEKT_ARP_H
#define MIKRO_PROJEKT_ARP_H


int arpQuery(tcpIp6Socket *sock, const ip6Address ip, mac_address *outMac);
void arpAdd(const ip6Address ip, const mac_address mac);

#endif /* MIKRO_PROJEKT_ARP_H */

#ifndef MIKRO_PROJEKT_UTILS_H
#define MIKRO_PROJEKT_UTILS_H

#include <stdint.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef uint8_t bool;
static const uint8_t true = 1;
static const uint8_t false = 0;

/* konwertuje liczbe 16bitowa z kolejnosci bajtow sieci na kolejnosc bajtow
 * hosta */
uint16_t ntohs(uint16_t bytes);

/* konwertuje liczbe 32bitowa z kolejnosci bajtow sieci na kolejnosc bajtow
 * hosta */
uint32_t ntohl(uint32_t bytes);

/* konwersje w druga strone - takie same */
#define htons ntohs
#define htonl ntohl

void logInfoNoNewline(const char *format, ...);
void logInfo(const char *format, ...);

#endif /* MIKRO_PROJEKT_UTILS_H */

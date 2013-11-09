#ifndef MIKRO_PROJEKT_TEST_DATA_H
#define MIKRO_PROJEKT_TEST_DATA_H

#define TEST_HTTP_DATA \
    "GET /index.html HTTP/1.1\r\n" \
    "Host: www.example.com\r\n"

#define TEST_TCP_PACKET_HEADER \
    "\xe3\x4c"          /* port zrodlowy             */ \
    "\x00\x50"          /* port docelowy = 80 (HTTP) */ \
    "\xcd\x0b\xcf\x24"  /* numer sekwencyjny         */ \
    "\xba\x8f\xba\xff"  /* numer potwierdzenia       */ \
    "\x80\x02"          /* dlugosc naglowka (4b)
                           + zarezerwowane  (3b)
                           + flagi          (9b)     */ \
    "\x00\x32"          /* szerokosc okna            */ \
    "\xc0\xab"          /* suma kontrolna            */ \
    "\x00\x00"          /* wskaznik priorytetu       */ \
    /* opcje (???) */ \
    "\x01\x01\x08\x0a\x0f\xdf\x4d\x5b\x00\x11\x2d\x3c"

#define TEST_TCP_PACKET \
    TEST_TCP_PACKET_HEADER TEST_HTTP_DATA

#define TEST_IPv6_PACKET_HEADER \
    "\x60\x00\x00\x00" /* wersja               (4b)
                          + klasa ruchu        (8b)
                          + etykieta przeplywu (20b)                     */ \
    "\x00\x51"         /* dlugosc danych                                 */ \
    "\x06"             /* protokol warstwy wyzszej, dla TCP: 6 (RFC 790) */ \
    "\x01"             /* liczba przeskokow                              */ \
    /* adres zrodlowy */ \
    "\xfe\x80\x00\x00\x00\x00\x00\x00\x39\x89\x48\x68\xa2\xf7\xc4\x78" \
    /* adres docelowy */ \
    "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c"

#define TEST_IPv6_PACKET \
    TEST_IPv6_PACKET_HEADER TEST_TCP_PACKET

#endif /* MIKRO_PROJEKT_TEST_DATA_H */

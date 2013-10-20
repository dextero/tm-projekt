CC = clang
CFLAGS = -Wall -Wextra -pedantic -g

default: tcp
tcp: tcp.c
	$(CC) $(CFLAGS) -o tcp $<

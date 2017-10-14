all: sniffer

CC = gcc
INCLUDE = ../inc
CFLAGS = -g -Wall -ansi --std=c99

sniffer: main.o sniffer.o
	$(CC) -o sniffer main.o sniffer.o

sniffer.o: sniffer.c
	$(CC) -I$(INCLUDE) $(CFLAGS) sniffer.c -c

main.o: main.c
	$(CC) -I$(INCLUDE) $(CFLAGS) main.c -c

clean:
	rm -rf *.o *.bin
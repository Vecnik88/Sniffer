all: clean sniffer

CC = gcc
INC = ./inc
SRC = ./src
CFLAGS =-g -Wall -g3 -O0 -I$(INC)
SOURCES = $(wildcard ./src/*.c)
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = sniffer
INSTPATH = /usr/bin

.PHONY: all clean run install uninstall

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	-rm -f ./src/*.o $(EXECUTABLE) *.txt

install:
	sudo install $(EXECUTABLE) $(INSTPATH)

uninstall:
	sudo rm $(INSTPATH)/$(EXECUTABLE)

run:
	$(INSTPATH)/$(EXECUTABLE)
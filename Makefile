# $@ Имя цели обрабатываемого правила
# $< Имя первой зависимости обрабатываемого правила
# $^ Список всех зависимостей обрабатываемого правила

C_SOURCES = $(wildcard kernel/*.c drivers/*.c cpu/*.c libc/*.c memory/*.c)
HEADERS = $(wildcard inc/*.h)
# Nice syntax for file extension replacement
# OBJ = ${C_SOURCES:.c=.o cpu/interrupt.o}

CC = gcc
GDB = gdb

CFLAGS = -g
main: sniffer.o main.o
	${CC} ${CFLAGS} -o main -c sniffer.o main.o
# Generic rules for wildcards
# To make an object, always compile from its .c
sniffer.o: sniffer.c sniffer.h
	${CC} ${CFLAGS} -c $< -o $@

main.o: main.c sniffer.h
	${CC} ${CFLAGS} -c $< -o $@

#%.o: %.c ${HEADERS}
#	${CC} ${CFLAGS} -c $< -o $@

clean:
	rm -rf *.bin *.dis *.o os-image.bin *.elf
	rm -rf inc/*.o src/*.o
#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

#define BUF_SIZE 8192

extern FILE* logfile;
extern int tcp;
extern int udp;
extern int icmp;
extern int others;
extern int igmp;
extern int total;

void print_data(unsigned char *buffer, int size);
void print_ip_header(unsigned char *buffer, int size);
void print_tcp_packet(unsigned char *buffer, int size);
void print_udp_packet(unsigned char *buffer, int size);
void print_icmp_packet(unsigned char *buffer, int size);
void package_processing(unsigned char *buffer, int size);

#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/filter.h>
#include <sys/ioctl.h> 
#include <string.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

void package_processing(unsigned char* buffer, int size);
void print_ip_header(unsigned char* buffer, int size);
void print_tcp_packet(unsigned char* buffer, int size);
void print_udp_packet(unsigned char * buffer, int size);
void print_icmp_packet(unsigned char* buffer, int size);
void print_data(unsigned char* buffer, int size);

FILE* logfile = NULL;

int main(int argc, char** argv)
{
	int raw_sock = 0;
	int data_size = 0;
	char* buffer = (char*) malloc(65536);
	raw_sock = socket(AF_INET, SOCK_RAW, htons(ETH_P_ALL));

	if (raw_sock == -1) {
		perror("Error: create socket\n");
		exit(EXIT_FAILURE);
	}

	logfile = fopen("log.txt", "w");
	if (logfile == NULL)
		printf("Unable to create file.\n");

	printf("Starting...\n");

	while (1) {
		data_size = recvfrom(raw_sock, buffer, 65536, 0, NULL, NULL);

		if (data_size < 0) {
			printf("Recvfrom error, failed to get packets\n");
			exit(EXIT_FAILURE);
		}

		package_processing(buffer);
	}

	close(raw_sock);
	printf("Finished\n");

	return 0;
}
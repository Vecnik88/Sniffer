#include "../inc/sniffer.h"

int main(int argc, char** argv)
{
	int raw_sock = 0;
	int data_size = 0;
	char* buffer = (char*) malloc(BUF_SIZE);

	if (buffer == NULL) {
		printf("Error allocate memory\n");
		exit(EXIT_FAILURE); 
	}

	raw_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (raw_sock == -1) {
		perror("Error: create socket\n");
		exit(EXIT_FAILURE);
	}

	logfile = fopen("log.txt", "w");
	if (logfile == NULL)
		printf("Unable to create file.\n");

	printf("Starting...\n");

	while (1) {
		data_size = recvfrom(raw_sock, buffer, BUF_SIZE, 0, NULL, NULL);

		if (data_size < 0) {
			printf("Recvfrom error, failed to get packets\n");
			exit(EXIT_FAILURE);
		}

		package_processing(buffer + sizeof(struct ethhdr), data_size);
	}

	close(raw_sock);
	printf("Finished\n");

	return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef WIN32
	#include <windows.h>
	#include <winsock.h>
	#include <sodium.h>
	#include <sodium/crypto_box.h>

	#pragma comment(lib, "wsock32.lib")
	#pragma comment(lib, "libsodium.lib")

	typedef int socklen_t;
#else
	#include <unistd.h>
	#include <fcntl.h>
	#include <dlfcn.h>
	#include <sys/select.h>
	#include <sys/types.h>
	#include <sys/time.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#define closesocket close

	typedef	int SOCKET;
	#define SOCKET_ERROR	-1
	#define INVALID_SOCKET	-1

	#include "crypto_box.h"
#endif



extern "C" {
	void randombytes(unsigned char *x,unsigned long long xlen);
}

#define MAX(x,y) (x) > (y) ? (x) : (y)
#define MIN(x,y) (x) < (y) ? (x) : (y)

char *get_file(char *filename, unsigned int *size)
{
	FILE	*file;
	char	*buffer;
	int	file_size, bytes_read;
	
	file = fopen(filename, "rb");
	if (file == NULL)
		return 0;
	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	buffer = new char [file_size + 1];
	bytes_read = (int)fread(buffer, sizeof(char), file_size, file);
	if (bytes_read != file_size)
	{
		delete [] buffer;
		fclose(file);
		return 0;
	}
	fclose(file);
	buffer[file_size] = '\0';

	if (size != NULL)
	{
		*size = file_size;
	}

	return buffer;
}

int nacl_encrypt(unsigned char *private_key, unsigned char *public_key, unsigned char *data, unsigned int data_size, unsigned char *&ciphertext, unsigned int &ciphertext_len, unsigned char *nonce)
{
	// Init N once with random data
	randombytes(nonce, 24);

	unsigned int size = 0;

	char *message = (char *)malloc(data_size + crypto_box_ZEROBYTES);
	if (message == NULL)
	{
		perror("malloc failed");
		return -1;
	}

	ciphertext = (unsigned char *)malloc(data_size + crypto_box_ZEROBYTES);
	if (ciphertext == NULL)
	{
		perror("malloc failed");
		return -1;
	}

	printf("nonce: ");
	for(int i = 0; i < 24; i++)
	{
		printf("%02X", nonce[i]);
	}
	printf("\n");

	memset(message, 0, data_size + crypto_box_ZEROBYTES);
	// NaCl has a stupid zero byte front padding crypto_box_ZEROBYTES
	memcpy(&message[crypto_box_ZEROBYTES], data, data_size);

	// cipher length same as message length
	unsigned int mlen = data_size + crypto_box_ZEROBYTES;
	ciphertext_len = mlen;

	// magic encrypt function Curve25519, Salsa20, and Poly1305
	int ret = crypto_box(ciphertext, (unsigned char *)message, ciphertext_len, nonce, public_key, private_key);
	if (ret == -1)
	{
		printf("crypto_box failed\r\n");
		return -1;
	}

	free((void *)message);

	return 0;
}

int nacl_file_upload(char *file, unsigned short port, unsigned char *private_key, unsigned char *public_key)
{
	int			connfd;
	unsigned int		size = sizeof(struct sockaddr_in);
	struct sockaddr_in	servaddr, client;
	time_t			ticks;
	int listenfd;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1)
	{
		perror("socket error");
		return -1;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if ((::bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) == -1)
	{
		perror("bind error");
		return 0;
	}

	printf("Server listening on: %s:%d\n", inet_ntoa(servaddr.sin_addr), htons(servaddr.sin_port));

	if (listen(listenfd, 3) == -1)
	{
		perror("listen error");
		return -1;
	}

	for (;;)
	{
		char response[1024] = { 0 };
		unsigned char nonce[crypto_box_NONCEBYTES] = {0};
		unsigned char *ciphertext = NULL;
		unsigned int ciphertext_len = 0;

		printf("listening for connections...\n");
		connfd = accept(listenfd, (struct sockaddr *)&client, (socklen_t *)&size);
		if (connfd == INVALID_SOCKET)
			continue;

		ticks = time(NULL);
		snprintf(response, sizeof(response), "%.24s\r\n", ctime(&ticks));
		printf("Client: %s - %s\r\n", inet_ntoa(client.sin_addr), response);

		unsigned int file_size = 0;
		unsigned char *data = (unsigned char *)get_file(file, &file_size);
		if (data == NULL)
		{
			printf("Error: could not open file %s\r\n", file);
			continue;
		}

		printf("Opened file %s size %d bytes\r\n", file, file_size);

		char file_name[128] = { 0 };

		printf("Performing encryptions\r\n");
		nacl_encrypt(private_key, public_key, data, file_size, ciphertext, ciphertext_len, nonce);

		printf("Encrypted size %d\r\n", ciphertext_len);

		delete[] data;
		printf("Encryption complete, sending file\r\n");
		memcpy(file_name, file, MIN(127, strlen(file)));
		send(connfd, (char *)&ciphertext_len, sizeof(int), 0);
		send(connfd, (char *)&file_name, 128, 0);
		send(connfd, (char *)&file_size, sizeof(int), 0);
		send(connfd, (char *)&nonce, 24, 0);
		send(connfd, (char *)ciphertext, ciphertext_len, 0);
		closesocket(connfd);

		printf("Ciphertext: ");
		for (int i = 0; i < ciphertext_len; i++)
		{
			printf("%02X", ciphertext[i]);
		}
		printf("\n");
		free((void *)ciphertext);

	}
	return 0;
}




int main(int argc, char *argv[])
{
	unsigned short port = 65535;

	if (argc < 5)
	{
		printf("Usage: nacl_upload filename port private_key public_key\r\n");
		printf("Example: nacl_upload file.tgz 65535 private_key public_key\r\n");
		return 0;
	}

#ifdef _WIN32
	WSADATA		WSAData;

	WSAStartup(MAKEWORD(2, 0), &WSAData);
#endif


	port = atoi(argv[2]);

	unsigned int private_size = 0;
	unsigned char *private_key = (unsigned char *)get_file(argv[3], &private_size);
	if (private_key == NULL)
	{
		printf("Failed to open %s\r\n", argv[3]);
		return -1;
	}

	unsigned int public_size = 0;
	unsigned char *public_key = (unsigned char *)get_file(argv[4], &public_size);
	if (public_key == NULL)
	{
		printf("Failed to open %s\r\n", argv[4]);
		return -1;
	}

	printf("public_key: ");
	for (int i = 0; i < public_size; i++)
	{
		printf("%02X", public_key[i]);
	}
	printf("\n");

	printf("private_key: ");
	for (int i = 0; i < private_size; i++)
	{
		printf("%02X", private_key[i]);
	}
	printf("\n");



	printf("Attempting to upload %s to client connecting on port %d\r\n", argv[1], (int)port);
	nacl_file_upload(argv[1], port, private_key, public_key);

	return 0;
}


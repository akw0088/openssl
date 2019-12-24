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

#define SIZE_PATH 128

#define MAX(x,y) (x) > (y) ? (x) : (y)
#define MIN(x,y) (x) < (y) ? (x) : (y)


extern "C" {
	void randombytes(unsigned char *x,unsigned long long xlen);
}


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
	randombytes(nonce, crypto_box_NONCEBYTES);

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
	for(int i = 0; i < crypto_box_NONCEBYTES; i++)
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

int nacl_file_upload_reverse(char *file, char *ip_str, unsigned short port, unsigned char *private_key, unsigned char *public_key)
{
	struct sockaddr_in	servaddr;
	SOCKET sock;
	int ret;


	unsigned int file_size = 0;
	unsigned char *data = (unsigned char *)get_file(file, &file_size);
	if (data == NULL)
	{
		printf("Error: could not open file %s\r\n", file);
		return -1;
	}
	printf("Opened file %s size %d bytes\r\n", file, file_size);

	char file_name[SIZE_PATH] = { 0 };

	unsigned char *ciphertext = NULL;
	unsigned int ciphertext_len = 0;

	printf("Performing encryptions\r\n");
	unsigned char nonce[crypto_box_NONCEBYTES] = { 0 };

	randombytes(nonce, crypto_box_NONCEBYTES);

	nacl_encrypt(private_key, public_key, data, file_size, ciphertext, ciphertext_len, nonce);
	printf("Encrypted size %d\r\n", ciphertext_len);
	printf("Encryption complete, connecting to server\r\n");
	delete[] data;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(ip_str);
	servaddr.sin_port = htons(port);

	// 3 way handshake
	printf("Attempting to connect to %s\n", ip_str);
	ret = connect(sock, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in));
	if (ret == SOCKET_ERROR)
	{
#ifdef _WIN32
		ret = WSAGetLastError();

		switch (ret)
		{
		case WSAETIMEDOUT:
			printf("Fatal Error: Connection timed out.\n");
			break;
		case WSAECONNREFUSED:
			printf("Fatal Error: Connection refused\n");
			break;
		case WSAEHOSTUNREACH:
			printf("Fatal Error: Router sent ICMP packet (destination unreachable)\n");
			break;
		default:
			printf("Fatal Error: %d\n", ret);
			break;
		}
#else
		ret = errno;

	        switch(ret)
	        {
		case ENETUNREACH:
			printf("Fatal Error: The network is unreachable from this host at this time.\n(Bad IP address)\n");
			break;
	        case ETIMEDOUT:
	                printf("Fatal Error: Connecting timed out.\n");
	                break;
	        case ECONNREFUSED:
	                printf("Fatal Error: Connection refused\n");
	                break;
	        case EHOSTUNREACH:
	                printf("Fatal Error: router sent ICMP packet (destination unreachable)\n");
	                break;
	        default:
	                printf("Fatal Error: %d\n", ret);
	                break;
	        }
#endif
		return -1;
	}
	printf("TCP handshake completed\n");

	unsigned int magic = 0xF0F0F0F0;

	memcpy(file_name, file, MIN(SIZE_PATH - 1, strlen(file)));
	send(sock, (char *)&magic, sizeof(int), 0);
	send(sock, (char *)&ciphertext_len, sizeof(int), 0);
	send(sock, (char *)&file_name, SIZE_PATH, 0);
	send(sock, (char *)&file_size, sizeof(int), 0);
	send(sock, (char *)&nonce, crypto_box_NONCEBYTES, 0);
	send(sock, (char *)ciphertext, ciphertext_len, 0);
	closesocket(sock);
	free((void *)ciphertext);

	return 0;
}




int main(int argc, char *argv[])
{
	if (argc < 6)
	{
		printf("Usage: nacl_upload filename ip port private_key public_key\r\n");
		printf("Example: nacl_upload file.tgz ip 65535 private_key public_key\r\n");
		return 0;
	}

#ifdef _WIN32
	WSADATA		WSAData;

	WSAStartup(MAKEWORD(2, 0), &WSAData);
#endif

	unsigned short port = atoi(argv[3]);

	unsigned int private_size = 0;
	unsigned char *private_key = (unsigned char *)get_file(argv[4], &private_size);
	if (private_key == NULL)
	{
		printf("Failed to open %s\r\n", argv[3]);
		return -1;
	}

	unsigned int public_size = 0;
	unsigned char *public_key = (unsigned char *)get_file(argv[5], &public_size);
	if (public_key == NULL)
	{
		printf("Failed to open %s\r\n", argv[4]);
		return -1;
	}


	char *ip_str = argv[2];

	printf("Attempting to upload %s to ip %s port %d\r\n", argv[1], ip_str, (int)port);
	nacl_file_upload_reverse(argv[1], ip_str, port, private_key, public_key);

	return 0;
}


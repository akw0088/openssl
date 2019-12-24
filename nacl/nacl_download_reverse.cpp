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





#define MAX(x,y) (x) > (y) ? (x) : (y)
#define MIN(x,y) (x) < (y) ? (x) : (y)

int decrypt_download(char *file_name, unsigned char *nonce, char *response, int download_size, unsigned char *private_key, unsigned char *public_key, unsigned int max_malloc_size);

void StripChars(const char *in, char *out, char *stripc)
{
    while (*in)
    {
    	bool flag = false;

	int length = strlen(stripc);
    	for(int i = 0; i < length; i++)
	{
		if (*in == stripc[i])
		{
			flag = true;
			break;
		}
	}

	if (flag)
	{
		in++;
		continue;
	}
        *out++ = *in++;
    }
    *out = 0;
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

int write_file(char *filename, const char *bytes, int size)
{
    FILE *fp = fopen(filename, "wb");
    int ret;
    
    if (fp == NULL)
    {
        perror("Unable to open file for writing");
        return -1;
    }
    
    ret = fwrite(bytes, sizeof(char), size, fp);
    
    if (ret != size)
    {
        printf("fwrite didnt write all data\n");
	fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int nacl_file_download_reverse(unsigned short int port, unsigned char *private_key, unsigned char *public_key, int max_malloc_size)
{
	int			connfd;
	unsigned int		socklen = sizeof(struct sockaddr_in);
	struct sockaddr_in	servaddr, client;
	time_t			ticks;
	int listenfd;

#ifdef _WIN32
	WSADATA		WSAData;

	WSAStartup(MAKEWORD(2, 0), &WSAData);
#endif

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

	printf("Allocating %d bytes\r\n", max_malloc_size);
	char *response = (char *)malloc(max_malloc_size);
	if (response == NULL)
	{
		perror("malloc failed");
		return -1;
	}


	for (;;)
	{
		unsigned int final_size = 0;
		unsigned char nonce[25] = {0};
		unsigned char encrypted_key[256] = {0};
		unsigned int download_size = 0;
		char file_name[128] = {0};




		printf("listening for connections...\n");
		connfd = accept(listenfd, (struct sockaddr *)&client, (socklen_t *)&socklen);
		if (connfd == INVALID_SOCKET)
			continue;

		printf("Client: %s\r\n", inet_ntoa(client.sin_addr));

		int expected_size = 0;
		int magic = 0;
		recv(connfd, (char *)&magic, 4, 0);

		if (magic != 0xF0F0F0F0)
		{
			closesocket(connfd);
			continue;
		}

		printf("Client passed magic cookie %X: Downloading\r\n", magic);

		recv(connfd, (char *)&expected_size, 4, 0);
		recv(connfd, (char *)file_name, 128, 0);
		recv(connfd, (char *)&final_size, 4, 0);
		recv(connfd, (char *)nonce, 24, 0);

		while (download_size < expected_size)
		{
			download_size += recv(connfd, &response[download_size], expected_size - download_size, 0);
		}

		if (download_size != expected_size)
		{
			printf("expected %d bytes, got only %d bytes\r\n", expected_size, download_size);
		}
		closesocket(connfd);
		decrypt_download(file_name, nonce, response, download_size, private_key, public_key, max_malloc_size);
		expected_size = 0;
		memset(file_name, 0, 128);
		final_size = 0;
		memset(nonce, 0, 25);

	}
	return 0;
}





int decrypt_download(char *file_name, unsigned char *nonce, char *response, int download_size, unsigned char *private_key, unsigned char *public_key, unsigned int max_malloc_size)
{
	if (download_size == 0)
	{
		printf("Download failed\r\n");
		return 0;
	}

	printf("Download complete\r\n");
	printf("Got %d bytes file name %s\r\n", download_size, file_name);


	char new_filename[256] = {0};
	char strip_filename[256] = {0};

	StripChars(file_name, strip_filename, ".\\/;:*?\"<>|");

	printf("Attempting to decrypt\r\n");
	// cipher length same as message length
	unsigned int clen = download_size;

	printf("Allocating %d bytes\r\n", max_malloc_size);
	char *plaintext = (char *)malloc(max_malloc_size);
	if (plaintext == NULL)
	{
		perror("malloc failed");
		return -1;
	}

	memset(plaintext, 0, max_malloc_size);

	// The open function also needs zero padding on ciphertext of crypto_box_BOXZEROBYTES
	// should already be padded from crypto_box
	int ret = crypto_box_open((unsigned char *)plaintext, (unsigned char *)response, clen, nonce, public_key, private_key);
	if (ret == -1)
	{
		free((void *)response);
		free((void *)plaintext);
		delete[] private_key;
		delete[] public_key;
		printf("crypto_box_open failed\r\n");
		return -1;
	}
	printf("Decryption Complete\r\n");
	printf("Saving as file name %s\r\n", new_filename);
	write_file(new_filename, &plaintext[crypto_box_ZEROBYTES], clen - crypto_box_ZEROBYTES);



	return 0;
}

int main(int argc, char *argv[])
{
	unsigned short port = 65535;
	unsigned int max_malloc_size = 0;

	if (argc < 5)
	{
		printf("Usage: nacl_download_reverse port max_size private_key public_key\r\n");
		printf("Example: ./nacl_download_reverse 65535 536870912 nacl.private nacl.public\r\n");
		return 0;
	}

#ifdef _WIN32
	WSADATA		WSAData;

	WSAStartup(MAKEWORD(2, 0), &WSAData);
#endif


	port = atoi(argv[1]);
	max_malloc_size = atoi(argv[2]);

	unsigned int private_size = 0;
	unsigned char *private_key = (unsigned char *)get_file(argv[3], &private_size);
	if (private_key == NULL)
	{
		printf("Failed to open private key\r\n");
		return -1;
	}

	unsigned int public_size = 0;
	unsigned char *public_key = (unsigned char *)get_file(argv[4], &public_size);
	if (public_key == NULL)
	{
		printf("Failed to open public key\r\n");
		return -1;
	}

	printf("Waiting for download file on port %d\r\n", (int)port);
	int ret = nacl_file_download_reverse(port, private_key, public_key, max_malloc_size);

	return 0;
}
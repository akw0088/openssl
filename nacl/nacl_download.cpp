#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef WIN32
	#include <windows.h>
	#include <winsock.h>

	#pragma comment(lib, "wsock32.lib")

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
#endif



#include "crypto_box.h"


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

int nacl_file_download(char *ip_str, unsigned short int port, unsigned char *response, int size, unsigned int *download_size, char *file_name, unsigned int &final_size, unsigned char *nonce)
{
	struct sockaddr_in	servaddr;
	SOCKET sock;
	int ret;

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

	memset(response, 0, size);

	int expected_size = 0;
	recv(sock, (char *)&expected_size, 4, 0);
	recv(sock, (char *)file_name, 128, 0);
	recv(sock, (char *)&final_size, 4, 0);
	recv(sock, (char *)nonce, 24, 0);

	while (*download_size < expected_size)
	{
		*download_size += recv(sock, &response[*download_size], expected_size - *download_size, 0);
	}
	closesocket(sock);
	return 0;
}

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


int main(int argc, char *argv[])
{
	unsigned short port = 65535;
	unsigned int size = 0;
	unsigned char nonce[24] = {0};

	if (argc < 5)
	{
		printf("Usage: nacl_download ip port max_size pubkey prikey\r\n");
		printf("Example: ./nacl_download 127.0.0.1 65535 536870912 nacl.public nacl.private\r\n");
		return 0;
	}

	port = atoi(argv[2]);
	size = atoi(argv[3]);

	unsigned int pubkey_size = 0;
	unsigned char *public_key = (unsigned char *)get_file(argv[4], &pubkey_size);
	if (public_key == NULL)
	{
		printf("Failed to open public key\r\n");
		return -1;
	}

	unsigned int prikey_size = 0;
	unsigned char *private_key = (unsigned char *)get_file(argv[5], &prikey_size);
	if (private_key == NULL)
	{
		printf("Failed to open private key\r\n");
		return -1;
	}

	printf("Allocating %d bytes\r\n", size);
	unsigned char *response = (unsigned char *)malloc(size);
	if (response == NULL)
	{
		perror("malloc failed");
		return -1;
	}

	unsigned int download_size = 0;
	unsigned int final_size = 0;
	char file_name[128] = {0};

	printf("Attempting to download file from ip %s port %d\r\n", argv[1], (int)port);
	int ret = nacl_file_download(argv[1], port, response, size, &download_size, file_name, final_size, nonce);
	if (ret != 0 || download_size == 0)
	{
		printf("Download failed\r\n");
		return 0;
	}

	printf("Download complete\r\n");
	printf("Got %d bytes file name %s\r\n", download_size, file_name);
	printf("nonce: ");
	for(int i = 0; i < 24; i++)
	{
		printf("%02X", nonce[i]);
	}
	printf("\n");


	char new_filename[256] = {0};
	char strip_filename[256] = {0};

	StripChars(file_name, strip_filename, ".\\/;:*?\"<>|");

	sprintf(new_filename, "downloaded_%s_unencrypted", strip_filename);
	printf("Attempting to decrypt\r\n");

	// cipher length same as message length
	unsigned int clen = download_size;
	char *plaintext = (char *)malloc(size);
	if (plaintext == NULL)
	{
		perror("malloc failed");
		return -1; 
	}

	printf("Allocating %d bytes\r\n", size);


	// The open function also needs zero padding on ciphertext of crypto_box_BOXZEROBYTES
	// should already be padded from crypto_box
	ret = crypto_box_open((unsigned char *)plaintext, (unsigned char *)response, clen, nonce, public_key, private_key);
	if (ret == -1)
	{
		free((void *)response);
		free((void *)plaintext);
		delete [] private_key;
		delete [] public_key;
		printf("crypto_box_open failed\r\n");
		return -1;
	}

	printf("Saving as file name %s\r\n", new_filename);
	write_file(new_filename, &plaintext[crypto_box_ZEROBYTES], clen - crypto_box_ZEROBYTES);

	free((void *)response);
	free((void *)plaintext);
	delete [] private_key;
	delete [] public_key;

	return 0;
}


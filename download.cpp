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

int file_download(char *ip_str, unsigned short int port, char *response, int size, unsigned int *download_size, char *file_name)
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

	while (*download_size < expected_size)
	{
		*download_size += recv(sock, &response[*download_size], expected_size - *download_size, 0);
	}
	closesocket(sock);
	return 0;
}

int file_upload(char *file, unsigned short port)
{
	int			connfd;
	unsigned int		size = sizeof(struct sockaddr_in);
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

	for (;;)
	{
		char response[1024] = { 0 };

		printf("listening for connections...\n");
		connfd = accept(listenfd, (struct sockaddr *)&client, (socklen_t *)&size);
		if (connfd == INVALID_SOCKET)
			continue;

		ticks = time(NULL);
		snprintf(response, sizeof(response), "%.24s\r\n", ctime(&ticks));
		printf("Client: %s - %s", inet_ntoa(client.sin_addr), response);

		unsigned int file_size = 0;
		char *data = get_file(file, &file_size);
		char file_name[128] = { 0 };

		memcpy(file_name, file, MIN(127, strlen(file)));
		send(connfd, (char *)&file_size, sizeof(int), 0);
		send(connfd, (char *)&file_name, 128, 0);
		send(connfd, data, file_size, 0);
		closesocket(connfd);
	}
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

	if (argc < 4)
	{
		printf("Usage: download ip port max_size\r\n");
		return 0;
	}

	port = atoi(argv[2]);
	size = atoi(argv[3]);

	printf("Allocating %d bytes\r\n", size);
	char *response = (char *)malloc(size);
	if (response == NULL)
	{
		perror("malloc failed");
	}

	unsigned int download_size = 0;
	char file_name[128] = {0};

	printf("Attempting to download file from ip %s port %d\r\n", argv[1], (int)port);
	int ret = file_download(argv[1], port, response, size, &download_size, file_name);
	if (ret != 0)
	{
		printf("Download failed\r\n");
		return 0;
	}

	printf("Download complete\r\n");
	printf("Got %d bytes file name %s\r\n", download_size, file_name);

	char new_filename[256] = {0};
	char strip_filename[256] = {0};

	StripChars(file_name, strip_filename, (char *)".\\/;:*?\"<>|");

	sprintf(new_filename, "downloaded_%s", strip_filename);
	printf("Saving as file name %s\r\n", new_filename);
	write_file(new_filename, response, download_size);
	return 0;
}

#include <stdio.h>
#include <stdint.h>
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

#define BLOCK_SIZE (1024 * 1024)

#define MAX(x,y) (x) > (y) ? (x) : (y)
#define MIN(x,y) (x) < (y) ? (x) : (y)

#define MOD_ADLER 65521

//    Adler-32 checksum is obtained by calculating two 16-bit checksums A and B and concatenating their bits into a 32-bit integer.
// A is the sum of all bytes in the stream plus one, and B is the sum of the individual values of A from each step.
// At the beginning of an Adler-32 run, A is initialized to 1, B to 0. The sums are done modulo 65521 
unsigned int adler32(unsigned char *buf, unsigned int length)
{
	unsigned short a = 1;
	unsigned short b = 0;

	for(int i = 0; i < length; i++)
	{
	        a = (a + buf[i]) % MOD_ADLER;
	        b = (b + a) % MOD_ADLER;
	}

	return (b << 16) | a;
}


// Rolling checksum for Rsync -- note this is failing to match above after some shifts, not sure whats up
unsigned int adler32_roll(unsigned int adler, unsigned char buf_in, unsigned char buf_out, unsigned int block_size)
{
	unsigned short a = adler & 0xFFFF;
	unsigned short b = (adler >> 16) & 0xFFFF;

	// remove old byte, add new byte
	a = (a - buf_out + buf_in) % MOD_ADLER;

	// add new a, remove old a
	b = (b - (block_size * buf_out) + a - 1) % MOD_ADLER;

	return (b << 16) | a;
}

int adler32_scan(unsigned char *data, int length, int block_size, unsigned int *hash_array, int num_hash, int *offset_array)
{
	if (block_size > length)
	{
		printf("Block size larger than file\r\n");
		return -1;
	}
	
	unsigned int checksum = 0;
	unsigned int initial_found = 0;

	checksum = adler32(&data[0], block_size);
	
	for (int i = 0; i < num_hash; i++)
	{
		offset_array[i] = -1;
		if (checksum == hash_array[i])
		{
			printf("offset %d matches %08X\r\n", 0, checksum);
			offset_array[i] = 0;
			initial_found = 1;
		}
	}

	for(int i = 1; i < length - block_size + 1; i++)
	{
		if (initial_found)
		{
			initial_found = 0;
			i = block_size - 1;
			continue;
		}
		checksum = adler32_roll(checksum,
			data[i + block_size - 1],
			data[i - 1],
			block_size);
			
		unsigned int full_hash = adler32(&data[i], block_size);
		checksum = full_hash;
//		printf("adler32 %d %d\r\n", i, block_size);
//		printf("Searching for hashes pos %d hash %08X size %d fullhash %08X match %d\r\n", i, checksum, block_size, full_hash, checksum == full_hash);
		for (int j = 0; j < num_hash; j++)
		{
			if (checksum == hash_array[j])
			{
				printf("offset %d matches %08X block %d\r\n", i, checksum, j);
				offset_array[j] = i;
				i += block_size - 1;
				break;
			}
		}

		if (checksum != full_hash)
		{
			printf("adler32_roll failed\r\n");
			exit(0);
		}
//		sleep(1);

	}
	printf("block_size %d\r\n", block_size);
	return -1;
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
	buffer = (char *)malloc(file_size + 1);
	bytes_read = (int)fread(buffer, sizeof(char), file_size, file);
	if (bytes_read != file_size)
	{
		free((void *)buffer);
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

int rsync_file_download(char *ip_str, unsigned short int port, char *response, int size, unsigned int *download_size, char *file_name)
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

	unsigned int rnum_block = 0;
	int expected_size = 0;
	recv(sock, (char *)&expected_size, 4, 0);
	recv(sock, (char *)file_name, 128, 0);


	printf("Opening local %s file for local block check\r\n", file_name);
	unsigned int file_size = 0;
	char *data = get_file(file_name, &file_size);
	if (data == NULL)
	{
		printf("Unable to open %s\r\n", file_name);
		return -1;
	}

	int block_size = BLOCK_SIZE;
	int num_block = file_size / block_size;
	
	if (file_size % block_size != 0)
	{
		num_block++;
	}

	printf("File has %d blocks %d bytes\r\n", num_block, file_size);

	unsigned int *checksum_array = (unsigned int *)malloc(num_block * sizeof(unsigned int));

	printf("Calculating adler32 for each block\r\n");
	for(int i = 0; i < num_block; i++)
	{
		unsigned int rsize = block_size;

		if (i == num_block - 1)
		{
			rsize = file_size - block_size * i;
		}

		checksum_array[i] = adler32((unsigned char *)&data[block_size * i], rsize);
		printf("Block %d has checksum %08X rsize %d\r\n", i, checksum_array[i], rsize);
		printf("adler32 %d %d\r\n", block_size * i, rsize);
	}

	
	printf("Sending block sums to server\r\n");	
	unsigned int *block_offset = (unsigned int *)malloc(num_block * sizeof(unsigned int));

	send(sock, (char *)&num_block, sizeof(int), 0);
	send(sock, (char *)checksum_array, num_block * sizeof(int), 0);
	recv(sock, (char *)&block_offset[0], sizeof(unsigned int) * num_block, 0);

	printf("Got offsets for each block\r\n");
	unsigned int diff_size = 0;
	recv(sock, (char *)&diff_size, 4, 0);

	printf("Delta size is %d bytes\r\n", diff_size);

	unsigned char *diff = malloc(diff_size);	
	*download_size = 0;
	while (*download_size < diff_size)
	{
		*download_size += recv(sock, &diff[*download_size], diff_size - *download_size, 0);
	}
	printf("Downloaded delta\r\n");
	closesocket(sock);
	exit(0);
	return 0;
}

int rsync_file_upload(char *file, unsigned short port)
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

	if ((bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) == -1)
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
		if (data == NULL)
		{
			printf("Unable to open %s\r\n", file);
			return -1;
		}

		char file_name[128] = { 0 };
		int block_size = BLOCK_SIZE;

		unsigned int rnum_block = 0;
		memcpy(file_name, file, MIN(127, strlen(file)));
		send(connfd, (char *)&file_size, sizeof(int), 0);
		send(connfd, (char *)&file_name, 128, 0);
		recv(connfd, (char *)&rnum_block, sizeof(int), 0);

		printf("Received %d checksum array from client\r\n", rnum_block);
		unsigned int *rchecksum_array = (unsigned int *)malloc(rnum_block * sizeof(int));
		if (rchecksum_array == NULL)
		{
			perror("malloc failed");
			exit(0);
		}


		recv(connfd, (char *)rchecksum_array, rnum_block * sizeof(int), 0);


		unsigned int *block_offset = malloc(sizeof(unsigned int) * rnum_block);
		if (block_offset == NULL)
		{
			perror("malloc failed");
			exit(0);
		}
		printf("Searching for matches in %d blocks\r\n", rnum_block);
		
		memset(block_offset, 0, sizeof(unsigned int) * rnum_block);

		unsigned int rsize = block_size;
		int ret = adler32_scan(&data[0], file_size, rsize, rchecksum_array, rnum_block - 1, block_offset);
		// last block is smaller than full block, needs another scan
		rsize = file_size - block_size * (rnum_block - 1);
		adler32_scan(&data[0], file_size, rsize, &rchecksum_array[rnum_block - 1], 1, &block_offset[rnum_block - 1]);
		printf("Sending block offsets\r\n");
		send(connfd, block_offset, rnum_block * sizeof(unsigned int), 0);

		// Remote side now knows where it's blocks go in new file
		// going to send all bytes in order of whats left starting from 0 and skipping whats in the block report
		
		printf("Determining data client is missing\r\n");
		unsigned char *send_file = malloc(file_size);
		int send_file_pos = 0;
		for(int i = 0; i < file_size; i++)
		{
			int skip = 0;

			for(int j = 0; j < rnum_block; j++)
			{
				if ( i >= block_offset[j] && i < block_offset[j] + block_size )
				{
					// we are in this block, skip to the end of this block
					i = block_offset[j] + block_size;
					skip = 1;
					break;
				}
			}
			
			if (skip)
			{
				// restart again as we move passed a block
				i--;
				continue;
			}
			
			// This byte needs to be sent, move into transport block
			send_file[send_file_pos++] = data[i];
		}
		
		printf("Sending client missing chunk of size %d\r\n", send_file_pos);
		printf("Sending data\r\n");
		send(connfd, (char *)&send_file_pos, sizeof(unsigned int), 0);		
		send(connfd, (char *)send_file, send_file_pos, 0);
		closesocket(connfd);
	}
	return 0;
}

void StripChars(const char *in, char *out, char *stripc)
{
    while (*in)
    {
    	int flag = 0;

		int length = strlen(stripc);
		for(int i = 0; i < length; i++)
		{
			if (*in == stripc[i])
			{
				flag = 1;
				break;
			}
		}

		if (flag)
		{
			*in++;
			continue;
		}
        *out++ = *in++;
    }
    *out = 0;
}




int main(int argc, char *argv[])
{
	unsigned short port = 65535;
	unsigned int max_malloc_size = 0;

	if (argc < 4)
	{
		printf("Usage: rsync_download ip port max_size\r\n");
		return 0;
	}

	port = atoi(argv[2]);
	max_malloc_size = atoi(argv[3]);

	printf("Allocating %d bytes\r\n", max_malloc_size);
	char *response = (char *)malloc(max_malloc_size);
	if (response == NULL)
	{
		perror("malloc failed");
	}

	unsigned int download_size = 0;
	char file_name[128] = {0};

	printf("Attempting to download file from ip %s port %d\r\n", argv[1], (int)port);
	int ret = rsync_file_download(argv[1], port, response, max_malloc_size, &download_size, file_name);
	if (ret != 0)
	{
		printf("Download failed\r\n");
		return 0;
	}

	printf("Download complete\r\n");
	printf("Got %d bytes file name %s\r\n", download_size, file_name);

	char new_filename[256] = {0};
	char strip_filename[256] = {0};

	StripChars(file_name, strip_filename, ".\\/;:*?\"<>|");

	sprintf(new_filename, "downloaded_%s", strip_filename);
	printf("Saving as file name %s\r\n", new_filename);
	write_file(new_filename, response, download_size);
	return 0;
}

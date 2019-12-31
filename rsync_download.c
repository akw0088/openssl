#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "md5sum.h"

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
#define PATH_SIZE 128
#define MD5_SIZE 32
#define MAX(x,y) (x) > (y) ? (x) : (y)
#define MIN(x,y) (x) < (y) ? (x) : (y)

#define MOD_ADLER 65521

typedef struct
{
	unsigned int offset;
	unsigned int length;
} block_t;

void md5sum(char *data, unsigned int size, char *hash);
void StripChars(const char *in, char *out, char *stripc);

//    Adler-32 checksum is obtained by calculating two 16-bit checksums A and B and concatenating their bits into a 32-bit integer.
// A is the sum of all bytes in the stream plus one, and B is the sum of the individual values of A from each step.
// At the beginning of an Adler-32 run, A is initialized to 1, B to 0. The sums are done modulo 65521 
unsigned int adler32(unsigned char *data, unsigned int len)
{
	unsigned short a = 1, b = 0;
	unsigned int i;

	// Process each byte of the data in order
	for (i = 0; i < len; i++)
	{
		a = (a + data[i]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}

	return (b << 16) | a;
}



// Rolling checksum for Rsync
unsigned int adler32_roll(unsigned int adler, unsigned char buf_in, unsigned char buf_out, unsigned int block_size)
{
	unsigned int a = adler & 0xFFFF;
	unsigned int b = adler >> 16;

	int a32 = (a + buf_in - buf_out);
	while (a32 < 0)
	{
		a32 += MOD_ADLER;
	}
	a = a32 % MOD_ADLER;

	int b32 = b + a - 1 - block_size * buf_out;
	while (b32 < 0)
	{
		b32 += MOD_ADLER;
	}
	b = b32 % MOD_ADLER;

	return (b << 16) | a;
}


int adler32_scan(unsigned char *data, unsigned int length, int block_size, unsigned int *hash_array, int num_hash, block_t *offset_array, char **md5_array)
{
	unsigned int start_offset = 1;
	if (block_size > length)
	{
		printf("Block size larger than file\r\n");
		return -1;
	}
	

	unsigned int checksum =   adler32(&data[0], block_size);

	for (int i = 0; i < num_hash; i++)
	{
		// init output
		offset_array[i].offset = -1;
		offset_array[i].length = block_size;
	}

	for (int i = 0; i < num_hash; i++)
	{
		if (checksum == hash_array[i])
		{
			printf("offset %d matches %08X\r\n", 0, checksum);
			char hash[33] = { 0 };
			//				printf("offset %d matches %08X block %d\r\n", i, checksum, j);
			//				printf("Performing strong hash\r\n");
			md5sum((char *)&data[i], block_size, (char *)&hash);

			if (strcmp(hash, md5_array[i]) == 0)
			{
				printf("offset %d matches %08X block %d with strong hash\r\n", i, checksum, i);
				offset_array[i].offset = 0;
				offset_array[i].length = block_size;
				start_offset = block_size - 1;
				checksum = adler32(&data[start_offset - 1], block_size);
				break;
			}
		}
	}

	for(unsigned int i = start_offset; i < length - block_size + 1; i++)
	{
		checksum = adler32_roll(checksum,
			data[i + block_size - 1],
			data[i - 1],
			block_size);
#ifdef DEBUG
		unsigned int full_hash = adler32(&data[i], block_size);
#endif
//		checksum = full_hash;
//		printf("adler32 %d %d\r\n", i, block_size);
//		printf("Searching for hashes pos %d hash %08X size %d fullhash %08X match %d\r\n", i, checksum, block_size, full_hash, checksum == full_hash);
		for (int j = 0; j < num_hash; j++)
		{
			if (checksum == hash_array[j])
			{
				char hash[33] = { 0 };
//				printf("offset %d matches %08X block %d\r\n", i, checksum, j);
//				printf("Performing strong hash\r\n");
				md5sum((char *)&data[i], block_size, (char *)&hash);

				if (strcmp(hash, md5_array[j]) == 0)
				{
					printf("offset %d matches %08X block %d with strong hash\r\n", i, checksum, j);
					offset_array[j].offset = i;
					offset_array[j].length = block_size;

					// skip the block length and recalc full adler
					i += block_size - 1;
					if (i < length - block_size + 1)
					{
						checksum = adler32(&data[i], block_size);
					}
				}
				break;
			}
		}

#ifdef DEBUG
		if (checksum != full_hash)
		{
			printf("adler32_roll failed at index %d\r\n", i);
			exit(0);
		}
#endif

	}
	return -1;
}


// Recv can return before recv'ing all data, causing your data to get shifted in rare occurances
int Recv(SOCKET sock, char *buffer, int size, int flag)
{
	int num_read = 0;

	while (num_read < size && num_read >= 0)
	{
		int ret = 0;

		ret = recv(sock, &buffer[num_read], size - num_read, flag);
		if (ret > 0)
		{
			num_read += ret;
			if (size > 8192)
			{
				printf("Recv %d of %d\r", num_read, size);
			}
		}
		else
		{
			return ret;
		}
	}
	if (size > 8192)
	{
		printf("\r\n");
	}
	return num_read;
}


// Normally send never fails as it just memcpy's into a send buffer, but just in case
int Send(SOCKET sock, char *buffer, int size, int flag)
{
	int num_sent = 0;

	while (num_sent < size && num_sent >= 0)
	{
		int ret = 0;

		ret = send(sock, &buffer[num_sent], size - num_sent, flag);
		if (ret > 0)
		{
			num_sent += ret;

			if (size > 8192)
			{
				printf("Sent %d of %d\r", num_sent, size);
			}
		}
		else
		{
			return ret;
		}
	}
	if (size > 8192)
	{
		printf("\r\n");
	}
	return num_sent;
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
		perror("fwrite didnt write all data");
		fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int assemble_download(char *response, unsigned int rfile_size, char *data, unsigned int file_size, block_t *block_offset, int num_block, unsigned int block_size, char *diff, unsigned int diff_size)
{
	unsigned int diff_pos = 0;

	memset(response, 0, rfile_size);
	for (int j = 0; j < num_block; j++)
	{
		if (block_offset[j].offset == -1)
		{
			printf("Filling block %d size %d with downloaded data\r\n", j, block_offset[j].length);
			memcpy(&response[j * block_size], &diff[diff_pos], block_offset[j].length);
			diff_pos += block_offset[j].length;
			printf("%d bytes left of download\r\n", diff_size - diff_pos);
			continue;
		}

		printf("Keeping block %d size %d\r\n", j, block_offset[j].length);
		memcpy(&response[j * block_size], &data[j * block_size], block_offset[j].length);
	}

	return 0;
}


int rsync_file_download(char *ip_str, unsigned short int port, char *response, int size, unsigned int *final_size, char *file_name)
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
	unsigned int rfile_size = 0;
	if (Recv(sock, (char *)&rfile_size, sizeof(unsigned int), 0) == -1)
	{
		printf("recv failed\r\n");
		return -1;
	}

	if ( Recv(sock, (char *)file_name, PATH_SIZE, 0) == -1)
	{
		printf("recv failed\r\n");
		return -1;
	}

	char temp[128] = {0};
	StripChars(file_name, temp, ".\\/;:*?\"<>|");
	strcpy(file_name, temp);

	unsigned char rfile_hash[33] = {0};
	if ( Recv(sock, (char *)rfile_hash, MD5_SIZE, 0) == -1)
	{
		printf("recv failed\r\n");
		return -1;
	}


	printf("Opening local %s file for compare\r\n", file_name);
	unsigned int file_size = 0;
	char *data = get_file(file_name, &file_size);
	if (data == NULL)
	{
		printf("Unable to open %s\r\n", file_name);
		return -1;
	}

	unsigned char file_hash[33] = {0};
	md5sum((char *)&data[0], file_size, file_hash);
	if ( Send(sock, (char *)file_hash, MD5_SIZE, 0) == -1)
	{
		printf("recv failed\r\n");
		return -1;
	}

	if (rfile_size == file_size)
	{
		printf("Our file is same size\r\n");
		if (strcmp(file_hash, rfile_hash) == 0)
		{
			printf("Files have the same hash\r\n");
			*final_size = 0;
			return 0;
		}

	}
	else if (rfile_size > file_size)
	{
		printf("Our file is smaller\r\n");
	}
	else
	{
		printf("Our file is larger\r\n");
	}


	// Calculate block size first
	int block_size = BLOCK_SIZE;
	int num_block = file_size / block_size;
	int remainder = file_size - num_block * block_size;
	if (remainder > 0)
	{
		num_block++;
	}


	printf("File has %d blocks %d bytes remainder %d\r\n", num_block, file_size, remainder);

	unsigned int *checksum_array = (unsigned int *)malloc(num_block * sizeof(unsigned int));
	char **md5_array = (char **)malloc(num_block * sizeof(char *));

	for (int i = 0; i < num_block; i++)
	{
		checksum_array[i] = -1;
	}
	printf("Calculating adler32 for each block\r\n");
	for(int i = 0; i < num_block; i++)
	{
		unsigned int rsize = block_size;

		if (i == num_block - 1)
		{
			rsize = file_size - block_size * i;
		}
		checksum_array[i] = adler32((unsigned char *)&data[block_size * i], rsize);
		md5_array[i] = malloc(MD5_SIZE + 1);
		memset(md5_array[i], 0, MD5_SIZE + 1);
		md5sum((char *)&data[block_size * i], rsize, md5_array[i]);
//		printf("Block %d has hash %s\r\n", i, md5_array[i]);
//		printf("Block %d has checksum %08X rsize %d\r\n", i, checksum_array[i], rsize);
//		printf("adler32 %d %d\r\n", block_size * i, rsize);
	}

	
	printf("Sending block sums to server\r\n");	
	block_t *block_offset = (block_t *)malloc(num_block * sizeof(block_t));

	Send(sock, (char *)&num_block, sizeof(int), 0);
	Send(sock, (char *)&block_size, sizeof(int), 0);
	Send(sock, (char *)checksum_array, num_block * sizeof(int), 0);
	for (int i = 0; i < num_block; i++)
	{
		Send(sock, (char *)md5_array[i], MD5_SIZE, 0);
	}

	if ( Recv(sock, (char *)&block_offset[0], sizeof(block_t) * num_block, 0) == -1)
	{
		printf("recv failed\r\n");
		return -1;
	}

	printf("Got offsets for each block\r\n");
	for (int i = 0; i < num_block; i++)
	{
		int rsize = block_size;

		if (i == num_block - 1)
		{
			rsize = rfile_size - (num_block - 1) * block_size;
		}


		if (block_offset[i].offset == -1)
		{
			printf("\tmissing block %d [%d bytes]\r\n", i, rsize);
		}
	}

	unsigned int diff_size = 0;
	if ( Recv(sock, (char *)&diff_size, sizeof(unsigned int), 0) == -1)
	{
		printf("recv failed\r\n");
		return -1;
	}

	printf("Delta size is %d bytes\r\n", diff_size);

	unsigned char *diff = (unsigned char *)malloc(diff_size + block_size);
	unsigned int download_size = 0;
	download_size = Recv(sock, diff, diff_size, 0);
	if (download_size == -1)
	{
		printf("recv failed\r\n");
		return -1;
	}
	printf("Downloaded delta\r\n");
	closesocket(sock);
	assemble_download(response, rfile_size, data, file_size, block_offset, num_block, block_size, (char *)diff, diff_size);
	*final_size = rfile_size;

	memset(file_hash, 0, MD5_SIZE + 1);
	md5sum(response, *final_size, file_hash);
	if (strcmp(file_hash, rfile_hash) == 0)
	{
		printf("Rsync successful\r\n");
	}
	else
	{
		printf("Rsync failed\r\n");
		printf("hashes dont match\r\n\tremote: %s\r\n\tlocal : %s\r\n", file_hash, rfile_hash);
		printf("file size\r\n\tremote: %d\r\n\tlocal : %d\r\n", *final_size, rfile_size);
		printf("First 8 bytes\r\n");
		for (int i = 0; i < 8; i++)
		{
			printf("%02X ", response[i]);
		}

		printf("\r\nLast 8 bytes\r\n");
		for (int i = 0; i < 8; i++)
		{
			printf("%02X ", response[i + *final_size - 8]);
		}
	}

	return 0;
}

int rsync_file_upload(char *file, unsigned short port)
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

	int ret = bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	while (ret == -1)
	{
		perror("bind error");
		printf("Retrying in 5 seconds\r\n");
#ifdef WIN32
		Sleep(5000);
#else
		sleep(5);
#endif
		ret = bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
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
			closesocket(connfd);
			continue;
		}

		char file_name[PATH_SIZE] = { 0 };
		int rblock_size = BLOCK_SIZE;
		unsigned char file_hash[33] = {0};
		unsigned char rfile_hash[33] = {0};
		md5sum((char *)&data[0], file_size, file_hash);

		unsigned int rnum_block = 0;
		memcpy(file_name, file, MIN(PATH_SIZE - 1, strlen(file)));
		Send(connfd, (char *)&file_size, sizeof(int), 0);
		Send(connfd, (char *)&file_name, PATH_SIZE, 0);
		Send(connfd, (char *)&file_hash, MD5_SIZE, 0);
		if ( Recv(connfd, (char *)&rfile_hash, MD5_SIZE, 0) == -1)
		{
			printf("recv failed\r\n");
			closesocket(connfd);
			continue;
		}

		if (strcmp(rfile_hash, file_hash) == 0)
		{
			printf("Files already match\r\n");
			closesocket(connfd);
			continue;
		}

		if ( Recv(connfd, (char *)&rnum_block, sizeof(int), 0) == -1)
		{
			printf("recv failed\r\n");
			closesocket(connfd);
			continue;
		}

		if ( Recv(connfd, (char *)&rblock_size, sizeof(int), 0) == -1)
		{
			printf("recv failed\r\n");
			closesocket(connfd);
			continue;
		}


		unsigned int *rchecksum_array = (unsigned int *)malloc(rnum_block * sizeof(int));
		if (rchecksum_array == NULL)
		{
			perror("malloc failed");
			closesocket(connfd);
			continue;
		}

		for (int i = 0; i < rnum_block; i++)
		{
			rchecksum_array[i] = -1;
		}

		printf("Received %d checksum array from client\r\n", rnum_block);
		if (rnum_block == 0)
		{
			printf("Dropping client as we got no blocks\r\n");
			closesocket(connfd);
			continue;
		}

		if ( Recv(connfd, (char *)rchecksum_array, rnum_block * sizeof(int), 0) == -1)
		{
			printf("recv failed\r\n");
			closesocket(connfd);
			continue;
		}

		char **rmd5_array = (char **)malloc(rnum_block * sizeof(char *));
		if (rmd5_array == NULL)
		{
			perror("malloc failed");
			closesocket(connfd);
			continue;
		}

		for (int i = 0; i < rnum_block; i++)
		{
			rmd5_array[i] = (char *)malloc(MD5_SIZE + 1 * sizeof(char));
			memset(rmd5_array[i], 0, MD5_SIZE + 1);

			if ( Recv(connfd, (char *)rmd5_array[i], MD5_SIZE, 0) == -1)
			{
				printf("recv failed\r\n");
				closesocket(connfd);
				continue;
			}

		}




		block_t *block_offset = (block_t *)malloc(sizeof(block_t) * rnum_block);
		if (block_offset == NULL)
		{
			perror("malloc failed");
			closesocket(connfd);
			continue;
		}
		printf("Searching for matches in %d blocks\r\n", rnum_block);
		
		for (int i = 0; i < rnum_block; i++)
		{
			block_offset[i].offset = -1;
			block_offset[i].length = 0;
		}

		// we dont send the last fragment block as we can only scan blocks of a single length at a time
		int ret = adler32_scan((unsigned char *)&data[0], file_size, rblock_size, rchecksum_array, rnum_block - 1, block_offset, rmd5_array);
		// set length of last block which is always transferred
		block_offset[rnum_block - 1].offset = -1;
		block_offset[rnum_block - 1].length = file_size - (rnum_block - 1) * rblock_size;


		printf("Sending block offsets\r\n");
		Send(connfd, (char *)block_offset, rnum_block * sizeof(block_t), 0);

		// Remote side now knows where it's blocks go in new file
		// going to send all bytes in order of whats left starting from 0 and skipping whats in the block report
		
		printf("Determining data client is missing\r\n");

		for (int i = 0; i < rnum_block; i++)
		{
			if (block_offset[i].offset == -1)
			{
				printf("\tClient missing block %d [%d bytes]\r\n", i, block_offset[i].length);
			}
		}

		unsigned char *send_file = (unsigned char *)malloc(file_size);
		int send_file_pos = 0;


		for(int i = 0; i < file_size; i++)
		{
			int skip = 0;


			for(int j = 0; j < rnum_block; j++)
			{
				if (block_offset[j].length == 0)
				{
					continue;
				}

				if ( i >= block_offset[j].offset && i < block_offset[j].offset + rblock_size )
				{
					// we are in this block, skip to the end of this block
					i = block_offset[j].offset + rblock_size;
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
		Send(connfd, (char *)&send_file_pos, sizeof(unsigned int), 0);		
		Send(connfd, (char *)send_file, send_file_pos, 0);
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
				if (stripc[i] == '.' && strlen(in) == 4)
				{
					continue;
				}
				flag = 1;
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

	if (argc < 4)
	{
		printf("Usage: rsync_download ip port max_size\r\n");
		return 0;
	}

	unsigned short port = atoi(argv[2]);
	unsigned int max_malloc_size = atoi(argv[3]);

	printf("Allocating %d bytes\r\n", max_malloc_size);
	char *response = (char *)malloc(max_malloc_size);
	if (response == NULL)
	{
		perror("malloc failed");
	}

	unsigned int download_size = 0;
	char file_name[PATH_SIZE] = {0};

#ifdef WIN32
	WSADATA		WSAData;

	WSAStartup(MAKEWORD(2, 0), &WSAData);
#endif

	printf("Attempting to download file from ip %s port %d\r\n", argv[1], (int)port);
	int ret = rsync_file_download(argv[1], port, response, max_malloc_size, &download_size, file_name);
	if (ret < 0)
	{
		printf("Download failed\r\n");
		return 0;
	}
	else if (ret == 0 && download_size == 0)
	{
		printf("File did not change\r\n");
	}
	else
	{
		printf("Download complete\r\n");
		printf("Got %d bytes file name %s\r\n", download_size, file_name);

		char new_filename[PATH_SIZE] = {0};
		char strip_filename[PATH_SIZE] = {0};

		StripChars(file_name, strip_filename, ".\\/;:*?\"<>|");

		sprintf(new_filename, "downloaded_%s", strip_filename);
		printf("Saving as file name %s\r\n", new_filename);
		write_file(new_filename, response, download_size);
	}
	return 0;
}

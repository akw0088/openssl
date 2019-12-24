#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "huffman.h"

static unsigned char huffbuf[HUFFHEAP_SIZE];


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
	buffer = new char[file_size + 1];
	bytes_read = (int)fread(buffer, sizeof(char), file_size, file);
	if (bytes_read != file_size)
	{
		delete[] buffer;
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

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf("Usage: huffman_dec file.huff\r\n");
		return -1;
	}

	unsigned int size = 0;

	char *buffer = get_file(argv[1], &size);
	if (buffer == NULL)
	{
		printf("Unable to open %s\r\n", argv[1]);
		return -1;
	}

	unsigned char *decode = (unsigned char *)malloc(2 * size);
	if (decode == NULL)
	{
		perror("malloc failed");
		return -1;
	}
	memset(decode, 0, 2 * size);
	size_t length = 2 * size;


	unsigned int decompressed_size = huffman_decompress(buffer, size, decode, length, huffbuf);
	char filename[256] = {0};

	snprintf(filename, 256, "%s.uncompressed", argv[1]);
	write_file(filename, decode, decompressed_size);

	return 0;
}


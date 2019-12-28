#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"

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
	buffer = malloc(file_size + 1);
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

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf("Usage: base64_enc file.bin\r\n");
		return -1;
	}

	unsigned int size = 0;

	char *encode = get_file(argv[1], &size);
	int buf_size = (size / 3) * 4;
	if (size % 3)
		buf_size += 4;

	char *buffer = (char *)malloc(buf_size);
	if (buffer == NULL)
	{
		perror("malloc failed");
		return -1;
	}

	memset(buffer, 0, buf_size);
	base64encode(encode, size, buffer, buf_size);
	buffer[buf_size] = 0;
	printf("Base64: %s\n", buffer);

	write_file((char *)"file.base64", buffer, buf_size);

    return 0;
}


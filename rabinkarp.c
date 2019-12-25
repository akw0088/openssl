#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MOD_RK 101
#define BASE_RK 256

int mpow(int base, int n)
{
	int result = 1;
	for(int i = 0; i < n; i++)
	{
		result *= base;
	}

	return result;
}

unsigned int rk_hash(unsigned char *data, unsigned int length)
{
	unsigned int hash = 0;
	for(int i = 0; i < length; i++)
	{
		hash += ((int)(data[i] * mpow(BASE_RK, length - i - 1))) % MOD_RK;
	}

	return hash % MOD_RK;
}

unsigned int rk_hash_roll(unsigned int hash, unsigned char in, unsigned char out, unsigned int length)
{
	hash -= out * mpow(BASE_RK, length - 1);
	return (hash * BASE_RK + in) % MOD_RK;
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


int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("Usage: rabinkarp file\r\n");
		return -1;
	}

	unsigned int length = 0;
	char *data = get_file(argv[1], &length);
	if (data == NULL)
	{
		printf("Unable to open %s\r\n", argv[1]);
	}
	
	unsigned int hash = 0;
	hash = rk_hash(data, length);
	printf("%08X\r\n", hash);
	return 0;
}

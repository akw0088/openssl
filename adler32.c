#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MOD_ADLER 65521

//    Adler-32 checksum is obtained by calculating two 16-bit checksums A and B and concatenating their bits into a 32-bit integer.
// A is the sum of all bytes in the stream plus one, and B is the sum of the individual values of A from each step.
// At the beginning of an Adler-32 run, A is initialized to 1, B to 0. The sums are done modulo 65521 
unsigned int adler32(char *buf, unsigned int length)
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


// Rolling checksum for Rsync
unsigned int adler32_roll(unsigned int adler, unsigned char buf_in, unsigned char buf_out, unsigned int block_size)
{
	unsigned short a = adler & 0xFFFF;
	unsigned short b = adler >> 16;

	// remove old byte, add new byte
        a = (a - buf_out + buf_in) % MOD_ADLER;

	// add new a, remove old a
	b = (b - (block_size * buf_out) + a - 1) % MOD_ADLER;

	return b << 16 | a;
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
		printf("Usage: adler32 file\r\n");
		return -1;
	}

	unsigned int length = 0;
	char *data = get_file(argv[1], &length);
	if (data == NULL)
	{
		printf("Unable to open %s\r\n", argv[1]);
	}

	
	unsigned int checksum = 0;
	checksum = adler32(data, length);
	printf("%08X", checksum);
	return 0;
}

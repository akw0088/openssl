#ifdef WIN32
	#include <sodium.h>
	#include <sodium/crypto_box.h>
#else
	#include "crypto_box.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void randombytes(unsigned char *x,unsigned long long xlen);

// https://nacl.cr.yp.to/install.html
//
// Installing NACL (do takes a while as it's compiling without much output)
//
//	wget https://hyperelliptic.org/nacl/nacl-20110221.tar.bz2
//      bunzip2 < nacl-20110221.tar.bz2 | tar -xf -
//      cd nacl-20110221
//     ./do

// https://nacl.cr.yp.to/box.html

// compile:
// gcc nacl.c devurandom.c ./nacl-20110221/build/localhost/lib/amd64/libnacl.a -I ./nacl-20110221/build/localhost/include/amd64/ -fpermissive

// Note: The NaCl "tests" directory has useful examples
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
	if (buffer == NULL)
	{
		return NULL;
	}

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
}

int main(int argc, char *argv[])
{
	unsigned char *public_key = NULL;
	unsigned char *private_key = NULL;
	unsigned char nonce[crypto_box_NONCEBYTES] = {0};

	if (argc < 3)
	{
		printf("Usage: nacl_enc file private_key public_key\r\n");
		return -1;
	}

	// Init N once with random data
	randombytes(nonce, 24);

	unsigned int size = 0;
	char *data = get_file(argv[1], &size);
	if (data == NULL)
	{
		printf("Failed to open %s\r\n", argv[1]);
		return -1;
	}

	unsigned int private_size = 0;
	unsigned int public_size = 0;
	private_key = get_file(argv[2], &private_size);
	if (private_key == NULL)
	{
		printf("Failed to open %s\r\n", argv[2]);
		return -1;
	}

	public_key = get_file(argv[3], &public_size);
	if (public_key == NULL)
	{
		printf("Failed to open %s\r\n", argv[3]);
		return -1;
	}

	char *message = malloc(size + crypto_box_ZEROBYTES);
	if (message == NULL)
	{
		perror("malloc failed");
		return -1;
	}

	char *ciphertext = malloc(size + crypto_box_ZEROBYTES);
	if (ciphertext == NULL)
	{
		perror("malloc failed");
		return -1;
	}

	// NaCl has a stupid zero byte front padding crypto_box_ZEROBYTES
	memset(message, 0, size + crypto_box_ZEROBYTES);
	memcpy(&message[crypto_box_ZEROBYTES], data, size);

	// cipher length same as message length
	unsigned int mlen = size + crypto_box_ZEROBYTES;
	unsigned int clen = mlen;

	// magic encrypt function Curve25519, Salsa20, and Poly1305
	int ret = crypto_box(ciphertext, message, mlen, nonce, public_key, private_key);
	if (ret == -1)
	{
		printf("crypto_box failed\r\n");
		return -1;
	}

	write_file("file.enc", ciphertext, clen);
	write_file("file.nonce", nonce, crypto_box_NONCEBYTES);

	return 0;
}

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

int main(void)
{
	unsigned char public_key[crypto_box_PUBLICKEYBYTES] = {0};
	unsigned char private_key[crypto_box_SECRETKEYBYTES] = {0};

	// Generate keypair
	crypto_box_keypair(public_key, private_key);

	write_file("nacl.public", public_key, crypto_box_PUBLICKEYBYTES); 
	write_file("nacl.private", private_key, crypto_box_SECRETKEYBYTES); 

	return 0;
}

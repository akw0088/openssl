#include "crypto_box.h"

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

	write_file("nalc.public", public_key, crypto_box_PUBLICKEYBYTES); 
	write_file("nalc.private", private_key, crypto_box_SECRETKEYBYTES); 

	return 0;
}

#include "crypto_box.h"

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

int main(void)
{
	unsigned char public_key[crypto_box_PUBLICKEYBYTES] = {0};
	unsigned char private_key[crypto_box_SECRETKEYBYTES] = {0};
	unsigned char nonce[crypto_box_NONCEBYTES] = {0};
	unsigned char message[512] = {0};
	unsigned char ciphertext[512] = {0};
	unsigned char plaintext[512] = {0};

	// Generate keypair
	crypto_box_keypair(public_key, private_key);

	// Init N once with random data
	randombytes(nonce, 24);

	// NaCl has a stupid zero byte front padding crypto_box_ZEROBYTES
	sprintf(&message[crypto_box_ZEROBYTES], "Hello World!");
	printf("message: %s\r\n", &message[crypto_box_ZEROBYTES]);

	// cipher length same as message length
	unsigned int mlen = strlen(&message[crypto_box_ZEROBYTES]) + crypto_box_ZEROBYTES;
	unsigned int clen = mlen;

	// magic encrypt function Curve25519, Salsa20, and Poly1305
	int ret = crypto_box(ciphertext, message, mlen, nonce, public_key, private_key);
	if (ret == -1)
	{
		printf("crypto_box failed\r\n");
		return -1;
	}

	// The open function also needs zero padding on ciphertext of crypto_box_BOXZEROBYTES
	// should already be padded from crypto_box
	crypto_box_open(plaintext, ciphertext, clen, nonce, public_key, private_key);
	if (ret == -1)
	{
		printf("crypto_box_open failed\r\n");
		return -1;
	}

	// Plain text will also have zero padding of crypto_box_ZEROBYTES
	printf("decrypted: %s\r\n", &plaintext[crypto_box_ZEROBYTES]);//&d[crypto_box_BOXZEROBYTES]);

	return 0;
}

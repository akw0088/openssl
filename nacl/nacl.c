#include "crypto_box.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char n[crypto_box_NONCEBYTES];      // n-once (random data)

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
	unsigned char pk[crypto_box_PUBLICKEYBYTES] = {0};
	unsigned char sk[crypto_box_SECRETKEYBYTES] = {0};
	unsigned char n[crypto_box_NONCEBYTES] = {0};
	unsigned char m[512] = {0};
	unsigned char c[512] = {0};
	unsigned char d[512] = {0};

	crypto_box_keypair(pk, sk);


	randombytes(n, 24);
	// NaCl has a stupid zero byte front padding crypto_box_ZEROBYTES
	sprintf(&m[crypto_box_ZEROBYTES], "Hello World!");
	printf("plaintext: %s\r\n", &m[crypto_box_ZEROBYTES]);
	unsigned int mlen = strlen(&m[crypto_box_ZEROBYTES]) + crypto_box_ZEROBYTES;
	unsigned int clen = mlen;

	int ret = crypto_box(c, m, mlen, n, pk, sk);
	if (ret == -1)
	{
		printf("crypto_box failed\r\n");
		return -1;
	}

	// The open function also needs zero padding on ciphertext of crypto_box_BOXZEROBYTES
	// Plain text will also have zero padding of crypto_box_BOXZEROBYTES
	crypto_box_open(d, c, clen, n, pk, sk);
	if (ret == -1)
	{
		printf("crypto_box_open failed\r\n");
		return -1;
	}

	printf("decrypted: %s\r\n", &d[crypto_box_ZEROBYTES]);//&d[crypto_box_BOXZEROBYTES]);

	return 0;
}

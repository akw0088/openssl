#include "crypto_box.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char n[crypto_box_NONCEBYTES];      // n-once (random data)

extern "C" {
	void randombytes(unsigned char *x,unsigned long long xlen);
}

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
// gcc -c devurandom.c
// g++ nacl.cpp devurandom.o ./nacl-20110221/build/localhost/lib/amd64/libnacl.a -I ./nacl-20110221/build/localhost/include/amd64/ -fpermissive

int main(void)
{
	std::string c;
	std::string m = "Hello World";
	std::string pt;
	std::string nonce;
	std::string pk;
	std::string sk;

	printf("crypto_box_keypair()\r\n");
	pk = crypto_box_keypair(&sk);

	randombytes(n, 24);
	nonce =(char *)&n[0];


	printf("crypto_box()\r\n");

	try
	{
		c = crypto_box(m,nonce,pk, sk);
	}
	catch (char const *e)
	{
		printf("Exception: %s\r\n", e);
	}

	printf("plaintext: %s\r\n", m.c_str());
	printf("n size: %d\r\n", crypto_box_NONCEBYTES);
	
	printf("crypto_box_open()\r\n");
	pt = crypto_box_open(c,nonce,pk,sk);
	printf("plaintext: %s\r\n", pt.c_str());


	return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef WIN32
	#include <windows.h>
	#include <winsock.h>

	#pragma comment(lib, "wsock32.lib")

	typedef int socklen_t;
#else
	#include <unistd.h>
	#include <fcntl.h>
	#include <dlfcn.h>
	#include <sys/select.h>
	#include <sys/types.h>
	#include <sys/time.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#define closesocket close

	typedef	int SOCKET;
	#define SOCKET_ERROR	-1
	#define INVALID_SOCKET	-1

	// RSA
	#include <openssl/pem.h>
	#include <openssl/ssl.h>
	#include <openssl/rsa.h>
	#include <openssl/evp.h>
	#include <openssl/bio.h>
	#include <openssl/err.h>

	// AES
	#include <openssl/conf.h>

	//MD5
	#include <openssl/md5.h>
#endif



#define MAX(x,y) (x) > (y) ? (x) : (y)
#define MIN(x,y) (x) < (y) ? (x) : (y)

void md5sum(char *data, int size, char *hash)
{
	MD5_CTX ctx;
	unsigned char digest[16] = { 0 };

	memset(&ctx, 0, sizeof(MD5_CTX));
	MD5_Init(&ctx);
	MD5_Update(&ctx, data, size);
	MD5_Final(digest, &ctx);

	for (int i = 0; i < 16; ++i)
	{
		sprintf(&hash[i * 2], "%02x", (unsigned int)digest[i]);
	}
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
	buffer = new char [file_size + 1];
	bytes_read = (int)fread(buffer, sizeof(char), file_size, file);
	if (bytes_read != file_size)
	{
		delete [] buffer;
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



RSA *createRSA(unsigned char *key, bool pub)
{
	RSA *rsa = NULL;
	BIO *keybio = BIO_new_mem_buf(key, -1); // a bio is just a memory buffer, -1 means do strlen of char *key

	if (keybio == NULL)
	{
		printf( "Failed to create key BIO");
		return 0;
	}

	if (pub)
	{
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	}
	else
	{
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}
	BIO_free_all(keybio);

	if (rsa == NULL)
	{
		printf( "Failed to create RSA");
	}
 
	return rsa;
}


int rsa_encrypt(char *public_key_filename, unsigned char *data, int data_len, unsigned char *encrypted, unsigned int &encrypted_length)
{
	unsigned char *pubkey = NULL;
	unsigned int size;

	pubkey = (unsigned char *)get_file(public_key_filename, &size);
	if (pubkey == NULL)
	{
		printf("Failed to open public key\r\n");
		return -1;
	}

	if (data_len > 245)
	{
		printf("Cannot encrypt more than 245 bytes with RSA 2048 bit key\r\n");
		delete [] pubkey;
		return -1;
	}

	RSA *rsa = createRSA(pubkey, true);
	encrypted_length = RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_PKCS1_PADDING);
	if (encrypted_length == -1)
	{
		char err[130];

		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		printf("ERROR: %s\n", err);
		delete [] pubkey;
		return -1;
	}
	RSA_free(rsa);
	delete [] pubkey;

	return 0;
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
			unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/*
	 * Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/*
	 * Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}


int aes_encrypt(unsigned char *key, unsigned char *iv, unsigned char *data, int data_size, unsigned char *&ciphertext, unsigned int &ciphertext_len)
{
	ciphertext = (unsigned char *)malloc( (data_size / 16 + 1) * 16 );
	if (ciphertext == NULL)
	{
		perror("malloc failed");
		return -1;
	}

	printf("Using key %s iv %s\r\n", key, iv);

	ciphertext_len = encrypt(data, data_size, key, iv, ciphertext);
	return 0;
}

int aes_file_upload(char *file, unsigned short port, unsigned char *key, unsigned char *iv, unsigned char *public_key_filename)
{
	int			connfd;
	unsigned int		size = sizeof(struct sockaddr_in);
	struct sockaddr_in	servaddr, client;
	time_t			ticks;
	int listenfd;

#ifdef _WIN32
	WSADATA		WSAData;

	WSAStartup(MAKEWORD(2, 0), &WSAData);
#endif

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1)
	{
		perror("socket error");
		return -1;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if ((::bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) == -1)
	{
		perror("bind error");
		return 0;
	}

	printf("Server listening on: %s:%d\n", inet_ntoa(servaddr.sin_addr), htons(servaddr.sin_port));

	if (listen(listenfd, 3) == -1)
	{
		perror("listen error");
		return -1;
	}

	for (;;)
	{
		char response[1024] = { 0 };

		printf("listening for connections...\n");
		connfd = accept(listenfd, (struct sockaddr *)&client, (socklen_t *)&size);
		if (connfd == INVALID_SOCKET)
			continue;

		ticks = time(NULL);
		snprintf(response, sizeof(response), "%.24s\r\n", ctime(&ticks));
		printf("Client: %s - %s\r\n", inet_ntoa(client.sin_addr), response);

		unsigned int file_size = 0;
		unsigned char *data = (unsigned char *)get_file(file, &file_size);
		if (data == NULL)
		{
			printf("Error: could not open file %s\r\n", file);
			continue;
		}
		printf("Opened file %s size %d bytes\r\n", file, file_size);

		char file_name[128] = { 0 };

		unsigned char *ciphertext = NULL;
		unsigned int ciphertext_len = 0;

		printf("Performing AES encryptions\r\n");
		aes_encrypt(key, iv, data, file_size, ciphertext, ciphertext_len);

		char rsa_plaintext[1024] = {0};

		sprintf(rsa_plaintext, "%s %s", iv, key);

		int rsa_plaintext_len = strlen(rsa_plaintext);

		unsigned char encrypted[4098] = {0};
		unsigned int encrypted_length = 0;
		unsigned char hash[33] = {0};

		md5sum((char *)data, file_size, (char *)&hash[0]);
		printf("Unencrypted MD5: %s\r\n", hash);
		printf("AES Encrypted size %d\r\n", ciphertext_len);

		printf("Performing RSA encryptions\r\n");
		rsa_encrypt((char *)public_key_filename, (unsigned char *)&rsa_plaintext[0], rsa_plaintext_len, encrypted, encrypted_length);

		delete[] data;
		printf("Encryption complete, sending file\r\n");
		memcpy(file_name, file, MIN(127, strlen(file)));
		send(connfd, (char *)&ciphertext_len, sizeof(int), 0);
		send(connfd, (char *)&file_name, 128, 0);
		send(connfd, (char *)&file_size, sizeof(int), 0);
		send(connfd, (char *)&hash, 32, 0);
		send(connfd, (char *)&encrypted, 256, 0);
		send(connfd, ciphertext, ciphertext_len, 0);
		free((void *)ciphertext);
		closesocket(connfd);
	}
	return 0;
}




int main(int argc, char *argv[])
{
	unsigned short port = 65535;

	if (argc < 5)
	{
		printf("Usage: aes_upload filename port key iv public_key\r\n");
		printf("Example: aes_upload file.tgz 65535 01234567890123456789012345678901 0123456789012345 id_rsa.openssl.pub\r\n");
		return 0;
	}

	port = atoi(argv[2]);
	unsigned char *key = (unsigned char *)argv[3];
	unsigned char *iv = (unsigned char *)argv[4];
	unsigned char *pubkey = (unsigned char *)argv[5];

	printf("Attempting to upload %s to client connecting on port %d\r\n", argv[1], (int)port);
	aes_file_upload(argv[1], port, key, iv, pubkey);

	return 0;
}


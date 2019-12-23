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

int aes_file_upload_reverse(char *file, char *ip_str, unsigned short port, unsigned char *key, unsigned char *iv, unsigned char *public_key_filename)
{
	struct sockaddr_in	servaddr;
	SOCKET sock;
	int ret;


	unsigned int file_size = 0;
	unsigned char *data = (unsigned char *)get_file(file, &file_size);
	if (data == NULL)
	{
		printf("Error: could not open file %s\r\n", file);
		return -1;
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


	printf("Encryption complete, connecting to server\r\n");
	delete[] data;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(ip_str);
	servaddr.sin_port = htons(port);

	// 3 way handshake
	printf("Attempting to connect to %s\n", ip_str);
	ret = connect(sock, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in));
	if (ret == SOCKET_ERROR)
	{
#ifdef _WIN32
		ret = WSAGetLastError();

		switch (ret)
		{
		case WSAETIMEDOUT:
			printf("Fatal Error: Connection timed out.\n");
			break;
		case WSAECONNREFUSED:
			printf("Fatal Error: Connection refused\n");
			break;
		case WSAEHOSTUNREACH:
			printf("Fatal Error: Router sent ICMP packet (destination unreachable)\n");
			break;
		default:
			printf("Fatal Error: %d\n", ret);
			break;
		}
#else
		ret = errno;

	        switch(ret)
	        {
		case ENETUNREACH:
			printf("Fatal Error: The network is unreachable from this host at this time.\n(Bad IP address)\n");
			break;
	        case ETIMEDOUT:
	                printf("Fatal Error: Connecting timed out.\n");
	                break;
	        case ECONNREFUSED:
	                printf("Fatal Error: Connection refused\n");
	                break;
	        case EHOSTUNREACH:
	                printf("Fatal Error: router sent ICMP packet (destination unreachable)\n");
	                break;
	        default:
	                printf("Fatal Error: %d\n", ret);
	                break;
	        }
#endif
		return -1;
	}
	printf("TCP handshake completed\n");

	unsigned int magic = 0xF0F0F0F0;

	memcpy(file_name, file, MIN(127, strlen(file)));
	send(sock, (char *)&magic, sizeof(int), 0);
	send(sock, (char *)&ciphertext_len, sizeof(int), 0);
	send(sock, (char *)&file_name, 128, 0);
	send(sock, (char *)&file_size, sizeof(int), 0);
	send(sock, (char *)&hash, 32, 0);
	send(sock, (char *)&encrypted, 256, 0);
	send(sock, ciphertext, ciphertext_len, 0);
	closesocket(sock);
	free((void *)ciphertext);

	return 0;
}




int main(int argc, char *argv[])
{

	if (argc < 6)
	{
		printf("Usage: aes_upload_reverse filename ip port key iv public_key\r\n");
		printf("Example: ./aes_upload_reverse file.tgz 127.0.0.1 65535 01234567890123456789012345678901 0123456789012345 id_rsa.openssl.pub\r\n");
		return 0;
	}

	char *filename = argv[1];
	char *ip_str = argv[2];
	unsigned short port = atoi(argv[3]);
	unsigned char *key = (unsigned char *)argv[4];
	unsigned char *iv = (unsigned char *)argv[5];
	unsigned char *pubkey = (unsigned char *)argv[6];

	printf("Attempting to upload %s to ip %s port %d\r\n", filename, ip_str, (int)port);
	aes_file_upload_reverse(filename, ip_str, port, key, iv, pubkey);

	return 0;
}


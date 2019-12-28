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

int process_download(char *file_name, char *remote_hash, char *response, int download_size, unsigned char *encrypted_key, unsigned char *prikey, unsigned int max_malloc_size);

void StripChars(const char *in, char *out, char *stripc)
{
    while (*in)
    {
    	bool flag = false;

	int length = strlen(stripc);
    	for(int i = 0; i < length; i++)
	{
		if (*in == stripc[i])
		{
			flag = true;
			break;
		}
	}

	if (flag)
	{
		in++;
		continue;
	}
        *out++ = *in++;
    }
    *out = 0;
}


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





int aes_file_download_reverse(unsigned short int port, unsigned char *prikey, int max_malloc_size)
{
	int			connfd;
	unsigned int		socklen = sizeof(struct sockaddr_in);
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

	printf("Allocating %d bytes\r\n", max_malloc_size);
	char *response = (char *)malloc(max_malloc_size);
	if (response == NULL)
	{
		perror("malloc failed");
		return -1;
	}


	for (;;)
	{
		unsigned int final_size = 0;
		char hash[33] = {0};
		unsigned char encrypted_key[256] = {0};
		unsigned int download_size = 0;
		char file_name[128] = {0};




		printf("listening for connections...\n");
		connfd = accept(listenfd, (struct sockaddr *)&client, (socklen_t *)&socklen);
		if (connfd == INVALID_SOCKET)
			continue;

		printf("Client: %s\r\n", inet_ntoa(client.sin_addr));

		int expected_size = 0;
		int magic = 0;
		recv(connfd, (char *)&magic, 4, 0);

		if (magic != 0xF0F0F0F0)
		{
			closesocket(connfd);
			continue;
		}

		printf("Client passed magic cookie %X: Downloading\r\n", magic);

		recv(connfd, (char *)&expected_size, 4, 0);
		recv(connfd, (char *)file_name, 128, 0);
		recv(connfd, (char *)&final_size, 4, 0);
		recv(connfd, (char *)hash, 32, 0);
		recv(connfd, (char *)encrypted_key, 256, 0);

		while (download_size < expected_size)
		{
			download_size += recv(connfd, &response[download_size], expected_size - download_size, 0);
		}

		if (download_size != expected_size)
		{
			printf("expected %d bytes, got only %d bytes\r\n", expected_size, download_size);
		}
		closesocket(connfd);
		process_download(file_name, hash, response, download_size, encrypted_key, prikey, max_malloc_size);
		expected_size = 0;
		memset(file_name, 0, 128);
		final_size = 0;
		memset(hash, 0, 33);
		memset(encrypted_key, 0, 256);

	}
	return 0;
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

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
			unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/*
	 * Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary.
	 */
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/*
	 * Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

int aes_decrypt(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int size, unsigned int &decryptedtext_len, char *remote_hash, char *filename)
{

	/* Buffer for the decrypted text */
	unsigned char *decryptedtext = (unsigned char *)malloc(size);
	if (decryptedtext == NULL)
	{
		perror("malloc failed");
		return -1;
	}

	unsigned int ciphertext_len = size;

	decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
	decryptedtext[decryptedtext_len] = '\0';

	char new_filename[256] = {0};



	unsigned char local_hash[33] = {0};

	md5sum((char *)decryptedtext, decryptedtext_len, (char *)&local_hash[0]);


	if (strcmp(remote_hash, (char *)&local_hash[0]) == 0)
	{
		printf("MD5 Hash Pass: %s\r\n", remote_hash);
	}
	else
	{
		printf("MD5 Hash Fail: local %s != remote %s\r\n", local_hash, remote_hash);
		free((void *)decryptedtext);
		return -1;
	}


	sprintf(new_filename, "%s_decrypted", filename);

	printf("Saving decrypted file as \"%s\"\r\n", new_filename);
	write_file(new_filename, (char *)decryptedtext, decryptedtext_len);
	free((void *)decryptedtext);
	return 0;
}


int process_download(char *file_name, char *remote_hash, char *response, int download_size, unsigned char *encrypted_key, unsigned char *prikey, unsigned int max_malloc_size)
{
	if (download_size == 0)
	{
		printf("Download failed\r\n");
		return 0;
	}

	printf("Download complete\r\n");
	printf("Got %d bytes file name %s remote md5sum %s\r\n", download_size, file_name, remote_hash);


	char new_filename[256] = {0};
	char strip_filename[256] = {0};

	StripChars(file_name, strip_filename, (char *)".\\/;:*?\"<>|");

	printf("Attempting to decrypt AES key with RSA\r\n");

	unsigned char decrypted[4098] = {0};

	RSA *rsa = createRSA(prikey, false);
	int decrypted_length = RSA_private_decrypt(256, encrypted_key, decrypted, rsa, RSA_PKCS1_PADDING);
	if (decrypted_length == -1)
	{
		char err[130];

		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		printf("ERROR: %s\n", err);
//		free((void *)response);
		return -1;
	}
	RSA_free(rsa);

//	printf("Decrypted Text: %s\n", decrypted);
//	printf("Decrypted Length: %d\n", decrypted_length);

	if (decrypted_length != 16 + 32 + 1)
	{
		printf("Unexpected AES key string size\r\n");
		//free((void *)response);
		return -1;
	}

	if (decrypted[16] != ' ')
	{
		printf("Unexpected AES key format: %s\r\n", decrypted);
		//free((void *)response);
		return -1;
	}



	unsigned char key[128] = {0};
	unsigned char iv[128] = {0};

	int ret = sscanf((char *)&decrypted[0], "%s %s", (char *)&iv[0], (char *)&key[0]);

	if (ret != 2)
	{
		printf("Unexpected AES key format: %s matched %d\r\n", decrypted, ret);
		//free((void *)response);
		return -1;
	}

	printf("Decrypted AES Key successfully\r\n");

	printf("Attempting to decrypt file with remote hash %s\r\n", remote_hash);
	aes_decrypt(key, iv, (unsigned char *)response, download_size, max_malloc_size, remote_hash, strip_filename);


	//free((void *)response);
	return 0;
}

int main(int argc, char *argv[])
{
	unsigned short port = 65535;
	unsigned int max_malloc_size = 0;
	unsigned char encrypted_key[256] = {0};
	char remote_hash[33] = {0};

	if (argc < 4)
	{
		printf("Usage: aes_download_reverse port max_size prikey\r\n");
		printf("Example: ./aes_download_reverse 65535 70912 id_rsa\r\n");
		return 0;
	}

	port = atoi(argv[1]);
	max_malloc_size = atoi(argv[2]);

	unsigned int prikey_size = 0;
	unsigned char *prikey = (unsigned char *)get_file(argv[3], &prikey_size);


	printf("Waiting for download file on port %d\r\n", (int)port);
	int ret = aes_file_download_reverse(port, prikey, max_malloc_size);

	delete [] prikey;

	return 0;
}


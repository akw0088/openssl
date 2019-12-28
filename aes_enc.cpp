#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
			unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
			unsigned char *iv, unsigned char *plaintext);

// original example from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption


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

int main(int argc, char *argv[])
{
	if (argc < 3)
	{
		printf("Usage:\taes_enc 256bit_key 128bit_iv plaintext\r\n");
		printf("Example:\taes_enc 01234567890123456789012345678901 0123456789012345 HelloWorld!\r\n");
		return -1;
	}

	/* A 256 bit key */
	unsigned char *key = (unsigned char *)argv[1];

	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *)argv[2];

	/* Message to be encrypted */
	unsigned char *plaintext = (unsigned char *)argv[3];

	/*
	 * Buffer for ciphertext. Ensure the buffer is long enough for the
	 * ciphertext which may be longer than the plaintext, depending on the
	 * algorithm and mode.
	 */
	unsigned char *ciphertext = (unsigned char *)malloc(strlen((char *)plaintext) * 2);
	if (ciphertext == NULL)
	{
		perror("malloc failed");
		return -1;
	}


	int ciphertext_len;

	/* Encrypt the plaintext */
	ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv, ciphertext);

	/* Do something useful with the ciphertext here */
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

	write_file((char *)"file.enc", (char *)ciphertext, ciphertext_len);
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


#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h> 

// based on this example: http://hayageek.com/rsa-encryption-decryption-openssl-c/


// How to generate keys

// Use ssh-keygen to generate id_rsa
// ssh-keygen

// Convert private key to public key in OpenSSL format:
// openssl rsa -in id_rsa -outform PEM -pubout -out id_rsa.openssl.pub

// Note this is a different format from ssh known_host public key / fingerprint: ssh-keygen -f id_rsa -y > id_rsa.pub

// compile: g++ rsa_enc.cpp -fpermissive -lcrypto -g

// Note: Max message size for RSA is 245 bytes!!!
// RSA usually used to send a AES-256 key over a network, which then is used to send encrypted data
// Note: AES-256 comes in CBC mode and XTS mode -- XTS is supposedly "better", but not too confident in openssl implementation just yet.
// XTS uses two keys 256 bit keys, so 512 bit total key or you are doing it wrong

// EG:	Client connects, server sends public key, client encrypts AES key, sends AES key to server, sends AES Cipher data to server.
// 	Server gets a client, sends it's public key, gets RSA encrypted AES key, decrypts to get AES key, gets AES cipher data, which uses decrypted key to decrypt


/*
openssl asn1parse -in id_rsa

							    0:d=0  hl=4 l=1188 cons: SEQUENCE
[VERSION NUMBER]					    4:d=1  hl=2 l=   1 prim: INTEGER	   :00 
[RSA modulus N]						    7:d=1  hl=4 l= 257 prim: INTEGER	   :D22E8280A21DA9031D397594628C18963DDC60AB3302FEEA8C2EDA49FD28DCB6D5DD01E2218265C514ED94E62FBFC0D0C51D9034A4C0DD5F666A7EEF7AAB533414C8F35AA7A669E8770716DC9320BE91CBA93DA6E368A01B18B1FC5BA055A03CBDB12BF2587991955B7E4D814802D35F2FE2AC3104847AEE134A8AE731D71F6BAA00C592069A9F5C5C7716931FC03E1EB06975BF3ACB6BA60D00052CCA29552E75D643496A6E0381B70DBA055E35D0900E67FF414432CC8F3B90728B43530F4FE1E5D646C240DEB32A456D4627C051FE132BA4BFE805995D6118F6F88DAEC29128B21B219CC451B72FFBF4DA7813F4FDDA6A2EDB8DD71C3AE82804BE16918E8F
[PUBLIC EXPONENT E]					  268:d=1  hl=2 l=   3 prim: INTEGER		   :010001 
[RSA Private Exponent D]				  273:d=1  hl=4 l= 256 prim: INTEGER		   :272AFDACE5092BF6E59A509C0F65562BA1699126364267A8E3E8D34B187F65EA389E8FFC490C58D4CA5A9FF5E98E0D6B9A6031006E77768991B764E251F4DD7386301091A34E72CC1C6A58CB502BB8F7C8814878F2460C18209902933CA4D85099750BE084B65AF7FF6DE119A786C74724D054106A6C19D0860DCD26DA75E167C34BB71B9124075ED3FE571237A282F076EDB55D8541D3829E513877264FA5239EDAAC805B44E1C233F60D90AE7F83D94972C1F050E2A4359FFCB818A41602B2F12991ADEB25EDC5AEC5C9426B12347B5A10B954C804FE9CD380B3A73F636296484709276E37FB5D0EB26CC1D16F6AB7AB731202CFD6C1F45602610718FB4E61
[Derived from N and D, used to speed up calculations]	  533:d=1  hl=3 l= 129 prim: INTEGER		   :F74D6B92CC960DB4F291C6BE3D7347FBDDB1C9A307FF1178645D90B5B4C22BE4D389C424A8B616BB6445B4DB4B3E778EF688DD9AD928E5DF9DCE8837E05B2198F141697E734111F8B8380CC9A8842FB635346FDE5409987DA3C7EBF72FCF6D5096454F11DF74561DE0891C172C3C742E20B9C9556A80A25054FD69EE64DC4891 
[Derived from N and D, used to speed up calculations]	  665:d=1  hl=3 l= 129 prim: INTEGER		   :D992DFC411978F4472A76ECCF77F876B49FBC4F1C7DE1722882B40B43B7912DFDD116B9B66FE3A79F245309A06E36D5C9FF8E27E022B9AD7B0A84727D8A1A2B1F99FBBA0E7AF2F31087085E5DCC5A0D54D5F8B204ECBC21EA451D61445DBC526851BA0437C2D57B3ADA8CFFEF80DFFD05F244D813C7AB8FC9F8F7D94D052F51F
[Derived from N and D, used to speed up calculations]	  797:d=1  hl=3 l= 129 prim: INTEGER		   :907B91FACD3E69B9AAF2924BB9392DF82FB8DC563CA8BFFB37A01698A287C2FF48BBB775B77FD2DE1EA23F1CD3E42613C763851D1FFCADF8AC88EABAC2805BABB060081351A0D5B01B68DBC7C185A11E720D35C28E14A11BDE61423243A38B7946A22DA50289447AE62114E150FDECDEBA4DF11BCF4262124EE5534B6D6FE991
[Derived from N and D, used to speed up calculations]	  929:d=1  hl=3 l= 128 prim: INTEGER		   :295B028F792C8EBDDAF13A5D5959F33A90787BA9DD6CB88706CCF9E2883F6E38010433A8F93DAF8DC8602069D68F5A15360F0FB615E185F0239308DB6910E824DE26DF7A292FA24FB6A3F4BF8964433AE8171611D10867E07D295500CB7A8791D7D135783E5D3C035A29F1472C8D34A7BDBDDFC185E669CD12E32A62A3EA70CF
[Derived from N and D, used to speed up calculations]	 1060:d=1  hl=3 l= 129 prim: INTEGER		   :830D170DBA788C035A3D54108B2B992E7DA598D3C9397183A9A8433FB6510E206CF286FDDB6295A73ED377BF369E94DADEF70291B138A6D3473DF2C8AAF65D3F9AFBB4BCC1775590CA062BCF6ED7B0CE66A388311A060335888F6F968BF722555CC670F5D56C175477CC6E3C1D9959DFC8731DF911DA1466F207469CCF37B9C0

RSA algo (minus the key generation)

public key is (n,e) (3233,17)
	c = m^e mod n
	c = m^17 mod 3233

private key is (n,d) (3233, 2753)
	m = c^d mod n
	m = c^2753 mod 3233
*/



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
	unsigned char *pubkey = NULL;
	unsigned int size;

	if (argc < 3)
	{
		printf("Usage: enc public_key plaintext\r\n");
		return -1;
	}

	pubkey = (unsigned char *)get_file(argv[1], &size);
	if (pubkey == NULL)
	{
		printf("Failed to open public key\r\n");
		return -1;
	}

	unsigned char data[256] = {0};

	strcpy((char *)data, argv[2]);
	int data_len = strlen((char *)data);
	printf("plaintext %s\r\n", data); 

	unsigned char encrypted[4098]={};



	RSA *rsa = createRSA(pubkey, true);
	int encrypted_length = RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_PKCS1_PADDING);
	if (encrypted_length == -1)
	{
		char err[130];

		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		printf("ERROR: %s\n", err);
		return -1;
	}
	RSA_free(rsa);

	printf("Encrypted Length %d\r\n", encrypted_length);
	write_file("file.enc", (char *)encrypted, encrypted_length);
	return 0;
}

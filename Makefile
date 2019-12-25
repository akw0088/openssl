CPP := g++ 
CC := gcc 

all: adler32 rabinkarp crc32 base64_enc base64_dec huffman_enc huffman_dec rsa_enc rsa_dec aes_enc aes_dec upload download aes_upload aes_download aes_upload_reverse aes_download_reverse getrandom


adler32: adler32.c
	gcc -o adler32 adler32.c

rabinkarp: rabinkarp.c
	gcc -o rabinkarp rabinkarp.c

crc32: crc32.c
	gcc -o crc32 crc32.c

base64_enc: base64_enc.cpp
	g++ -o base64_enc base64_enc.cpp base64.c -fpermissive
base64_dec: base64_dec.cpp
	g++ -o base64_dec base64_dec.cpp base64.c -fpermissive

huffman_enc: huffman_enc.c huffman.c
	g++ -o huffman_enc huffman_enc.c huffman.c -fpermissive
huffman_dec: huffman_dec.c huffman.c
	g++ -o huffman_dec huffman_dec.c huffman.c -fpermissive


rsa_enc: rsa_enc.cpp
	g++ -o rsa_enc rsa_enc.cpp -lcrypto -fpermissive
rsa_dec: rsa_dec.cpp
	g++ -o rsa_dec rsa_dec.cpp -lcrypto -fpermissive

aes_enc: aes_enc.cpp
	g++ -o aes_enc aes_enc.cpp -lcrypto -fpermissive
aes_dec: aes_dec.cpp
	g++ -o aes_dec aes_dec.cpp -lcrypto -fpermissive

upload: upload.cpp
	g++ -o upload upload.cpp -fpermissive
download: download.cpp
	g++ -o download download.cpp -fpermissive

aes_upload: aes_upload.cpp
	g++ -o aes_upload aes_upload.cpp -lcrypto -fpermissive
aes_download: aes_download.cpp
	g++ -o aes_download aes_download.cpp -lcrypto -fpermissive

aes_upload_reverse: aes_upload_reverse.cpp
	g++ -o aes_upload_reverse aes_upload_reverse.cpp -lcrypto -fpermissive
aes_download_reverse: aes_download_reverse.cpp
	g++ -o aes_download_reverse aes_download_reverse.cpp -lcrypto -fpermissive

getrandom: getrandom.cpp
	g++ -o getrandom getrandom.cpp

clean:
	rm adler32 rabinkarp crc32 base64_enc base64_dec huffman_enc huffman_dec rsa_enc rsa_dec aes_enc aes_dec upload download aes_upload aes_download aes_upload_reverse aes_download_reverse getrandom

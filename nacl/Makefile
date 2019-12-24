CPP := g++ 
CC := gcc 

CFLAGS := -g -fpermissive
LFLAGS := 

all: genkeys nacl_enc nacl_dec nacl_upload nacl_download nacl_upload_reverse nacl_download_reverse


genkeys: genkeys.c devurandom.c
	gcc -o genkeys genkeys.c devurandom.c -fpermissive ./nacl-20110221/build/localhost/lib/amd64/libnacl.a -I ./nacl-20110221/build/localhost/include/amd64/

nacl_enc: nacl_enc.c devurandom.c
	gcc -o nacl_enc nacl_enc.c devurandom.c -fpermissive ./nacl-20110221/build/localhost/lib/amd64/libnacl.a -I ./nacl-20110221/build/localhost/include/amd64/
nacl_dec: nacl_dec.c devurandom.c
	gcc -o nacl_dec nacl_dec.c devurandom.c -fpermissive ./nacl-20110221/build/localhost/lib/amd64/libnacl.a -I ./nacl-20110221/build/localhost/include/amd64/

nacl_upload: nacl_upload.cpp devurandom.c
	g++ -o nacl_upload nacl_upload.cpp devurandom.o -fpermissive ./nacl-20110221/build/localhost/lib/amd64/libnacl.a -I ./nacl-20110221/build/localhost/include/amd64/
nacl_download: nacl_download.cpp devurandom.c
	g++ -o nacl_download nacl_download.cpp devurandom.o -fpermissive ./nacl-20110221/build/localhost/lib/amd64/libnacl.a -I ./nacl-20110221/build/localhost/include/amd64/

nacl_upload_reverse: nacl_upload_reverse.cpp devurandom.c
	g++ -o nacl_upload_reverse nacl_upload_reverse.cpp devurandom.o -fpermissive ./nacl-20110221/build/localhost/lib/amd64/libnacl.a -I ./nacl-20110221/build/localhost/include/amd64/
nacl_download_reverse: nacl_download_reverse.cpp devurandom.c
	g++ -o nacl_download_reverse nacl_download_reverse.cpp devurandom.o -fpermissive ./nacl-20110221/build/localhost/lib/amd64/libnacl.a -I ./nacl-20110221/build/localhost/include/amd64/

clean:
	rm genkeys nacl_enc nacl_dec nacl_upload nacl_download nacl_upload_reverse nacl_download_reverse

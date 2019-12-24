#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

uint32_t crc32_for_byte(uint32_t r)
{
	for(int j = 0; j < 8; ++j)
	{
		r = (r & 1? 0: (uint32_t)0xEDB88320L) ^ r >> 1;
	}
	return r ^ (uint32_t)0xFF000000L;
}

void crc32(const void *data, size_t n_bytes, uint32_t* crc)
{
	static uint32_t table[0x100];

	if(!*table)
	{
		for(size_t i = 0; i < 0x100; ++i)
		{
			table[i] = crc32_for_byte(i);
		}
	}

	for(size_t i = 0; i < n_bytes; ++i)
	{
		*crc = table[(uint8_t)*crc ^ ((uint8_t*)data)[i]] ^ *crc >> 8;
	}
}

int main(int argc, char** argv)
{
	FILE *fp;
	char buf[1L << 15];

	for(int i = argc > 1; i < argc; ++i)
	{
		if((fp = i ? fopen(argv[i], "rb"): stdin))
		{ 
			uint32_t crc = 0;
			while(!feof(fp) && !ferror(fp))
			{
				crc32(buf, fread(buf, 1, sizeof(buf), fp), &crc);
			}
			if(!ferror(fp))
			{
				printf("%08X%s%s\n", crc, argc > 2? "\t": "", argc > 2? argv[i]: "");
			}
			if(i)
			{
				fclose(fp);
			}
		}
	}
	return 0;
}

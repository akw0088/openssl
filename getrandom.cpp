#include <stdio.h>
#include <sys/random.h>

int main(int argc, char *argv[])
{
	char buf[256] = {0};
	ssize_t size;

	if (argc > 1)
	{
		size = getrandom(buf, 256, 0);
	}
	else
	{
		printf("Using /dev/random, may block add a parameter to use /dev/urandom\r\n");
		size = getrandom(buf, 256, GRND_RANDOM);
	}

	if (size > 0)
	{
		for (int i = 0; i < size; i++)
		{
			printf("%02X", (unsigned int)buf[i]);
		}
		printf("\r\n");
	}
	else
	{
		printf("getrandom() returned %d try again later\r\n", (int)size);
	}

	return 0;
}
